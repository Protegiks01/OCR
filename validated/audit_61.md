## Title
Non-Atomic Final-Bad Unit Voiding Causes Fund Freezing in Light Clients

## Summary
In `light.js` function `processHistory()`, the sequence update marking a unit as 'final-bad' and the subsequent voiding operation (which restores inputs to unspent status) execute in separate database transactions. [1](#0-0)  If the voiding transaction fails after the sequence update commits, the light client database enters an inconsistent state where inputs remain marked as spent, freezing those funds until manual intervention.

## Impact
**Severity**: High  
**Category**: Permanent Fund Freeze

Light client users lose access to funds when final-bad unit voiding fails. Affected outputs remain marked as `is_spent=1` in the local database, preventing them from being included in balance calculations [2](#0-1)  or spent in new transactions. While recovery is possible via re-synchronization or manual database repair, no automatic recovery mechanism exists, effectively freezing funds indefinitely for users without technical knowledge.

## Finding Description

**Location**: `byteball/ocore/light.js:310-325`, function `processHistory()`

**Intended Logic**: When a light client processes a unit marked as final-bad (double-spend/invalid), it should atomically: (1) update `units.sequence='final-bad'`, and (2) void the unit by deleting its outputs and marking its inputs as unspent (`is_spent=0`), restoring funds to the original owner.

**Actual Logic**: The sequence update executes via `db.query()` (line 310-313), which auto-commits immediately. The voiding operation executes separately via `db.executeInTransaction()` (line 318-323). [1](#0-0)  These operations are not wrapped in a single atomic transaction.

**Code Evidence**: [1](#0-0) 

The `db.executeInTransaction()` wrapper [3](#0-2)  begins a new transaction with `BEGIN`, but the prior UPDATE at line 310 has already committed independently.

**Exploitation Path**:

1. **Preconditions**: 
   - Light client user owns output X worth 1000 bytes
   - User's transaction becomes final-bad on network (double-spend detected)
   - Hub sends history with final-bad unit to light client

2. **Step 1 - Sequence Update Commits**: 
   - `processHistory()` executes UPDATE query (line 310-313)
   - Database commits: `units.sequence='final-bad'`
   - Output X remains `is_spent=1` in database

3. **Step 2 - Voiding Transaction Fails**:
   - `db.executeInTransaction()` begins (line 318)
   - `archiving.generateQueriesToArchiveJoint()` generates voiding queries [4](#0-3) 
   - Database error occurs (disk full, connection timeout, I/O error, deadlock)
   - Transaction rolls back - voiding queries don't execute
   - Error propagates to callback (line 323 → 332-336)

4. **Step 3 - Inconsistent State Persists**:
   - Database state: `sequence='final-bad'` (committed), but outputs not deleted and inputs still `is_spent=1`
   - No retry logic in `light_wallet.js:199-204` [5](#0-4)  - error simply propagated

5. **Step 4 - Fund Access Lost**:
   - Balance queries filter `WHERE is_spent=0` [6](#0-5) 
   - Output X excluded from balance calculations
   - User cannot spend output (marked as spent)
   - Recovery requires re-sync (may fail if error persists) or manual database repair

**Security Property Broken**: Transaction Atomicity - Multi-step database operations that modify related state must execute atomically. Partial commits violate database consistency invariants.

**Root Cause Analysis**: The code uses `db.query()` for sequence update (auto-commit) followed by separate `db.executeInTransaction()` for voiding. The transaction boundary at line 318 does not encompass the prior UPDATE, creating a window where the first operation can commit while the second fails, leaving the database in an inconsistent state.

## Impact Explanation

**Affected Assets**: Bytes (native currency) and all custom assets (divisible and indivisible)

**Damage Severity**:
- **Quantitative**: Any amount - from minimal to significant balances. Every output spent by a final-bad unit whose voiding fails becomes inaccessible.
- **Qualitative**: Loss of access to funds requiring technical intervention. Users without database expertise face permanent loss unless they export private keys to a new wallet.

**User Impact**:
- **Who**: Light client users whose transactions become final-bad during synchronization when database errors occur
- **Conditions**: Database transaction failures during history processing (disk full, I/O errors, connection timeouts, deadlocks)
- **Recovery**: No automatic recovery. Requires re-sync (if error was transient), manual database repair, or exporting keys to new wallet.

**Systemic Risk**: 
- Affects light clients only (full nodes use different code paths)
- Can impact multiple users during systemic database issues
- Silent failure - users see "spent" outputs without realizing corruption occurred
- Accumulates over time if undetected

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Not applicable - this is a fault tolerance issue, not an attack
- **Resources Required**: None
- **Technical Skill**: N/A

**Preconditions**:
- **Network State**: Any final-bad units in history (double-spends occur naturally)
- **Timing**: During light client synchronization when database errors occur

**Execution Complexity**:
- **Transaction Count**: Automatic during sync
- **Coordination**: None required
- **Detection Risk**: Low - appears as normal database error in logs

**Frequency**:
- **Repeatability**: Occurs whenever voiding transaction fails
- **Scale**: Individual users, but multiple users can be affected during systemic database issues

**Overall Assessment**: Medium likelihood. Database transaction failures are uncommon but inevitable in production environments due to resource exhaustion, I/O errors, connection issues, or deadlocks. The voiding operation involves multiple table operations across `archiving.js` [7](#0-6) , increasing failure probability under load.

## Recommendation

**Immediate Mitigation**:
Wrap both operations in a single atomic transaction:

```javascript
// File: byteball/ocore/light.js
// Function: processHistory(), lines 310-325

db.executeInTransaction(function(conn, cb){
    var arrQueries = [];
    conn.addQuery(arrQueries, 
        "UPDATE units SET main_chain_index=?, sequence=?, actual_tps_fee=? WHERE unit=?",
        [objUnit.main_chain_index, sequence, objUnit.actual_tps_fee, unit]);
    
    if (sequence === 'good')
        return async.series(arrQueries, cb);
    
    // void the final-bad
    archiving.generateQueriesToArchiveJoint(conn, objJoint, 'voided', arrQueries, function(){
        async.series(arrQueries, cb);
    });
}, cb2);
```

**Permanent Fix**:
Alternatively, implement retry logic with exponential backoff when voiding fails, ensuring eventual consistency.

**Additional Measures**:
- Add database constraint verification after voiding to detect inconsistencies
- Implement health check that detects final-bad units with undeleted outputs
- Add monitoring/alerts for voiding transaction failures
- Include recovery procedure in light client documentation

## Proof of Concept

```javascript
// Test: test_light_voiding_atomicity.js
const assert = require('assert');
const db = require('../db.js');
const light = require('../light.js');
const eventBus = require('../event_bus.js');

describe('Light client final-bad unit voiding atomicity', function() {
    it('should handle voiding transaction failure without leaving inconsistent state', function(done) {
        // Setup: Create test database with a final-bad unit scenario
        db.query("INSERT INTO units (unit, sequence, main_chain_index) VALUES (?, 'good', 100)", 
            ['test_unit_hash'], function() {
            
            db.query("INSERT INTO outputs (unit, message_index, output_index, address, amount, is_spent) VALUES (?, 0, 0, 'TEST_ADDRESS', 1000, 1)",
                ['test_unit_hash'], function() {
                
                // Simulate database failure during voiding by causing executeInTransaction to fail
                const originalExecuteInTransaction = db.executeInTransaction;
                let updateExecuted = false;
                let voidingAttempted = false;
                
                // Override db.query to track sequence update
                const originalQuery = db.query;
                db.query = function(sql, params, callback) {
                    if (sql.includes('UPDATE units SET main_chain_index')) {
                        updateExecuted = true;
                    }
                    return originalQuery.call(this, sql, params, callback);
                };
                
                // Override executeInTransaction to simulate failure during voiding
                db.executeInTransaction = function(doWork, onDone) {
                    voidingAttempted = true;
                    // Simulate database error
                    setTimeout(() => onDone(new Error('Simulated database error')), 10);
                };
                
                // Create mock history response with final-bad unit
                const objResponse = {
                    unstable_mc_joints: [/* mock witness proof */],
                    witness_change_and_definition_joints: [],
                    joints: [{
                        unit: {
                            unit: 'test_unit_hash',
                            main_chain_index: 100,
                            sequence: 'final-bad',
                            actual_tps_fee: 0
                        }
                    }],
                    proofchain_balls: []
                };
                
                // Process history - should fail during voiding
                light.processHistory(objResponse, Array(12).fill('WITNESS_ADDRESS'), {
                    ifError: function(err) {
                        // Restore original functions
                        db.query = originalQuery;
                        db.executeInTransaction = originalExecuteInTransaction;
                        
                        // Verify atomicity violation occurred
                        assert(updateExecuted, 'Sequence update should have executed');
                        assert(voidingAttempted, 'Voiding should have been attempted');
                        assert(err, 'Error should be propagated');
                        
                        // Check database state - this is the bug
                        db.query("SELECT sequence FROM units WHERE unit=?", ['test_unit_hash'], function(rows) {
                            assert.equal(rows[0].sequence, 'final-bad', 'Unit marked as final-bad');
                            
                            db.query("SELECT is_spent FROM outputs WHERE unit=?", ['test_unit_hash'], function(rows) {
                                // BUG: Output should be deleted or is_spent=0, but it remains is_spent=1
                                assert.equal(rows.length, 1, 'Output still exists (should be deleted)');
                                assert.equal(rows[0].is_spent, 1, 'Output still marked as spent (INCONSISTENT STATE)');
                                
                                console.log('VULNERABILITY CONFIRMED: Atomicity violation leaves outputs marked as spent after voiding failure');
                                done();
                            });
                        });
                    },
                    ifOk: function() {
                        assert.fail('Should not succeed when voiding fails');
                    }
                });
            });
        });
    });
});
```

**Notes**

This vulnerability represents a data integrity issue specific to light clients. While funds are not lost on the blockchain network, affected users lose access to them in their local light client database. The severity is HIGH rather than CRITICAL because:

1. Recovery is possible (though not automatic) via re-synchronization or manual intervention
2. No network-wide hard fork is required
3. Only light clients are affected, not full nodes
4. The funds exist on the blockchain; only local database access is impaired

The atomicity violation is clear and violates fundamental database consistency requirements. The fix is straightforward: wrap both operations in a single transaction using `db.executeInTransaction()` for the entire sequence.

### Citations

**File:** light.js (L310-325)
```javascript
								db.query(
									"UPDATE units SET main_chain_index=?, sequence=?, actual_tps_fee=? WHERE unit=?", 
									[objUnit.main_chain_index, sequence, objUnit.actual_tps_fee, unit], 
									function(){
										if (sequence === 'good')
											return cb2();
										// void the final-bad
										breadcrumbs.add('will void '+unit);
										db.executeInTransaction(function doWork(conn, cb3){
											var arrQueries = [];
											archiving.generateQueriesToArchiveJoint(conn, objJoint, 'voided', arrQueries, function(){
												async.series(arrQueries, cb3);
											});
										}, cb2);
									}
								);
```

**File:** balances.js (L15-18)
```javascript
		"SELECT asset, is_stable, SUM(amount) AS balance \n\
		FROM outputs "+join_my_addresses+" CROSS JOIN units USING(unit) \n\
		WHERE is_spent=0 AND "+where_condition+" AND sequence='good' \n\
		GROUP BY asset, is_stable",
```

**File:** db.js (L25-37)
```javascript
function executeInTransaction(doWork, onDone){
	module.exports.takeConnectionFromPool(function(conn){
		conn.query("BEGIN", function(){
			doWork(conn, function(err){
				conn.query(err ? "ROLLBACK" : "COMMIT", function(){
					conn.release();
					if (onDone)
						onDone(err);
				});
			});
		});
	});
}
```

**File:** archiving.js (L46-68)
```javascript
function generateQueriesToVoidJoint(conn, unit, arrQueries, cb){
	generateQueriesToUnspendOutputsSpentInArchivedUnit(conn, unit, arrQueries, function(){
		// we keep witnesses, author addresses, and the unit itself
		conn.addQuery(arrQueries, "DELETE FROM witness_list_hashes WHERE witness_list_unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM earned_headers_commission_recipients WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "UPDATE unit_authors SET definition_chash=NULL WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM address_definition_changes WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM inputs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM outputs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM spend_proofs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM poll_choices WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM polls WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM votes WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM attested_fields WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM attestations WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM asset_metadata WHERE asset=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM asset_denominations WHERE asset=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM asset_attestors WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM assets WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM messages WHERE unit=?", [unit]);
		cb();
	});
}
```

**File:** archiving.js (L70-104)
```javascript
function generateQueriesToUnspendOutputsSpentInArchivedUnit(conn, unit, arrQueries, cb){
	generateQueriesToUnspendTransferOutputsSpentInArchivedUnit(conn, unit, arrQueries, function(){
		generateQueriesToUnspendHeadersCommissionOutputsSpentInArchivedUnit(conn, unit, arrQueries, function(){
			generateQueriesToUnspendWitnessingOutputsSpentInArchivedUnit(conn, unit, arrQueries, cb);
		});
	});
}

function generateQueriesToUnspendTransferOutputsSpentInArchivedUnit(conn, unit, arrQueries, cb){
	conn.query(
		"SELECT src_unit, src_message_index, src_output_index \n\
		FROM inputs \n\
		WHERE inputs.unit=? \n\
			AND inputs.type='transfer' \n\
			AND NOT EXISTS ( \n\
				SELECT 1 FROM inputs AS alt_inputs \n\
				WHERE inputs.src_unit=alt_inputs.src_unit \n\
					AND inputs.src_message_index=alt_inputs.src_message_index \n\
					AND inputs.src_output_index=alt_inputs.src_output_index \n\
					AND alt_inputs.type='transfer' \n\
					AND inputs.unit!=alt_inputs.unit \n\
			)",
		[unit],
		function(rows){
			rows.forEach(function(row){
				conn.addQuery(
					arrQueries, 
					"UPDATE outputs SET is_spent=0 WHERE unit=? AND message_index=? AND output_index=?", 
					[row.src_unit, row.src_message_index, row.src_output_index]
				);
			});
			cb();
		}
	);
}
```

**File:** light_wallet.js (L199-204)
```javascript
				light.processHistory(response, objRequest.witnesses, {
					ifError: function(err){
						clearInterval(interval);
						network.sendError(ws, err);
						finish(err);
					},
```
