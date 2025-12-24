## Title
Foreign Key Constraint Violation Causes Node Crash During Poll Unit Archiving

## Summary
When archiving a poll unit with `sequence='final-bad'`, the deletion of `poll_choices` triggers a foreign key constraint violation if votes from other units still reference those choices. The error is thrown as an uncaught exception in `sqlite_pool.js`, crashing the node process and causing temporary network disruption.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay / Network Disruption

The vulnerability allows any user to crash nodes by creating polls that transition to `final-bad` status after receiving votes. No funds are lost, but affected nodes experience downtime until manual restart. The database transaction rollback prevents corruption.

## Finding Description

**Location**: `byteball/ocore/archiving.js` (function `generateQueriesToRemoveJoint()`, line 29) and `byteball/ocore/sqlite_pool.js` (error handling, line 115)

**Intended Logic**: The archiving mechanism should clean up bad units while respecting foreign key constraints. Votes referencing a poll should either be deleted first or the deletion should fail gracefully without crashing the node.

**Actual Logic**: The archiving process deletes `poll_choices` before checking if votes still reference them. When the foreign key constraint is violated, the error is thrown synchronously from an async callback, creating an unhandled exception that crashes the Node.js process.

**Code Evidence**:

Archiving deletion sequence that deletes poll_choices before votes that reference them: [1](#0-0) 

Foreign key constraint from votes to poll_choices in database schema: [2](#0-1) 

Error handling that throws uncaught exception on constraint violation: [3](#0-2) 

**Exploitation Path**:

1. **Preconditions**: Attacker has funds to create poll and vote units; network operates normally

2. **Step 1**: Attacker creates poll unit A that will later become `final-bad` (by spending from an output that later becomes bad, or via double-spend)
   - Code path: `composer.js` → `validation.js` → `storage.js`

3. **Step 2**: While poll unit A has `sequence='good'`, attacker or users cast votes (units B, C, D) referencing poll A
   - Vote validation passes because it checks poll sequence at submission time [4](#0-3) 

4. **Step 3**: Poll unit A transitions to `sequence='final-bad'` through conflict resolution or parent unit becoming bad

5. **Step 4**: Vote units B, C, D remain `sequence='good'` because bad status only propagates through spending relationships, not message references [5](#0-4) 

6. **Step 5**: Automatic archiving process runs every 60 seconds and selects unit A for removal [6](#0-5) 

7. **Step 6**: Archiving executes within transaction but deletes `poll_choices WHERE unit=A` while votes still reference them [7](#0-6) 

8. **Step 7**: Database raises foreign key constraint error, callback throws it synchronously, no error handling catches it

9. **Step 8**: Node crashes with unhandled exception; must be manually restarted

**Security Property Broken**: Error handling fails to gracefully handle database constraint violations during multi-step operations, violating node availability expectations.

**Root Cause Analysis**: 
The archiving deletion at line 29 only deletes votes contained IN the archived unit (`WHERE unit=?`), not votes that REFERENCE the archived poll (`WHERE poll_unit=?`). Combined with synchronous error throwing in async callbacks without proper error handling, this causes process crashes.

## Impact Explanation

**Affected Assets**: Node availability, network processing capacity

**Damage Severity**:
- **Quantitative**: Each exploited poll crashes one or more nodes. Attack is repeatable with multiple polls.
- **Qualitative**: Temporary service disruption; transaction rollback prevents database corruption

**User Impact**:
- **Who**: Users whose transactions route through crashed nodes; network capacity reduction
- **Conditions**: Exploitable when any poll unit with votes becomes `final-bad` through natural protocol operation
- **Recovery**: Nodes must be manually restarted; no data loss or corruption

**Systemic Risk**: Multiple simultaneous attacks could crash numerous nodes, causing network-wide transaction delays until nodes restart.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with minimal funds for transaction fees
- **Resources Required**: ~1000 bytes for poll creation + votes + double-spend setup
- **Technical Skill**: Medium - requires understanding DAG consensus and double-spend mechanics

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Unspent output to create transactions
- **Timing**: Poll must become final-bad after votes are cast (depends on consensus timing)

**Execution Complexity**:
- **Transaction Count**: 3+ transactions (poll, votes, conflicting unit)
- **Coordination**: Minimal - attacker can vote themselves, doesn't require other users
- **Detection Risk**: Low - appears as normal poll activity

**Frequency**:
- **Repeatability**: High - can repeat with multiple polls
- **Scale**: Per-poll impact on nodes that process the archiving

**Overall Assessment**: Medium likelihood - technically straightforward, low cost, repeatable, but requires timing around consensus.

## Recommendation

**Immediate Mitigation**:
Add proper error handling around archiving queries to catch and log foreign key violations without crashing:

```javascript
// In joint_storage.js around line 259
async.series(arrQueries, function(err){
    if (err) {
        console.error("Archiving error (non-fatal):", err);
        breadcrumbs.add("------- archiving failed for "+row.unit);
        return cb();
    }
    // ... existing success path
});
```

**Permanent Fix**:
Modify archiving deletion order to delete referencing votes before poll_choices:

```javascript
// In archiving.js, before line 29
conn.addQuery(arrQueries, "DELETE FROM votes WHERE poll_unit=?", [unit]);
conn.addQuery(arrQueries, "DELETE FROM poll_choices WHERE unit=?", [unit]);
```

**Additional Measures**:
- Add test case verifying archiving handles polls with external votes
- Consider ON DELETE CASCADE on foreign key (requires migration)
- Add monitoring for archiving failures

## Proof of Concept

```javascript
const async = require('async');
const db = require('./db.js');
const composer = require('./composer.js');
const network = require('./network.js');

// Test: Poll archiving with external votes crashes node
describe('Poll archiving foreign key violation', function() {
    it('should not crash when archiving poll with external votes', function(done) {
        this.timeout(60000);
        
        async.series([
            // Step 1: Create poll unit A
            function(cb) {
                composer.composeJoint({
                    paying_addresses: [address1],
                    outputs: [{address: address1, amount: 1000}],
                    messages: [{
                        app: 'poll',
                        payload: {
                            question: 'Test poll',
                            choices: ['Yes', 'No']
                        }
                    }],
                    callbacks: {
                        ifOk: function(joint) {
                            pollUnit = joint.unit.unit;
                            cb();
                        },
                        ifError: cb
                    }
                });
            },
            
            // Step 2: Cast vote from different address while poll is good
            function(cb) {
                composer.composeJoint({
                    paying_addresses: [address2],
                    outputs: [{address: address2, amount: 1000}],
                    messages: [{
                        app: 'vote',
                        payload: {
                            unit: pollUnit,
                            choice: 'Yes'
                        }
                    }],
                    callbacks: {
                        ifOk: function(joint) {
                            voteUnit = joint.unit.unit;
                            cb();
                        },
                        ifError: cb
                    }
                });
            },
            
            // Step 3: Create double-spend to make poll bad
            function(cb) {
                // Create conflicting unit spending same output as poll
                // Poll will become final-bad after stabilization
                createConflictingUnit(pollUnit, cb);
            },
            
            // Step 4: Wait for stabilization and archiving
            function(cb) {
                setTimeout(function() {
                    // Verify poll is final-bad
                    db.query("SELECT sequence FROM units WHERE unit=?", [pollUnit], function(rows) {
                        assert.equal(rows[0].sequence, 'final-bad');
                        cb();
                    });
                }, 30000);
            },
            
            // Step 5: Trigger archiving - should handle gracefully without crash
            function(cb) {
                const joint_storage = require('./joint_storage.js');
                
                // This should NOT crash the process
                joint_storage.purgeUncoveredNonserialJoints(false, function() {
                    // If we reach here, node didn't crash
                    cb();
                });
            }
        ], function(err) {
            assert.ifError(err, 'Node should not crash during poll archiving');
            done();
        });
    });
});
```

## Notes

The vulnerability is real but has limited impact. The transaction rollback prevents database corruption, so the only consequence is node downtime until restart. The fix is straightforward: either (1) add error handling to prevent crashes, or (2) delete votes referencing the poll before deleting poll_choices. The most robust solution combines both approaches.

### Citations

**File:** archiving.js (L29-31)
```javascript
		conn.addQuery(arrQueries, "DELETE FROM poll_choices WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM polls WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM votes WHERE unit=?", [unit]);
```

**File:** initial-db/byteball-sqlite.sql (L229-229)
```sql
	CONSTRAINT votesByChoice FOREIGN KEY (poll_unit, choice) REFERENCES poll_choices(unit, choice),
```

**File:** sqlite_pool.js (L113-115)
```javascript
					if (err){
						console.error("\nfailed query:", new_args);
						throw Error(err+"\n"+sql+"\n"+new_args[1].map(function(param){ if (param === null) return 'null'; if (param === undefined) return 'undefined'; return param;}).join(', '));
```

**File:** validation.js (L1638-1639)
```javascript
					if (objPollUnitProps.sequence !== 'good')
						return callback("poll unit is not serial");
```

**File:** main_chain.js (L1305-1305)
```javascript
		conn.query("SELECT DISTINCT inputs.unit, main_chain_index FROM inputs LEFT JOIN units USING(unit) WHERE src_unit IN(?)", [arrFinalBadUnits], function(rows){
```

**File:** network.js (L4068-4068)
```javascript
	setInterval(joint_storage.purgeUncoveredNonserialJointsUnderLock, 60*1000);
```

**File:** joint_storage.js (L255-257)
```javascript
									conn.addQuery(arrQueries, "BEGIN");
									archiving.generateQueriesToArchiveJoint(conn, objJoint, 'uncovered', arrQueries, function(){
										conn.addQuery(arrQueries, "COMMIT");
```
