# Race Condition in Indivisible Asset Serial Number Assignment Causes Node Crashes

## Summary

A race condition in the `issueNextCoin()` function allows concurrent issuance from separate nodes to assign duplicate serial numbers to indivisible assets. The non-atomic read-modify-write pattern, combined with validation logic that accepts conflicting units on different DAG branches, enables both units to be stored with `is_unique=NULL`. When both units stabilize, the database UNIQUE constraint violation causes unhandled exceptions that crash affected nodes.

## Impact

**Severity**: High  
**Category**: Network Disruption / Permanent Ledger Inconsistency

**Concrete Impact:**
- All nodes that receive both conflicting units crash during stabilization with unhandled database exceptions
- Affected nodes enter a crash loop on restart when attempting to process the duplicate stabilization
- Duplicate serial numbers permanently violate the uniqueness invariant for indivisible assets
- Manual database intervention or protocol hard fork required to resolve inconsistency

**Affected Parties:**
- Any node that receives both conflicting units (crashes)
- Network capacity reduced as nodes become unavailable
- Asset holders whose asset has duplicate serials (permanent ledger corruption)

## Finding Description

**Location**: Multiple files interact to create this vulnerability

**Intended Logic**: Each indivisible asset issuance should receive a unique serial number by atomically reading and incrementing `max_issued_serial_number`. The UNIQUE constraint in the database should prevent duplicate serial numbers.

**Actual Logic**: The serial number assignment is non-atomic across three separate operations, and the mutex lock only protects operations on the same node. Different nodes maintain independent counter states, allowing concurrent issuance to assign duplicate serial numbers.

**Code Evidence**: [1](#0-0) 

The above code shows the non-atomic read-modify-write sequence where:
1. Line 506-510: SELECT query reads current `max_issued_serial_number`
2. Line 518: JavaScript calculates `serial_number = row.max_issued_serial_number+1`
3. Line 522: UPDATE increments the database counter

**Mutex Protection is Node-Local Only**: [2](#0-1) 

The mutex lock serializes operations on the same node but does not prevent concurrent execution across different nodes, as mutex instances are in-memory and process-local.

**Validation Accepts Conflicts on Different Branches**: [3](#0-2) 

When conflicting units are on different DAG branches (`bIncluded` is false), the validation accepts them without error.

**Conflicts Marked as is_unique=NULL**: [4](#0-3) 

Conflicting inputs on unstable units are marked with `is_unique=NULL`.

**Database UNIQUE Constraint Allows Multiple NULLs**: [5](#0-4) 

Since SQL treats `NULL != NULL`, multiple rows with `is_unique=NULL` can coexist despite having identical `(asset, denomination, serial_number, address)` values.

**Stabilization UPDATE Lacks Error Handling**: [6](#0-5) 

The callback has no error parameter. When the UPDATE violates the UNIQUE constraint, the error propagates unhandled.

**Database Wrappers Throw Errors Instead of Passing to Callbacks**: [7](#0-6) [8](#0-7) 

Both database wrappers throw errors instead of passing them to callbacks, causing unhandled exceptions when the UNIQUE constraint is violated.

## Exploitation Path

**Preconditions**:
- Indivisible asset exists with `issued_by_definer_only=true`
- Definer controls wallet on two separate nodes (Node A and Node B)
- Current `max_issued_serial_number = 5`

**Step 1 - Concurrent Issuance**:
- Node A: Reads `max_issued_serial_number = 5`, calculates `serial_number = 6`, updates counter to 6
- Node B: Concurrently reads `max_issued_serial_number = 5`, calculates `serial_number = 6`, updates counter to 7
- Both nodes create units with `serial_number = 6` and broadcast to network

**Step 2 - Validation Accepts Conflicts**:
- A third node receives both units
- Validation detects them as conflicting (same asset, denomination, serial_number, address)
- Since units are on different DAG branches, `checkForDoublespends()` accepts both
- Both units stored with `is_unique=NULL` in the `inputs` table

**Step 3 - Database Allows Duplicate NULLs**:
- UNIQUE constraint `(asset, denomination, serial_number, address, is_unique)` allows both rows because `NULL != NULL` in SQL

**Step 4 - Node Crash During Stabilization**:
- Both units eventually stabilize
- Stabilization code executes `UPDATE inputs SET is_unique=1 WHERE unit=?` for first unit - succeeds
- Stabilization code executes `UPDATE inputs SET is_unique=1 WHERE unit=?` for second unit - UNIQUE constraint violation
- Database wrapper throws error, callback has no error parameter - unhandled exception
- Node crashes

**Security Properties Broken**:
1. **Indivisible Serial Uniqueness Invariant** - Each serial number must be issued exactly once
2. **Transaction Atomicity Invariant** - Serial number read-modify-write must be atomic

**Root Cause Analysis**:
1. Node-local counter state not synchronized across network
2. Non-atomic read-calculate-write operations create race window
3. Mutex only protects single-node operations, not cross-node
4. Validation intentionally accepts conflicts with `is_unique=NULL` for unstable units
5. Stabilization UPDATE callback lacks error handling
6. Database wrappers throw instead of passing errors to callbacks

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Asset definer who controls the definer address
- **Resources**: Two nodes running simultaneously with same wallet (common for redundancy)
- **Technical Skill**: Moderate - requires triggering concurrent issuance transactions

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Operates multiple nodes (standard practice for availability)
- **Timing**: Concurrent issuance attempts within overlapping window

**Execution Complexity**:
- **Transaction Count**: Two concurrent issuance transactions
- **Coordination**: Both nodes attempt issuance at approximately the same time
- **Detection Risk**: Appears as normal activity until stabilization fails

**Overall Assessment**: Medium likelihood - requires infrastructure setup (multiple nodes) but straightforward execution once in place. Impact severity justifies HIGH classification.

## Recommendation

**Immediate Mitigation**:
Wrap stabilization UPDATE in error handling to prevent crashes while investigating:

```javascript
// File: byteball/ocore/main_chain.js
// Function: updateMainChainIndex()
conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], function(err){
    if (err) {
        console.error("Failed to set is_unique=1 for unit "+row.unit+": "+err);
        // Log error for manual intervention, continue processing other units
    }
    storage.assocStableUnits[row.unit].sequence = 'good';
    cb();
});
```

**Permanent Fix**:
Implement atomic serial number assignment using database-level atomic operations:

```javascript
// File: byteball/ocore/indivisible_asset.js
// Function: issueNextCoin()
// Replace lines 506-524 with:
conn.query(
    "UPDATE asset_denominations SET max_issued_serial_number=max_issued_serial_number+1 \n\
     WHERE denomination=? AND asset=? RETURNING max_issued_serial_number",
    [denomination, asset],
    function(rows){
        var serial_number = rows[0].max_issued_serial_number;
        // Continue with issuance using atomically-assigned serial_number
    }
);
```

**Additional Measures**:
- Add unique constraint enforcement check before accepting conflicting units with duplicate serials
- Add test case verifying concurrent issuance attempts from separate nodes result in unique serial numbers
- Database migration to detect and resolve any existing duplicate serial numbers
- Add monitoring to alert on `is_unique=NULL` inputs that remain unstable for extended periods

**Validation**:
- Fix ensures serial numbers are assigned atomically at database level
- No race window between read and write operations
- Compatible with existing validation logic
- Performance impact minimal (single query instead of two)

## Proof of Concept

```javascript
// File: test/concurrent_indivisible_issuance.test.js
const test = require('ava');
const db = require('../db.js');
const indivisible_asset = require('../indivisible_asset.js');
const composer = require('../composer.js');

test.serial('concurrent issuance from separate nodes assigns duplicate serial numbers', async t => {
    // Setup: Create indivisible asset with issued_by_definer_only=true
    const asset = 'test_asset_hash';
    const denomination = 1;
    const definer_address = 'DEFINER_ADDRESS';
    
    // Initialize asset_denominations table with max_issued_serial_number=5
    await db.query(
        "INSERT INTO asset_denominations (asset, denomination, max_issued_serial_number, count_coins) VALUES (?,?,?,?)",
        [asset, denomination, 5, 1]
    );
    
    // Simulate two nodes issuing concurrently
    const issuePromises = [];
    for (let i = 0; i < 2; i++) {
        issuePromises.push(new Promise((resolve, reject) => {
            db.takeConnectionFromPool(conn => {
                // Simulate issueNextCoin execution
                conn.query(
                    "SELECT max_issued_serial_number FROM asset_denominations WHERE asset=? AND denomination=?",
                    [asset, denomination],
                    function(rows){
                        const serial_number = rows[0].max_issued_serial_number + 1;
                        // Both nodes read serial_number=6
                        conn.query(
                            "UPDATE asset_denominations SET max_issued_serial_number=max_issued_serial_number+1 WHERE denomination=? AND asset=?",
                            [denomination, asset],
                            function(){
                                conn.release();
                                resolve(serial_number);
                            }
                        );
                    }
                );
            });
        }));
    }
    
    const [serial1, serial2] = await Promise.all(issuePromises);
    
    // VULNERABILITY: Both nodes assign the same serial number
    t.is(serial1, 6, 'First node assigns serial_number=6');
    t.is(serial2, 6, 'Second node also assigns serial_number=6 - DUPLICATE!');
    
    // Create two units with duplicate serial numbers
    // Insert into inputs table with is_unique=NULL (simulating validation acceptance)
    await db.query(
        "INSERT INTO inputs (unit, message_index, input_index, serial_number, asset, denomination, address, type, is_unique) VALUES (?,?,?,?,?,?,?,?,?)",
        ['unit1', 0, 0, 6, asset, denomination, definer_address, 'issue', null]
    );
    await db.query(
        "INSERT INTO inputs (unit, message_index, input_index, serial_number, asset, denomination, address, type, is_unique) VALUES (?,?,?,?,?,?,?,?,?)",
        ['unit2', 0, 0, 6, asset, denomination, definer_address, 'issue', null]
    );
    
    // Simulate stabilization - first UPDATE succeeds
    await db.query("UPDATE inputs SET is_unique=1 WHERE unit=?", ['unit1']);
    
    // Second UPDATE should violate UNIQUE constraint and throw
    await t.throwsAsync(
        async () => db.query("UPDATE inputs SET is_unique=1 WHERE unit=?", ['unit2']),
        {message: /UNIQUE constraint/i},
        'Second stabilization UPDATE violates UNIQUE constraint - NODE CRASH'
    );
});
```

## Notes

This vulnerability requires the asset definer to operate multiple nodes simultaneously, which is a common practice for redundancy and availability. The attack is unintentional - a definer legitimately issuing assets from multiple nodes would unknowingly trigger this bug. The permanent ledger inconsistency and node crashes make this a HIGH severity issue requiring immediate attention.

The fix must ensure atomic serial number assignment across all nodes by using database-level atomic operations rather than application-level read-modify-write sequences.

### Citations

**File:** indivisible_asset.js (L506-524)
```javascript
			conn.query(
				"SELECT denomination, count_coins, max_issued_serial_number FROM asset_denominations \n\
				WHERE asset=? AND "+can_issue_condition+" AND denomination<=? \n\
				ORDER BY denomination DESC LIMIT 1", 
				[asset, remaining_amount+tolerance_plus], 
				function(rows){
					if (rows.length === 0)
						return onDone(NOT_ENOUGH_FUNDS_ERROR_MESSAGE);
					var row = rows[0];
					if (!!row.count_coins !== !!objAsset.cap)
						throw Error("invalid asset cap and count_coins");
					var denomination = row.denomination;
					var serial_number = row.max_issued_serial_number+1;
					var count_coins_to_issue = row.count_coins || Math.floor((remaining_amount+tolerance_plus)/denomination);
					var issue_amount = count_coins_to_issue * denomination;
					conn.query(
						"UPDATE asset_denominations SET max_issued_serial_number=max_issued_serial_number+1 WHERE denomination=? AND asset=?", 
						[denomination, asset], 
						function(){
```

**File:** composer.js (L288-293)
```javascript
		function(cb){ // lock
			mutex.lock(arrFromAddresses.map(function(from_address){ return 'c-'+from_address; }), function(unlock){
				unlock_callback = unlock;
				cb();
			});
		},
```

**File:** validation.js (L1470-1492)
```javascript
					graph.determineIfIncludedOrEqual(conn, objConflictingRecord.unit, objUnit.parent_units, function(bIncluded){
						if (bIncluded){
							var error = objUnit.unit+": conflicting "+type+" in inner unit "+objConflictingRecord.unit;

							// too young (serial or nonserial)
							if (objConflictingRecord.main_chain_index > objValidationState.last_ball_mci || objConflictingRecord.main_chain_index === null)
								return cb2(error);

							// in good sequence (final state)
							if (objConflictingRecord.sequence === 'good')
								return cb2(error);

							// to be voided: can reuse the output
							if (objConflictingRecord.sequence === 'final-bad')
								return cb2();

							throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit);
						}
						else{ // arrAddressesWithForkedPath is not set when validating private payments
							if (objValidationState.arrAddressesWithForkedPath && objValidationState.arrAddressesWithForkedPath.indexOf(objConflictingRecord.address) === -1)
								throw Error("double spending "+type+" without double spending address?");
							cb2();
						}
```

**File:** validation.js (L2042-2063)
```javascript
					function acceptDoublespends(cb3){
						console.log("--- accepting doublespend on unit "+objUnit.unit);
						var sql = "UPDATE inputs SET is_unique=NULL WHERE "+doubleSpendWhere+
							" AND (SELECT is_stable FROM units WHERE units.unit=inputs.unit)=0";
						if (!(objAsset && objAsset.is_private)){
							objValidationState.arrAdditionalQueries.push({sql: sql, params: doubleSpendVars});
							objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
							return cb3();
						}
						mutex.lock(["private_write"], function(unlock){
							console.log("--- will ununique the conflicts of unit "+objUnit.unit);
							conn.query(
								sql, 
								doubleSpendVars, 
								function(){
									console.log("--- ununique done unit "+objUnit.unit);
									objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
									unlock();
									cb3();
								}
							);
						});
```

**File:** initial-db/byteball-sqlite.sql (L307-307)
```sql
	UNIQUE  (asset, denomination, serial_number, address, is_unique), -- UNIQUE guarantees there'll be no double issue
```

**File:** main_chain.js (L1260-1264)
```javascript
								if (sequence === 'good')
									conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], function(){
										storage.assocStableUnits[row.unit].sequence = 'good';
										cb();
									});
```

**File:** sqlite_pool.js (L113-115)
```javascript
					if (err){
						console.error("\nfailed query:", new_args);
						throw Error(err+"\n"+sql+"\n"+new_args[1].map(function(param){ if (param === null) return 'null'; if (param === undefined) return 'undefined'; return param;}).join(', '));
```

**File:** mysql_pool.js (L47-47)
```javascript
				throw err;
```
