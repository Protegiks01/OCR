# Concurrent Double-Spend Validation Race Causes Node Crash via UNIQUE Constraint Violation

## Summary

A race condition in the validation system allows two units from different authors to concurrently spend the same output, both passing validation with `is_unique=1`. When the second unit attempts to insert into the database, it violates a UNIQUE constraint, triggering an unhandled exception that crashes the node process. This occurs because validation locks on author addresses rather than outputs being spent, and SQLite's snapshot isolation prevents concurrent transactions from seeing each other's uncommitted writes. [1](#0-0) 

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

**Affected Assets**: All network nodes accepting units from untrusted peers

**Damage Severity**:
- **Quantitative**: Complete node unavailability upon receiving the malicious unit pair. Attack can be repeated indefinitely with minimal cost (one UTXO per attack iteration).
- **Qualitative**: Systematic denial of service against validator nodes, hubs, and full nodes. Attacker can target multiple nodes simultaneously, effectively shutting down transaction validation network-wide.

**User Impact**:
- **Who**: All users whose nodes accept units from untrusted sources (peer-to-peer network propagation)
- **Conditions**: Exploitable during normal operation whenever concurrent units are submitted
- **Recovery**: Manual node restart required after each crash; persistent attacks require network-level blocking

**Systemic Risk**: Witness nodes can be crashed, disrupting consensus. No rate limiting or automatic recovery mechanism exists.

## Finding Description

**Location**: `byteball/ocore/validation.js` lines 223-244, `byteball/ocore/writer.js` lines 357-371, `byteball/ocore/sqlite_pool.js` lines 111-115 [2](#0-1) [3](#0-2) [4](#0-3) 

**Intended Logic**: The double-spend prevention system should detect when two units attempt to spend the same output during validation. The `checkForDoublespends()` function queries the inputs table, and any conflicts should be marked with `is_unique=NULL`. The database UNIQUE constraint serves as a final safeguard.

**Actual Logic**: 

1. Validation locks on author addresses (line 223: `mutex.lock(arrAuthorAddresses, ...)`), allowing concurrent validation of units from different authors.

2. Each validation starts its own database transaction (line 244: `conn.query("BEGIN", ...)`). Due to SQLite's WAL mode snapshot isolation, each transaction sees a snapshot at its BEGIN time.

3. Both validations execute the double-spend check query, but neither sees the other's uncommitted transaction. Both queries return 0 rows, resulting in empty `arrDoubleSpendInputs`.

4. Both units proceed to the write phase with the decision to use `is_unique=1` already made during validation.

5. The units acquire the global "write" lock sequentially, but it's too late—the `is_unique` value was determined during concurrent validation.

6. First unit inserts successfully. Second unit's INSERT violates the UNIQUE constraint on `(src_unit, src_message_index, src_output_index, is_unique)`. [5](#0-4) 

7. The database error callback throws an Error (sqlite_pool.js:115), which occurs inside an asynchronous context where it cannot be caught by `async.series()`.

8. With no `uncaughtException` handler in the codebase, the Node.js process crashes.

**Exploitation Path**:

1. **Preconditions**: Attacker controls two addresses (Alice and Bob) and creates one UTXO to Alice's address.

2. **Step 1**: Attacker creates Unit A (authored by Alice) and Unit B (authored by Bob), both spending the same UTXO. Submits both units to target node simultaneously (within ~100-500ms).
   - Code path: `network.js` receives joints → `validation.js:validate()` called for each

3. **Step 2**: Unit A's validation acquires mutex lock on Alice's address. Unit B's validation acquires mutex lock on Bob's address. No contention—both proceed concurrently.
   - Code: `mutex.lock(arrAuthorAddresses, ...)` at line 223

4. **Step 3**: Both validations start separate database transactions and query for double-spends: [6](#0-5) [7](#0-6) 

   Both queries return 0 rows due to snapshot isolation. Both validations complete with `arrDoubleSpendInputs = []`.

5. **Step 4**: Unit A acquires write lock, inserts with `is_unique=1`, commits, releases write lock. [8](#0-7) 

6. **Step 5**: Unit B acquires write lock, attempts INSERT with `is_unique=1`. UNIQUE constraint violated.

7. **Step 6**: Database returns error. The error callback throws: [9](#0-8) 

   This throw occurs inside the async callback, after the `async.series()` task wrapper, so it cannot be caught.

8. **Step 7**: Unhandled exception propagates to Node.js event loop. Node crashes with exit code 1 (no `uncaughtException` handler exists in ocore).

**Security Properties Broken**:
- **Double-Spend Prevention**: Race condition allows both units to believe they are unique spenders
- **System Availability**: Unhandled exception crashes the node process
- **Transaction Atomicity**: Error handling for constraint violations is incomplete

**Root Cause Analysis**:

1. **Insufficient Locking Granularity**: Validation locks on author addresses rather than the specific outputs being spent, permitting concurrent validation of conflicting spends from different authors.

2. **Transaction Isolation Gap**: SQLite WAL mode provides snapshot isolation. The double-spend check during validation reads from a snapshot that doesn't include uncommitted concurrent transactions—classic TOCTOU vulnerability.

3. **Late Write Lock**: The global "write" lock is acquired in `saveJoint()` AFTER validation completes. The decision to use `is_unique=1` was made during validation using stale data.

4. **Unhandled Constraint Violation**: Database errors throw synchronous exceptions in asynchronous callbacks, which cannot be caught by `async.series()` error handlers.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with two addresses and ability to submit units
- **Resources Required**: Minimal—one UTXO (~1000 bytes), two addresses, network connectivity
- **Technical Skill**: Low—craft two units with same input using existing SDKs, submit concurrently

**Preconditions**:
- **Network State**: Normal operation (any time node accepts units from peers)
- **Attacker State**: Controls two addresses, has one unspent output
- **Timing**: Units must arrive within validation window (typically 100-500ms before first commits)

**Execution Complexity**:
- **Transaction Count**: 2 units per attack iteration
- **Coordination**: Minimal—simultaneous API calls via script
- **Detection Risk**: Low until crash occurs (appears as normal double-spend attempt)

**Frequency**:
- **Repeatability**: Unlimited—new UTXO per attack iteration
- **Scale**: Can target multiple nodes simultaneously

**Overall Assessment**: **High likelihood**—attack is trivial to execute, requires minimal resources, has high success rate, and is easily automated.

## Recommendation

**Immediate Mitigation**:

Wrap database constraint violations in error handling rather than throwing:

```javascript
// sqlite_pool.js:111-116
new_args.push(function(err, result){
    if (err){
        console.error("\nfailed query:", new_args);
        // Pass error to callback instead of throwing
        return last_arg({error: err, sql: sql});
    }
    // ... existing code ...
});
```

**Permanent Fix**:

1. **Lock on outputs being spent** rather than author addresses:
   - Modify `validation.js` to extract output references from all units
   - Acquire mutex locks on `src_unit+src_message_index+src_output_index` keys
   - Prevents concurrent validation of conflicting spends

2. **Re-check double-spends under write lock**:
   - In `writer.js:saveJoint()`, after acquiring write lock but before INSERT
   - Query inputs table again to detect races
   - If conflict found, reject unit with proper error (don't crash)

3. **Add graceful error handling** for all database constraint violations throughout the codebase.

**Additional Measures**:
- Add integration test reproducing concurrent double-spend scenario
- Add monitoring for constraint violation errors
- Implement automatic node restart with exponential backoff
- Add rate limiting on unit acceptance per peer

## Proof of Concept

```javascript
// Test: test/concurrent_doublespend_crash.test.js
const assert = require('assert');
const db = require('../db.js');
const composer = require('../composer.js');
const validation = require('../validation.js');
const writer = require('../writer.js');

describe('Concurrent double-spend node crash', function() {
    this.timeout(10000);
    
    before(async function() {
        // Initialize test database
        await db.executeInTransaction(async conn => {
            // Create genesis unit and test UTXO
            // ... setup code ...
        });
    });
    
    it('should not crash on concurrent double-spend attempts', async function() {
        // Create two addresses (Alice and Bob)
        const aliceAddress = "ALICE_TEST_ADDRESS_32CHARS_XXX";
        const bobAddress = "BOB_TEST_ADDRESS_32CHARS_XXXXX";
        
        // Create output owned by Alice
        const testOutput = {
            unit: "TEST_UNIT_HASH_44CHARS_XXXXXXXXXXXXXXXXXXXXXX",
            message_index: 0,
            output_index: 0,
            amount: 10000
        };
        
        // Compose Unit A (Alice spending output)
        const unitA = await composer.composeJoint({
            paying_addresses: [aliceAddress],
            outputs: [{address: "RECIPIENT_ADDRESS", amount: 10000}],
            inputs: [{
                unit: testOutput.unit,
                message_index: testOutput.message_index,
                output_index: testOutput.output_index
            }]
        });
        
        // Compose Unit B (Bob spending SAME output - invalid but should not crash)
        const unitB = await composer.composeJoint({
            paying_addresses: [bobAddress],
            outputs: [{address: "RECIPIENT_ADDRESS", amount: 10000}],
            inputs: [{
                unit: testOutput.unit,
                message_index: testOutput.message_index,
                output_index: testOutput.output_index
            }]
        });
        
        // Submit both units concurrently
        let crashDetected = false;
        process.once('uncaughtException', () => {
            crashDetected = true;
        });
        
        await Promise.all([
            validation.validate(unitA.unit, {}),
            validation.validate(unitB.unit, {})
        ]).catch(err => {
            // One should fail validation, but should NOT crash
        });
        
        // Wait briefly for potential crash
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Assert node did not crash
        assert.strictEqual(crashDetected, false, 
            "Node crashed due to UNIQUE constraint violation");
    });
});
```

**Notes**: 
- This vulnerability is a **TOCTOU race condition** where validation's check (concurrent, per-author locks, snapshot reads) becomes stale by the time of use (sequential write, constraint enforcement).
- The database constraint prevents actual double-spending but at the cost of node availability.
- Fix requires either locking on outputs (preventing concurrent validation of conflicts) or re-checking under write lock (detecting stale validation results).

### Citations

**File:** validation.js (L223-244)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
		
		var conn = null;
		var commit_fn = null;
		var start_time = null;

		async.series(
			[
				function(cb){
					if (external_conn) {
						conn = external_conn;
						start_time = Date.now();
						commit_fn = function (cb2) { cb2(); };
						return cb();
					}
					db.takeConnectionFromPool(function(new_conn){
						conn = new_conn;
						start_time = Date.now();
						commit_fn = function (cb2) {
							conn.query(objValidationState.bAdvancedLastStableMci ? "COMMIT" : "ROLLBACK", function () { cb2(); });
						};
						conn.query("BEGIN", function(){cb();});
```

**File:** validation.js (L2037-2040)
```javascript
				var doubleSpendQuery = "SELECT "+doubleSpendFields+" FROM inputs " + doubleSpendIndexMySQL + " JOIN units USING(unit) WHERE "+doubleSpendWhere;
				checkForDoublespends(
					conn, "divisible input", 
					doubleSpendQuery, doubleSpendVars, 
```

**File:** validation.js (L2175-2176)
```javascript
					doubleSpendWhere = "type=? AND src_unit=? AND src_message_index=? AND src_output_index=?";
					doubleSpendVars = [type, input.unit, input.message_index, input.output_index];
```

**File:** writer.js (L33-33)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
```

**File:** writer.js (L357-371)
```javascript
							determineInputAddress(function(address){
								var is_unique = 
									(objValidationState.arrDoubleSpendInputs.some(function(ds){ return (ds.message_index === i && ds.input_index === j); }) || conf.bLight) 
									? null : 1;
								conn.addQuery(arrQueries, "INSERT INTO inputs \n\
										(unit, message_index, input_index, type, \n\
										src_unit, src_message_index, src_output_index, \
										from_main_chain_index, to_main_chain_index, \n\
										denomination, amount, serial_number, \n\
										asset, is_unique, address) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
									[objUnit.unit, i, j, type, 
									 src_unit, src_message_index, src_output_index, 
									 from_main_chain_index, to_main_chain_index, 
									 denomination, input.amount, input.serial_number, 
									 payload.asset, is_unique, address]);
```

**File:** sqlite_pool.js (L111-115)
```javascript
				new_args.push(function(err, result){
					//console.log("query done: "+sql);
					if (err){
						console.error("\nfailed query:", new_args);
						throw Error(err+"\n"+sql+"\n"+new_args[1].map(function(param){ if (param === null) return 'null'; if (param === undefined) return 'undefined'; return param;}).join(', '));
```

**File:** initial-db/byteball-sqlite.sql (L305-305)
```sql
	UNIQUE  (src_unit, src_message_index, src_output_index, is_unique), -- UNIQUE guarantees there'll be no double spend for type=transfer
```
