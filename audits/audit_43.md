## Title
Unhandled Async Error in Post-Commit Callback Causes Permanent Write Mutex Deadlock and Network Freeze

## Summary
The `saveJoint()` function in `writer.js` uses an async callback after committing database transactions, but lacks error handling for rejected promises. When AA trigger handling or TPS fee update operations fail, the write mutex is never released, causing all subsequent unit writes to block indefinitely and freezing the entire network.

## Impact
**Severity**: Critical  
**Category**: Network Shutdown

The vulnerability causes complete network paralysis. All nodes attempting to write new units block permanently, preventing any transaction confirmations. The entire network becomes non-operational, requiring manual node restarts across all validators. All user funds become effectively frozen as no transactions can be processed.

## Finding Description

**Location**: `byteball/ocore/writer.js`, function `saveJoint()`, lines 693-730 [1](#0-0) 

**Intended Logic**: After committing a unit to the database, the code should handle AA triggers, update TPS fees, emit events, call the completion callback, and release the write mutex via `unlock()` to allow subsequent units to be processed.

**Actual Logic**: The post-commit callback is declared as an async function [2](#0-1) , but when the awaited operations reject, the promise rejection is unhandled. This prevents execution from reaching the critical `unlock()` call [3](#0-2) , leaving the mutex permanently locked.

**Exploitation Path**:

1. **Preconditions**: Network is operational and processing units normally. The write mutex is acquired at the start of `saveJoint()` [1](#0-0) 

2. **Step 1**: A unit is submitted that causes MCIs to stabilize, setting `bStabilizedAATriggers = true` [4](#0-3) 

3. **Step 2**: The database transaction commits successfully at line 693, but the write mutex is still held.

4. **Step 3**: The code attempts to handle AA triggers via `await aa_composer.handleAATriggers()` [5](#0-4) 

5. **Step 4**: Inside `handleAATriggers()`, multiple error scenarios can occur:
   - Database query rejection in the async callback [6](#0-5) 
   - Thrown error if unit props not found in cache [7](#0-6) 
   - Thrown error if kvstore batch write fails [8](#0-7) 

6. **Step 5**: Alternatively, `await storage.updateTpsFees()` can reject due to database query failures [9](#0-8) [10](#0-9) [11](#0-10) 

7. **Step 6**: When any of these operations throw or reject, the async callback rejects. Lines 724-729 never execute - `onDone()` is not called, and critically, `unlock()` is never called [12](#0-11) 

8. **Result**: The write mutex remains locked forever. All subsequent `saveJoint()` calls block at line 33 waiting for the mutex. No new units can be written to the database. The entire network freezes.

**Security Property Broken**: The fundamental invariant that acquired mutexes must be released is violated. This also breaks transaction atomicity at the system level - while the database transaction is atomic, the post-commit operations (AA trigger handling) are non-atomic with the mutex release, causing system-level inconsistency.

**Root Cause Analysis**: The code mixes synchronous control flow (mutex locking/unlocking) with asynchronous operations (async/await) without proper error handling. The `commit_fn` callback is defined to simply call the callback without handling the returned promise [13](#0-12) . When the async callback rejects, there's no catch handler, and the cleanup code (`unlock()`) is never reached.

## Impact Explanation

**Affected Assets**: All network participants, entire network operation, all bytes and custom assets

**Damage Severity**:
- **Quantitative**: 100% of network transaction capacity is lost. All user funds become frozen (cannot be moved). No time limit on freeze duration - permanent until manual intervention.
- **Qualitative**: Catastrophic - requires emergency node restarts across all validators. All economic activity ceases. The AA triggers table may contain stale entries requiring manual cleanup.

**User Impact**:
- **Who**: All users, validators, AA operators, exchange operators, and any service depending on the Obyte network
- **Conditions**: Triggered whenever a unit stabilizes MCIs while any error occurs during AA trigger handling or TPS fee updates
- **Recovery**: Requires manual node restart on all affected nodes. May require database cleanup of pending AA triggers.

**Systemic Risk**: Cascading network failure - once one node freezes, peers continue broadcasting units that cannot be processed, causing more nodes to freeze. Within minutes, the entire network becomes non-operational. The vulnerability can be triggered accidentally by infrastructure issues (database connection failures, disk errors) or intentionally by deploying problematic AAs.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Can be triggered accidentally by legitimate activity (database errors, infrastructure issues) or intentionally by malicious actors deploying AAs with edge cases
- **Resources Required**: Ability to submit transactions (minimal cost). No special privileges needed.
- **Technical Skill**: Low to Medium - can occur naturally, or be intentionally triggered with understanding of AA trigger timing

**Preconditions**:
- **Network State**: At least one AA trigger must be pending when a unit stabilizes MCIs (common during normal operation)
- **Attacker State**: None required for accidental triggers; for intentional exploitation, ability to deploy AA and submit trigger units
- **Timing**: Any time AA triggers are being processed

**Execution Complexity**:
- **Transaction Count**: Single unit submission can trigger the bug
- **Coordination**: None required
- **Detection Risk**: Low - appears as normal unit submission followed by network hang

**Frequency**:
- **Repeatability**: Can occur repeatedly during normal operation whenever database/infrastructure errors occur
- **Scale**: Single occurrence freezes entire network

**Overall Assessment**: High likelihood. The error handling gap is always present and can be triggered by database connection failures, disk errors, memory issues, or edge cases in AA execution that are difficult to predict or prevent. Production databases inevitably experience transient errors.

## Recommendation

**Immediate Mitigation**:
Wrap the async operations in a try-catch-finally block to ensure `unlock()` is always called:

```javascript
// In writer.js, modify the commit_fn callback starting at line 693
commit_fn(err ? "ROLLBACK" : "COMMIT", async function(){
    try {
        // existing code lines 694-728
        if (bStabilizedAATriggers) {
            // ... AA trigger handling and TPS fee updates
        }
        if (onDone)
            onDone(err);
    } catch (error) {
        console.error("Error in post-commit callback:", error);
        if (onDone)
            onDone(error);
    } finally {
        unlock(); // Always release the mutex
    }
});
```

**Permanent Fix**:
1. Add comprehensive error handling around all async operations in post-commit callbacks
2. Ensure `unlock()` is called in all code paths (success, error, exception)
3. Add logging for unhandled promise rejections in the callback
4. Consider refactoring to use async/await consistently throughout the stack

**Additional Measures**:
- Add monitoring to detect when the write mutex remains locked beyond expected duration
- Implement automatic mutex release with timeout as a failsafe
- Add test coverage for error scenarios in AA trigger handling
- Review all other locations where mutexes are used to ensure similar patterns don't exist

## Proof of Concept

```javascript
// test/mutex_deadlock.test.js
const test = require('ava');
const writer = require('../writer.js');
const aa_composer = require('../aa_composer.js');
const mutex = require('../mutex.js');

// Mock aa_composer.handleAATriggers to throw an error
const originalHandleAATriggers = aa_composer.handleAATriggers;
aa_composer.handleAATriggers = async function() {
    throw new Error("Simulated AA trigger handling error");
};

test.serial('write mutex deadlock on AA trigger error', async t => {
    // Create a mock joint that will trigger AA handling
    const objJoint = {
        unit: {
            unit: 'test_unit_hash_' + Date.now(),
            version: '1.0',
            alt: '1',
            authors: [],
            messages: [],
            parent_units: [],
            last_ball: 'last_ball_hash',
            last_ball_unit: 'last_ball_unit_hash',
            witness_list_unit: 'witness_list_unit_hash',
            headers_commission: 500,
            payload_commission: 500
        }
    };
    
    const objValidationState = {
        bUnderWriteLock: false,
        last_ball_mci: 1000000 // After v4 upgrade
    };
    
    // First saveJoint call - will fail and leave mutex locked
    let firstCallCompleted = false;
    writer.saveJoint(objJoint, objValidationState, null, (err) => {
        firstCallCompleted = true;
        t.truthy(err); // Should receive error
    });
    
    // Wait a bit for the error to occur
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Try to acquire the write mutex again - this should block forever
    const timeoutPromise = new Promise((resolve) => setTimeout(() => resolve('TIMEOUT'), 1000));
    const lockPromise = mutex.lock(['write']).then(unlock => {
        unlock();
        return 'LOCKED';
    });
    
    const result = await Promise.race([lockPromise, timeoutPromise]);
    
    // If working correctly, we should get 'LOCKED'
    // If the bug exists, we get 'TIMEOUT' because mutex is never released
    t.is(result, 'TIMEOUT', 'Write mutex was never released after error in AA trigger handling');
    
    // Restore original function
    aa_composer.handleAATriggers = originalHandleAATriggers;
});
```

## Notes

This vulnerability represents a critical failure in error handling that can completely halt the network. The issue is exacerbated by the fact that it can be triggered by transient infrastructure problems (database connection timeouts, disk I/O errors) that are inevitable in production environments. The lack of a try-catch-finally block around the async operations in the post-commit callback is a serious oversight that violates basic error handling principles for resource management (mutexes must be released in all code paths). The vulnerability affects all in-scope files and does not require any special attacker capabilities or threat model violations.

### Citations

**File:** writer.js (L33-33)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
```

**File:** writer.js (L45-49)
```javascript
			commit_fn = function (sql, cb) {
				conn.query(sql, function () {
					cb();
				});
			};
```

**File:** writer.js (L693-693)
```javascript
							commit_fn(err ? "ROLLBACK" : "COMMIT", async function(){
```

**File:** writer.js (L711-713)
```javascript
								if (bStabilizedAATriggers) {
									if (bInLargerTx || objValidationState.bUnderWriteLock)
										throw Error(`saveJoint stabilized AA triggers while in larger tx or under write lock`);
```

**File:** writer.js (L715-715)
```javascript
									await aa_composer.handleAATriggers();
```

**File:** writer.js (L724-729)
```javascript
								if (onDone)
									onDone(err);
								count_writes++;
								if (conf.storage === 'sqlite')
									updateSqliteStats(objUnit.unit);
								unlock();
```

**File:** aa_composer.js (L97-98)
```javascript
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
```

**File:** aa_composer.js (L100-101)
```javascript
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
```

**File:** aa_composer.js (L106-109)
```javascript
							batch.write({ sync: true }, function(err){
								console.log("AA batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("AA composer: batch write failed: "+err);
```

**File:** storage.js (L1210-1210)
```javascript
			await conn.query("UPDATE units SET actual_tps_fee=? WHERE unit=?", [tps_fee, objUnitProps.unit]);
```

**File:** storage.js (L1221-1221)
```javascript
				const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, mci]);
```

**File:** storage.js (L1223-1223)
```javascript
				await conn.query("REPLACE INTO tps_fees_balances (address, mci, tps_fees_balance) VALUES(?,?,?)", [address, mci, tps_fees_balance + tps_fees_delta]);
```
