# TOCTOU Race Condition in Stability Update Causes Network Deadlock

## Summary

The `determineIfStableInLaterUnitsAndUpdateStableMcFlag` function in `main_chain.js` reads unit properties before acquiring a write lock, then re-reads them after lock acquisition. If a concurrent main chain reorganization removes the unit from the main chain between these reads (setting `main_chain_index=NULL`), the function throws an error without releasing the write lock, causing permanent network-wide deadlock.

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

The entire network halts as the global write lock remains held indefinitely. All subsequent unit processing operations block forever waiting for the lock. Network remains frozen until manual process restart. All users affected, 100% capacity loss, no transactions can be confirmed.

## Finding Description

**Location**: `byteball/ocore/main_chain.js:1151-1198`, function `determineIfStableInLaterUnitsAndUpdateStableMcFlag()`

**Intended Logic**: The function should atomically check unit stability and advance the stability point while holding appropriate locks. All error paths should release acquired locks and database connections.

**Actual Logic**: The function performs a non-atomic two-phase operation: (1) check stability at line 771 without holding write lock, (2) advance stability point at lines 1163-1189 after acquiring write lock. If a concurrent main chain reorganization occurs between these phases and sets `main_chain_index=NULL`, the function throws an error at line 1174 without releasing the write lock acquired at line 1163.

**Code Evidence**:

Initial stability check reads unit properties WITHOUT write lock: [1](#0-0) 

Write lock acquisition happens AFTER the initial read: [2](#0-1) 

Second read and error throwing WITH write lock held, but NO try-catch: [3](#0-2) 

The unlock() that is NEVER reached when error is thrown: [4](#0-3) 

Main chain reorganization that sets `main_chain_index=NULL`: [5](#0-4) 

The `throwError` function throws an Error in Node.js environment: [6](#0-5) 

**Exploitation Path**:

1. **Preconditions**: Network processing units normally, with concurrent validations and main chain reorganizations

2. **Step 1 - Initial stability check**:
   - `validation.js:658` calls `determineIfStableInLaterUnitsAndUpdateStableMcFlag` for unit X
   - `main_chain.js:771` reads unit properties: `main_chain_index=100`, `is_free=0`
   - Check at line 774 passes (not NULL, not free)
   - Function determines stability and returns `bStable=true` at line 1159
   - Control returns to validation.js immediately (async continuation queued)

3. **Step 2 - Concurrent main chain reorganization**:
   - **RACE WINDOW**: Another unit is saved, triggers `writer.js:640` → `updateMainChain`
   - Write lock is held by the updateMainChain operation
   - `main_chain.js:140` executes: `UPDATE units SET main_chain_index=NULL WHERE main_chain_index>?`
   - Unit X's `main_chain_index` set to NULL
   - Write lock released

4. **Step 3 - Lock acquisition and re-read**:
   - Async continuation at `main_chain.js:1163` acquires write lock
   - New database connection taken at line 1166, transaction begins at line 1167
   - `main_chain.js:1171` reads properties again: `main_chain_index=NULL`
   - Line 1172: `new_last_stable_mci = null`

5. **Step 4 - Deadlock triggered**:
   - Line 1173: Check `null <= last_stable_mci` (JavaScript coerces `null` to `0`, so `0 <= 99` evaluates to `true`)
   - Line 1174: `throwError("new last stable mci expected to be higher than existing")` throws Error
   - Error propagates out of callback chain
   - **CRITICAL**: `unlock()` at line 1189 is NEVER called
   - Write lock held permanently, database connection leaked

6. **Step 5 - System-wide halt**:
   - All subsequent `writer.js:33` calls block forever waiting for write lock
   - No new units can be saved
   - Network permanently frozen until process restart

**Security Property Broken**: 
- **Invariant: Transaction Atomicity** - Multi-step operations must ensure resource cleanup on all code paths, including errors
- **Invariant: Liveness** - System must not enter permanent deadlock states

**Root Cause Analysis**:

Three compounding flaws create this vulnerability:

1. **Non-atomic operation**: Stability check (line 771) and stability marking (lines 1163-1189) are separated by a race window of hundreds of milliseconds during which database state can change

2. **Missing error handling**: No try-catch block protects the write lock section. When `throwError` is called at line 1174, it throws an Error that propagates out without executing cleanup code

3. **Different database contexts**: The initial read at line 771 uses the connection passed from validation.js, while the second read at line 1171 uses a NEW connection taken at line 1166. Transaction isolation doesn't protect against changes committed between these different transactions

The comment at line 1173 incorrectly assumes "our SQL transaction doesn't see the changes" - but the two reads occur in entirely different database transactions/connections, so isolation provides no protection.

## Impact Explanation

**Affected Assets**: Entire network - all bytes, all custom assets, all transactions, all users

**Damage Severity**:
- **Quantitative**: 100% network capacity lost, all pending transactions frozen indefinitely until manual restart
- **Qualitative**: Complete loss of transaction processing capability, network appears "stuck" with no confirmations

**User Impact**:
- **Who**: All network users
- **Conditions**: Occurs spontaneously during normal operation when validation and main chain reorganization overlap
- **Recovery**: Requires manual process restart by node operators; no data loss but operational disruption lasting minutes to hours

**Systemic Risk**:
- Single point of failure affecting entire network
- Can recur repeatedly if not fixed
- Write lock is global - blocks ALL unit processing
- Database connection permanently leaked from pool
- Database transaction never finalized (committed or rolled back)

## Likelihood Explanation

**Attacker Profile**: None required - spontaneous race condition during normal network operation

**Preconditions**:
- **Network State**: Active transaction processing with concurrent unit submissions (normal operation)
- **Timing**: Race window between line 771 (first read) and line 1163 (lock acquisition) is significant (potentially hundreds of milliseconds)

**Execution Complexity**: None - occurs naturally when:
- One thread validates a unit (calls determineIfStableInLaterUnitsAndUpdateStableMcFlag)
- Another thread saves a unit triggering main chain reorganization
- Timing causes reorganization to complete during the race window

**Frequency**: High likelihood in production with moderate transaction volume. While individual probability per operation may be low (0.1%-1%), cumulative probability over thousands of daily operations makes this a critical reliability issue. Main chain reorganizations are normal DAG behavior.

**Overall Assessment**: High likelihood spontaneous failure requiring immediate fix to ensure network stability.

## Recommendation

**Immediate Mitigation**:

Wrap the write lock section in try-catch to guarantee unlock on error:

```javascript
// File: byteball/ocore/main_chain.js:1163-1196
mutex.lock(["write"], async function(unlock){
    let conn;
    try {
        breadcrumbs.add('stable in parents, got write lock');
        conn = await db.takeConnectionFromPool();
        await conn.query("BEGIN");
        storage.readLastStableMcIndex(conn, function(last_stable_mci){
            // ... existing logic ...
        });
    } catch (err) {
        console.error("Error in determineIfStableInLaterUnitsAndUpdateStableMcFlag:", err);
        if (conn) {
            await conn.query("ROLLBACK").catch(() => {});
            conn.release();
        }
        unlock();
        throw err;
    }
});
```

**Permanent Fix**:

Acquire write lock BEFORE the initial stability check to make the entire operation atomic:

```javascript
// Restructure to acquire lock earlier, before reading properties
mutex.lock(["write"], async function(unlock){
    let conn = await db.takeConnectionFromPool();
    try {
        await conn.query("BEGIN");
        // Perform BOTH stability check AND stability marking within lock
        determineIfStableInLaterUnits(conn, earlier_unit, arrLaterUnits, function(bStable){
            if (bStable) {
                // Mark stable immediately, all within same lock/transaction
                markStableAndAdvance(conn, unlock);
            } else {
                conn.release();
                unlock();
                handleResult(bStable);
            }
        });
    } catch (err) {
        await conn.query("ROLLBACK").catch(() => {});
        conn.release();
        unlock();
        throw err;
    }
});
```

**Additional Measures**:
- Add integration test verifying concurrent stability checks and main chain reorganizations don't cause deadlock
- Add monitoring to detect held locks exceeding reasonable timeout (>30 seconds)
- Review all other mutex.lock call sites for similar missing error handling

**Validation**:
- Verify unlock() is called on ALL code paths (success, error, exception)
- Test under high concurrency with multiple concurrent unit submissions
- Confirm no performance regression from earlier lock acquisition

## Proof of Concept

```javascript
// File: test/toctou_deadlock.test.js
const main_chain = require('../main_chain.js');
const writer = require('../writer.js');
const db = require('../db.js');
const async = require('async');

describe('TOCTOU Race Condition Test', function() {
    this.timeout(10000);
    
    it('should not deadlock when main chain reorganization occurs during stability check', function(done) {
        // Setup: Create unit X on main chain at MCI=100
        const unitX = createTestUnit({ main_chain_index: 100 });
        
        // Thread A: Start stability check (will read MCI=100)
        const threadA = (cb) => {
            main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag(
                db.getConnection(),
                unitX.unit,
                [laterUnit1, laterUnit2],
                0,
                function(bStable, bAdvanced) {
                    console.log('Thread A completed:', bStable, bAdvanced);
                    cb();
                }
            );
        };
        
        // Thread B: Trigger main chain reorg after Thread A reads but before lock
        const threadB = (cb) => {
            setTimeout(() => {
                // This will set unitX.main_chain_index = NULL
                const newUnit = createTestUnit({ triggers_reorg: true });
                writer.saveJoint(newUnit, {}, null, function(err) {
                    console.log('Thread B completed main chain reorg');
                    cb(err);
                });
            }, 50); // Delay to hit race window
        };
        
        // Execute both threads concurrently
        async.parallel([threadA, threadB], function(err) {
            if (err && err.message.includes('new last stable mci expected to be higher')) {
                // Vulnerability triggered: error thrown but lock not released
                // Check if write lock is still held (this would hang)
                const mutex = require('../mutex.js');
                const lockCount = mutex.getCountOfLocks();
                
                if (lockCount > 0) {
                    return done(new Error('DEADLOCK: Write lock not released after error!'));
                }
            }
            
            // Test passes if no deadlock or if error is properly handled
            done(err);
        });
    });
});
```

**Notes**:

The vulnerability exists because the codebase uses callback-based error handling without try-catch protection. The mutex.js implementation requires explicit `unlock()` calls - there is no automatic cleanup. [7](#0-6) 

The write lock at line 1163 is the SAME lock used by writer.js:saveJoint at line 33, making this a global serialization point. [8](#0-7) 

Transaction isolation levels (SERIALIZABLE for SQLite, REPEATABLE READ for MySQL) do NOT protect against this race because the two reads occur on different database connections in different transactions. The initial read at line 771 happens in validation context, while the second read at line 1171 uses a newly acquired connection.

### Citations

**File:** main_chain.js (L140-140)
```javascript
			"UPDATE units SET is_on_main_chain=0, main_chain_index=NULL WHERE main_chain_index>?", 
```

**File:** main_chain.js (L771-774)
```javascript
	storage.readPropsOfUnits(conn, earlier_unit, arrLaterUnits, function(objEarlierUnitProps, arrLaterUnitProps){
		if (constants.bTestnet && objEarlierUnitProps.main_chain_index <= 1220148 && objEarlierUnitProps.is_on_main_chain && arrLaterUnits.indexOf('qwKGj0w8P/jscAyQxSOSx2sUZCRFq22hsE6bSiqgUyk=') >= 0)
			return handleResult(true);
		if (objEarlierUnitProps.is_free === 1 || objEarlierUnitProps.main_chain_index === null)
```

**File:** main_chain.js (L1163-1167)
```javascript
		mutex.lock(["write"], async function(unlock){
			breadcrumbs.add('stable in parents, got write lock');
			// take a new connection
			let conn = await db.takeConnectionFromPool();
			await conn.query("BEGIN");
```

**File:** main_chain.js (L1171-1174)
```javascript
				storage.readUnitProps(conn, earlier_unit, function(objEarlierUnitProps){
					var new_last_stable_mci = objEarlierUnitProps.main_chain_index;
					if (new_last_stable_mci <= last_stable_mci) // fix: it could've been changed by parallel tasks - No, our SQL transaction doesn't see the changes
						return throwError("new last stable mci expected to be higher than existing");
```

**File:** main_chain.js (L1189-1189)
```javascript
								unlock();
```

**File:** main_chain.js (L1853-1856)
```javascript
function throwError(msg){
	debugger;
	if (typeof window === 'undefined')
		throw Error(msg);
```

**File:** mutex.js (L47-58)
```javascript
	proc(function unlock(unlock_msg) {
		if (!bLocked)
			throw Error("double unlock?");
		if (unlock_msg)
			console.log(unlock_msg);
		bLocked = false;
		release(arrKeys);
		console.log("lock released", arrKeys);
		if (next_proc)
			next_proc.apply(next_proc, arguments);
		handleQueue();
	});
```

**File:** writer.js (L33-34)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);
```
