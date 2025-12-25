# TOCTOU Race Condition in Stability Update Causes Network Deadlock

## Summary

The `determineIfStableInLaterUnitsAndUpdateStableMcFlag` function reads unit properties without holding a write lock, then re-reads them after lock acquisition using a different database connection. If a concurrent main chain reorganization sets `main_chain_index=NULL` between these reads, the function throws an error without releasing the acquired write lock, causing permanent network-wide deadlock. [1](#0-0) 

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

The entire network halts as the global write lock remains held indefinitely. All subsequent unit processing operations block forever waiting for the lock. Network remains frozen until manual process restart, affecting all users with 100% capacity loss.

## Finding Description

**Location**: `byteball/ocore/main_chain.js:1151-1198`, function `determineIfStableInLaterUnitsAndUpdateStableMcFlag()`

**Intended Logic**: The function should atomically check unit stability and advance the stability point while holding appropriate locks. All error paths must release acquired locks and database connections.

**Actual Logic**: The function performs a non-atomic two-phase operation with a race condition vulnerability and missing error handling that causes resource leaks.

**Code Evidence**:

The initial stability check reads unit properties WITHOUT write lock: [2](#0-1) 

Write lock acquisition happens AFTER the initial read, creating a race window: [3](#0-2) 

A NEW database connection is taken after acquiring the lock (different from the first read): [4](#0-3) 

Second read and error throwing WITH write lock held, but NO try-catch protection: [5](#0-4) 

The unlock() that is NEVER reached when error is thrown: [6](#0-5) 

Main chain reorganization that sets `main_chain_index=NULL`: [7](#0-6) 

The `throwError` function throws an Error in Node.js environment: [8](#0-7) 

The global write lock used by all unit processing: [9](#0-8) 

**Exploitation Path**:

1. **Preconditions**: Network processing units normally with concurrent validations and main chain reorganizations

2. **Step 1 - Initial stability check**:
   - `validation.js` calls `determineIfStableInLaterUnitsAndUpdateStableMcFlag` for unit X
   - `main_chain.js:771` reads unit properties: `main_chain_index=100`, `is_free=0` (NO write lock)
   - Check passes, function returns `bStable=true` at line 1152
   - Async continuation queued for later execution

3. **Step 2 - Concurrent main chain reorganization**:
   - **RACE WINDOW**: Another thread acquires write lock, runs `updateMainChain`
   - `main_chain.js:140` executes: `UPDATE units SET main_chain_index=NULL WHERE main_chain_index>?`
   - Unit X's `main_chain_index` set to NULL
   - Write lock released

4. **Step 3 - Lock acquisition and re-read**:
   - Async continuation at line 1163 acquires write lock
   - Line 1166: Takes NEW database connection (different from first read)
   - Line 1167: Begins transaction
   - Line 1171: Reads properties again - now sees `main_chain_index=NULL`
   - Line 1172: Sets `new_last_stable_mci = null`

5. **Step 4 - Deadlock triggered**:
   - Line 1173: Check `null <= last_stable_mci` evaluates to `true` (JavaScript coerces `null` to `0`)
   - Line 1174: `throwError("new last stable mci expected to be higher than existing")` throws Error
   - Error propagates out of callback chain
   - **CRITICAL**: `unlock()` at line 1189 is NEVER called
   - Write lock held permanently, database connection leaked

6. **Step 5 - System-wide halt**:
   - All subsequent `writer.js:33` calls block forever waiting for write lock
   - No new units can be saved
   - Network permanently frozen until process restart

**Security Property Broken**:
- **Invariant: Transaction Atomicity** - Multi-step operations must ensure resource cleanup on all code paths
- **Invariant: Liveness** - System must not enter permanent deadlock states

**Root Cause Analysis**:

Three compounding flaws:
1. **Non-atomic operation**: Stability check (line 771) and stability marking (lines 1163-1189) separated by race window
2. **Missing error handling**: No try-catch block protects the write lock section
3. **Different database contexts**: Line 771 uses passed connection, line 1166 takes NEW connection - transaction isolation provides no protection

The comment at line 1173 is incorrect: "our SQL transaction doesn't see the changes" - but the two reads use entirely different database connections/transactions.

## Impact Explanation

**Affected Assets**: Entire network - all bytes, all custom assets, all transactions

**Damage Severity**:
- **Quantitative**: 100% network capacity lost, all transactions frozen indefinitely
- **Qualitative**: Complete loss of transaction processing capability

**User Impact**:
- **Who**: All network users
- **Conditions**: Occurs spontaneously during normal operation when validation and main chain reorganization overlap
- **Recovery**: Requires manual process restart; no data loss but operational disruption

**Systemic Risk**:
- Single point of failure affecting entire network
- Write lock is global - blocks ALL unit processing
- Database connection permanently leaked from pool
- Can recur repeatedly if not fixed

## Likelihood Explanation

**Attacker Profile**: None required - spontaneous race condition during normal operation

**Preconditions**:
- **Network State**: Active transaction processing (normal operation)
- **Timing**: Race window between line 771 and line 1163 is significant (potentially hundreds of milliseconds)

**Execution Complexity**: None - occurs naturally when one thread validates a unit while another triggers main chain reorganization

**Frequency**: High likelihood in production with moderate transaction volume. While individual probability per operation may be low, cumulative probability over thousands of daily operations makes this critical. Main chain reorganizations are normal DAG behavior.

**Overall Assessment**: High likelihood spontaneous failure requiring immediate fix.

## Recommendation

**Immediate Mitigation**:

Add try-catch-finally block to ensure resource cleanup on all error paths: [10](#0-9) 

**Permanent Fix**:

1. Hold write lock during BOTH reads to prevent race condition
2. Add error handling to ensure unlock() is always called
3. Add NULL check before comparison to prevent JavaScript coercion issue

**Additional Measures**:
- Add integration test verifying concurrent stability updates and MC reorganizations don't cause deadlock
- Add monitoring for long-held write locks (>30 seconds)
- Review all mutex.lock() usage for similar missing error handling

**Validation**:
- [ ] Fix prevents deadlock on concurrent MC reorganization
- [ ] Resources (lock, connection) released on all code paths
- [ ] No new race conditions introduced
- [ ] Backward compatible with existing units

## Notes

This vulnerability is particularly insidious because:
1. It only manifests under specific timing conditions (race window)
2. The incorrect comment at line 1173 suggests the developers believed transaction isolation would protect against this scenario
3. Once triggered, there's no automatic recovery - requires manual intervention
4. The use of different database connections (original at line 771, new at line 1166) means transaction isolation doesn't help

The vulnerability is confirmed by examining the mutex implementation which has no error handling around the callback execution, and the throwError function which does throw an actual Error in Node.js environments (not just logging).

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

**File:** main_chain.js (L1151-1198)
```javascript
function determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, earlier_unit, arrLaterUnits, bStableInDb, handleResult){
	determineIfStableInLaterUnits(conn, earlier_unit, arrLaterUnits, function(bStable){
		console.log("determineIfStableInLaterUnits", earlier_unit, arrLaterUnits, bStable);
		if (!bStable)
			return handleResult(bStable);
		if (bStable && bStableInDb)
			return handleResult(bStable);
		breadcrumbs.add('stable in parents, will wait for write lock');
		handleResult(bStable, true);

		// result callback already called, we leave here to move the stability point forward.
		// To avoid deadlocks, we always first obtain a "write" lock, then a db connection
		mutex.lock(["write"], async function(unlock){
			breadcrumbs.add('stable in parents, got write lock');
			// take a new connection
			let conn = await db.takeConnectionFromPool();
			await conn.query("BEGIN");
			storage.readLastStableMcIndex(conn, function(last_stable_mci){
				if (last_stable_mci >= constants.v4UpgradeMci && !(constants.bTestnet && last_stable_mci === 3547801))
					throwError(`${earlier_unit} not stable in db but stable in later units ${arrLaterUnits.join(', ')} in v4`);
				storage.readUnitProps(conn, earlier_unit, function(objEarlierUnitProps){
					var new_last_stable_mci = objEarlierUnitProps.main_chain_index;
					if (new_last_stable_mci <= last_stable_mci) // fix: it could've been changed by parallel tasks - No, our SQL transaction doesn't see the changes
						return throwError("new last stable mci expected to be higher than existing");
					var mci = last_stable_mci;
					var batch = kvstore.batch();
					advanceLastStableMcUnitAndStepForward();

					function advanceLastStableMcUnitAndStepForward(){
						mci++;
						if (mci <= new_last_stable_mci)
							markMcIndexStable(conn, batch, mci, advanceLastStableMcUnitAndStepForward);
						else{
							batch.write({ sync: true }, async function(err){
								if (err)
									throw Error("determineIfStableInLaterUnitsAndUpdateStableMcFlag: batch write failed: "+err);
								await conn.query("COMMIT");
								conn.release();
								unlock();
							//	handleResult(bStable, true);
							});
						}
					}            
				});
			});
		});
	});
}
```

**File:** main_chain.js (L1853-1859)
```javascript
function throwError(msg){
	debugger;
	if (typeof window === 'undefined')
		throw Error(msg);
	else
		eventBus.emit('nonfatal_error', msg, new Error());
}
```

**File:** writer.js (L33-33)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
```
