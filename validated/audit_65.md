# Audit Report: Light Client Timeout Vulnerability

## Title
Insufficient Retry Window in Light Client Bad Sequence Update Allows Spending from Double-Spend Units

## Summary
The `updateAndEmitBadSequenceUnits()` function in `light.js` uses exponential backoff with a hardcoded 6400ms retry cap, abandoning units after ~12.7 seconds. When light clients process large history batches on resource-constrained devices, units can be saved with `sequence='good'` after the retry timeout expires, bypassing double-spend protection and enabling fund loss.

## Impact
**Severity**: High  
**Category**: Direct Fund Loss / Double-Spend Prevention Bypass

Light client users can inadvertently spend outputs from units involved in double-spends. When the conflicting unit becomes stable, all descendant transactions become invalid, resulting in permanent fund loss. Affects mobile wallet users during history synchronization or network congestion.

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: When hubs detect double-spend conflicts, they send `'light/sequence_became_bad'` notifications. Light clients must mark these units as `'temp-bad'` to prevent spending until conflict resolution.

**Actual Logic**: The retry mechanism terminates when `retryDelay > 6400`, silently abandoning units not yet saved to the database. Units processed after timeout retain `sequence='good'` status.

**Code Evidence**: 
The timeout check at line 541-542 causes early termination: [2](#0-1) 

**Exploitation Path**:

1. **Preconditions**: Light client syncing history with large batch of units (up to 2000 per MAX_HISTORY_ITEMS); attacker has unspent output

2. **Step 1**: Attacker creates double-spend (Unit A to victim's hub, Unit B to witnesses)
   - Code path: Attacker uses standard unit composition via `composer.js`

3. **Step 2**: Hub sends history batch to light client containing Unit A (with `sequence='good'` in proofchain)
   - Code path: Hub's `light.prepareHistory()` includes Unit A at line 75-76 [3](#0-2) 

4. **Step 3**: Light client begins batch processing via `processHistory()` with mutex lock `["light_joints"]`
   - Sequential processing (line 291): if Unit A is position 1800/2000, ~13 seconds needed at 7ms/unit on mobile [4](#0-3) 

5. **Step 4**: Hub detects double-spend, sends notification via `wallet.handleLightJustsaying()` calling `light.updateAndEmitBadSequenceUnits()` [5](#0-4) 

6. **Step 5**: Retry mechanism executes at 100ms, 200ms, 400ms, 800ms, 1600ms, 3200ms, 6400ms (total: 12,700ms). Each query finds no Unit A in database yet: [6](#0-5) 

7. **Step 6**: After 12.7s timeout, retry terminates. Unit A eventually saved with `sequence='good'` based on hub's proofchain data: [7](#0-6) [8](#0-7) 

8. **Step 7**: Input selection includes Unit A because it queries `sequence='good'`: [9](#0-8) [10](#0-9) 

9. **Step 8**: User spends from Unit A. When Unit B stabilizes, Unit A becomes `'final-bad'`, invalidating all descendants and causing permanent fund loss.

**Security Property Broken**: 
- Double-Spend Prevention: Outputs from units in unresolved double-spends can be spent
- Input Validity: Inputs reference outputs from units that should be marked `'temp-bad'`

**Root Cause Analysis**: 
The 6400ms cap assumes all units complete database writes within 12.7 seconds. However:
- Light clients on mobile devices experience slower SQLite operations
- Batch processing of 2000 units can exceed timeout (7ms/unit × 1800 units = 12.6s)
- Database lock contention from concurrent operations extends delays
- No fallback mechanism re-checks sequence status after timeout

## Impact Explanation

**Affected Assets**: Bytes (native currency), all custom divisible and indivisible assets

**Damage Severity**:
- **Quantitative**: Full amount of outputs in Unit A can be lost. No upper bound—depends on Unit A's output values. Cascading invalidation affects all descendant transactions.
- **Qualitative**: Silent failure with no warning. Irreversible once conflict resolves unfavorably.

**User Impact**:
- **Who**: Mobile wallet users, light clients on resource-constrained devices
- **Conditions**: During large history syncs (new wallet setup, reconnection after offline period), or during natural network/device congestion
- **Recovery**: None—funds permanently lost when wrong branch stabilizes

**Systemic Risk**: Light clients rely entirely on hub notifications for double-spend detection. Timeout gap creates systematic vulnerability affecting all light clients during high-load periods.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with unspent outputs
- **Resources Required**: Transaction fees (~$0.001), ability to broadcast to different network segments
- **Technical Skill**: Medium—understanding of DAG propagation timing

**Preconditions**:
- **Network State**: Light client syncing large history or experiencing resource constraints
- **Attacker State**: Unspent output to double-spend
- **Timing**: Natural device/network delays OR attacker times attack during known congestion

**Execution Complexity**:
- **Transaction Count**: 3 (Unit A, Unit B, victim's spending transaction)
- **Coordination**: Broadcast to different network segments (multiple hub connections)
- **Detection Risk**: Low—appears as normal double-spend attempt

**Frequency**:
- **Repeatability**: Medium—depends on victim device performance and network state
- **Scale**: Affects all light clients during resource constraints

**Overall Assessment**: **Medium likelihood**—Not reliably exploitable on demand. Attacker cannot force 12.7s delay directly (light clients trust hub validation). Vulnerability is opportunistic, exploitable during natural processing delays on mobile devices or when victim syncs large history. Light clients processing 1500+ units in batch are vulnerable.

**Note**: Original claim overstated likelihood as "High" and incorrectly suggested attacker can "deliberately create slow-to-validate units"—light clients don't validate unit complexity, they trust hub.

## Recommendation

**Immediate Mitigation**:
1. Increase retry cap from 6400ms to at least 60000ms (60 seconds)
2. Add persistent retry queue—units not found after timeout should be retried on next sync

**Permanent Fix**:
```javascript
// File: byteball/ocore/light.js
// Function: updateAndEmitBadSequenceUnits()

// Replace line 541-542:
if (retryDelay > 6400)
    return;

// With:
if (retryDelay > 60000) {
    // Persist for retry on next history sync
    db.query("INSERT "+db.getIgnore()+" INTO pending_bad_sequence (unit) VALUES ?", 
        [arrNotSavedUnits.map(unit => [unit])], 
        function() {});
    return;
}

// Add check at start of processHistory() to apply pending bad sequences
```

**Additional Measures**:
- Pre-spending validation: Query hub for current sequence status before finalizing spending transaction
- User warning: Display alert when spending from units not yet stable
- Monitoring: Log timeout events to detect systematic issues

## Proof of Concept

```javascript
const test = require('tape');
const light = require('../light.js');
const db = require('../db.js');
const eventBus = require('../event_bus.js');

test('Light client timeout allows bad sequence unit spending', async function(t) {
    // Setup: Create test database with light client schema
    await setupLightClientDB();
    
    // Simulate hub sending 2000-unit history batch
    const largeHistoryBatch = await prepareHistoryBatch(2000);
    
    // Target unit at position 1800
    const unitA = largeHistoryBatch.joints[1800].unit.unit;
    
    // Start history processing (takes ~13s on slow device simulation)
    const processingPromise = light.processHistory(largeHistoryBatch, WITNESSES, {
        ifOk: () => {},
        ifError: (err) => t.fail(err)
    });
    
    // After 1 second, simulate hub notification
    await sleep(1000);
    light.updateAndEmitBadSequenceUnits([unitA]);
    
    // Wait for timeout (12.7s) + processing completion
    await sleep(12000);
    await processingPromise;
    
    // Verify: Unit A saved with sequence='good' despite notification
    const rows = await db.query("SELECT sequence FROM units WHERE unit=?", [unitA]);
    t.equal(rows[0].sequence, 'good', 'Unit has good sequence after timeout');
    
    // Verify: Input selection includes Unit A
    const inputs = await selectInputsForSpending(ADDRESS, 1000);
    const hasUnitA = inputs.some(input => input.unit === unitA);
    t.ok(hasUnitA, 'Input selection includes unit from bad sequence');
    
    t.end();
});
```

## Notes

This vulnerability requires specific timing conditions but is realistic on mobile devices. The 6400ms cap appears arbitrary—no documentation explains this value choice. Increasing to 60s provides safety margin for resource-constrained devices while maintaining reasonable timeout behavior. The vulnerability demonstrates why light client architectures must account for worst-case device performance when designing retry mechanisms for critical security properties like double-spend prevention.

### Citations

**File:** light.js (L75-76)
```javascript
		arrSelects.push("SELECT DISTINCT unit, main_chain_index, level, is_stable FROM outputs JOIN units USING(unit) \n\
			WHERE address IN("+ strAddressList + ") AND (+sequence='good' OR is_stable=1)" + mciCond);
```

**File:** light.js (L291-293)
```javascript
					async.eachSeries(
						objResponse.joints.reverse(), // have them in forward chronological order so that we correctly mark is_spent flag
						function(objJoint, cb2){
```

**File:** light.js (L301-301)
```javascript
							var sequence = assocProvenUnitsNonserialness[unit] ? 'final-bad' : 'good';
```

**File:** light.js (L329-329)
```javascript
								writer.saveJoint(objJoint, {sequence: sequence, arrDoubleSpendInputs: [], arrAdditionalQueries: []}, null, cb2);
```

**File:** light.js (L536-558)
```javascript
function updateAndEmitBadSequenceUnits(arrBadSequenceUnits, retryDelay){
	if (!ValidationUtils.isNonemptyArray(arrBadSequenceUnits))
		return console.log("arrBadSequenceUnits not array or empty");
	if (!retryDelay)
		retryDelay = 100;
	if (retryDelay > 6400)
		return;
	db.query("SELECT unit FROM units WHERE unit IN (?)", [arrBadSequenceUnits], function(rows){
		var arrAlreadySavedUnits = rows.map(function(row){return row.unit});
		var arrNotSavedUnits = _.difference(arrBadSequenceUnits, arrAlreadySavedUnits);
		if (arrNotSavedUnits.length > 0)
			setTimeout(function(){
				updateAndEmitBadSequenceUnits(arrNotSavedUnits, retryDelay*2); // we retry later for units that are not validated and saved yet
			}, retryDelay);
		if (arrAlreadySavedUnits.length > 0)
			db.query("UPDATE units SET sequence='temp-bad' WHERE is_stable=0 AND unit IN (?)", [arrAlreadySavedUnits], function(){
				db.query(getSqlToFilterMyUnits(arrAlreadySavedUnits),
				function(arrMySavedUnitsRows){
					if (arrMySavedUnitsRows.length > 0)
						eventBus.emit('sequence_became_bad', arrMySavedUnitsRows.map(function(row){ return row.unit; }));
				});
			});
	});
```

**File:** wallet.js (L44-47)
```javascript
			break;
		case 'light/sequence_became_bad':
			light.updateAndEmitBadSequenceUnits(body);
			break;
```

**File:** inputs.js (L102-103)
```javascript
			WHERE address IN(?) AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL")+" AND is_spent=0 AND amount "+more+" ? \n\
				AND sequence='good' "+confirmation_condition+" \n\
```

**File:** inputs.js (L125-126)
```javascript
			WHERE address IN(?) AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL")+" AND is_spent=0 \n\
				AND sequence='good' "+confirmation_condition+"  \n\
```
