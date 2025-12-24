# MCI Gap During Stability Advancement Causes Fatal Network Halt

## Summary

The `purgeUncoveredNonserialJoints` function can delete units that have assigned `main_chain_index` values but are not yet stable, creating gaps in the MCI sequence. When `determineIfStableInLaterUnitsAndUpdateStableMcFlag` attempts to mark these MCIs as stable, the `addBalls` function throws an unconditional error for empty MCIs, leaving the write lock permanently held and halting all stability advancement network-wide.

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

All network nodes lose the ability to advance transaction finality. Once triggered at a specific MCI, all nodes deterministically encounter the identical error, creating a synchronized network halt requiring manual intervention (hard fork or database repair) to recover.

## Finding Description

**Location**: Multiple files in byteball/ocore

**Root Cause**: The purge query lacks a filter for units with assigned `main_chain_index` values. [1](#0-0) 

This query can select and delete units that have `main_chain_index` assigned if they are temp-bad/final-bad, have no ball, and no content_hash. No check prevents purging units that are part of the MCI sequence.

**Unconditional Error on Missing Units**: When stability advancement reaches an MCI with no units: [2](#0-1) 

This throws an error without any fallback logic or gap-handling mechanism.

**Write Lock Never Released**: The stability advancement acquires a write lock but has no error handling: [3](#0-2) 

When the error is thrown from `addBalls`, execution never reaches line 1189 where `unlock()` is called, permanently holding the write lock.

**Sequential MCI Processing Without Gap Checks**: [4](#0-3) 

The code increments through MCIs sequentially without verifying that units exist at each MCI before calling `markMcIndexStable`.

**Complete Unit Deletion**: [5](#0-4) 

When a unit is purged, it is completely removed from the database, creating the gap.

## Exploitation Path

1. **Preconditions**: 
   - Unit U at MCI 500 with `sequence='temp-bad'` or `'final-bad'`
   - Unit U has `main_chain_index=500` assigned but `is_stable=0`
   - Unit U has `content_hash IS NULL` and no ball assigned
   - `last_stable_mci = 100`

2. **Purge Triggers**: 
   - `purgeUncoveredNonserialJoints` runs periodically
   - Query selects Unit U (meets all criteria, no main_chain_index filter)
   - Unit U is deleted from database
   - MCI 500 now has zero units

3. **Stability Advancement**:
   - New unit arrives, triggering stability advancement
   - Write lock acquired at line 1163
   - Loop begins incrementing MCI from 101 toward new stable point
   - At MCI 500, `markMcIndexStable` is called
   - `addBalls` queries for units at MCI 500
   - Zero rows returned
   - Error thrown at line 1391

4. **Network Halt**:
   - Error propagates, lines 1187-1189 never executed
   - Write lock remains held indefinitely
   - All subsequent stability attempts block or fail at same MCI
   - Network cannot advance stability past MCI 100
   - All nodes encounter identical failure deterministically

## Impact Explanation

**Affected Assets**: All network participants' ability to achieve transaction finality

**Damage Severity**:
- **Quantitative**: 100% of nodes unable to advance stability point beyond the gap MCI. No new transactions can become stable.
- **Qualitative**: Complete loss of consensus liveness. The network continues accepting new units but cannot confirm them as final. Exchanges must halt withdrawals, AAs cannot execute final responses, the network effectively freezes.

**User Impact**:
- **Who**: All users, exchanges, and applications requiring transaction finality
- **Conditions**: Triggered when bad units are purged between MCI assignment and stabilization
- **Recovery**: Requires hard fork or manual database repair to fill gaps or implement gap-skipping logic

**Systemic Risk**: Deterministic failure across all honest nodes. No automatic recovery mechanism exists.

## Likelihood Explanation

**Attacker Profile**: No attacker required - occurs through normal protocol operation

**Preconditions**:
- Bad units (double-spends) exist on the network (common)
- Bad units assigned MCIs but not yet stable (time window exists)
- All units at that MCI are bad and meet purge criteria (rare but possible)
- Stability point lags behind MCI assignment (normal during catchup)

**Execution Complexity**: Fully automatic - no coordination needed

**Frequency**: Low-to-medium probability (requires specific timing and all units at an MCI to be purgeable), but once triggered, impact is permanent and network-wide.

**Overall Assessment**: While the specific conditions are rare, the architectural flaw is real. The purge logic lacks the necessary safeguard against removing units from the MCI sequence, creating a latent failure mode in normal protocol operation.

## Recommendation

**Immediate Mitigation**:
Add `main_chain_index IS NULL` check to the purge query:

```javascript
// File: byteball/ocore/joint_storage.js
// Line 226-230
db.query(
    "SELECT unit FROM units "+byIndex+" \n\
    WHERE "+cond+" AND sequence IN('final-bad','temp-bad') AND content_hash IS NULL \n\
        AND main_chain_index IS NULL \n\  // ADD THIS CHECK
        AND NOT EXISTS (SELECT * FROM dependencies WHERE depends_on_unit=units.unit) \n\
        AND NOT EXISTS (SELECT * FROM balls WHERE balls.unit=units.unit) \n\
        ...",
```

**Permanent Fix**:
Additionally add error handling in stability advancement to skip gaps or retry:

```javascript
// File: byteball/ocore/main_chain.js
// Around line 1386-1391
function addBalls(){
    conn.query(
        "SELECT units.*, ball FROM units LEFT JOIN balls USING(unit) \n\
        WHERE main_chain_index=? ORDER BY level, unit", [mci], 
        function(unit_rows){
            if (unit_rows.length === 0) {
                console.error("WARNING: no units on mci "+mci+", skipping");
                return onDone(); // Skip this MCI instead of throwing
            }
            // ... rest of processing
        }
    );
}
```

**Additional Measures**:
- Add integration test verifying purge doesn't remove units with assigned MCIs
- Add monitoring for MCI gaps before stability advancement
- Database migration: Check for existing gaps and repair

## Proof of Concept

```javascript
// File: test/test_mci_gap_network_halt.js
const test = require('ava');
const db = require('../db.js');
const storage = require('../storage.js');
const main_chain = require('../main_chain.js');
const joint_storage = require('../joint_storage.js');

test.serial('MCI gap causes network halt', async t => {
    // Setup: Create bad unit with MCI assigned
    await db.query("INSERT INTO units (unit, sequence, main_chain_index, is_stable, content_hash) \
                    VALUES ('bad_unit_hash', 'temp-bad', 500, 0, NULL)");
    
    // Verify unit exists at MCI 500
    const [before] = await db.query("SELECT COUNT(*) as cnt FROM units WHERE main_chain_index=500");
    t.is(before.cnt, 1, "Unit should exist at MCI 500");
    
    // Trigger purge (should NOT delete units with main_chain_index)
    await new Promise(resolve => joint_storage.purgeUncoveredNonserialJoints(false, resolve));
    
    // Check if unit was incorrectly deleted
    const [after] = await db.query("SELECT COUNT(*) as cnt FROM units WHERE main_chain_index=500");
    
    if (after.cnt === 0) {
        // Vulnerability: unit with MCI was purged, creating gap
        t.fail("VULNERABILITY: Unit with main_chain_index was purged, creating MCI gap");
        
        // Attempting stability advancement should now throw error and lock
        try {
            await new Promise((resolve, reject) => {
                main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag(
                    null, 'test_unit', ['later_unit'], false, 
                    (bStable) => {
                        // This should never be reached due to error at MCI 500
                        resolve();
                    }
                );
            });
            t.fail("Should have thrown error at MCI gap");
        } catch (err) {
            t.regex(err.message, /no units on mci/, "Expected error thrown for empty MCI");
            // Write lock is now permanently held - network halted
        }
    } else {
        t.pass("Units with main_chain_index are protected from purge (vulnerability fixed)");
    }
});
```

## Notes

The vulnerability is real but nuanced. For a complete MCI gap to occur, ALL units at that MCI must be bad and meet purge criteria (no ball, no content_hash, no dependencies, old enough). While this is rarer than implied, the core issue remains: the purge query lacks the necessary protection for units that are part of the MCI sequence, and the stability advancement has no gap-handling logic. The missing `main_chain_index IS NULL` check in the purge query is a clear oversight that can lead to catastrophic network failure under specific but realistic conditions.

### Citations

**File:** joint_storage.js (L226-237)
```javascript
	db.query( // purge the bad ball if we've already received at least 7 witnesses after receiving the bad ball
		"SELECT unit FROM units "+byIndex+" \n\
		WHERE "+cond+" AND sequence IN('final-bad','temp-bad') AND content_hash IS NULL \n\
			AND NOT EXISTS (SELECT * FROM dependencies WHERE depends_on_unit=units.unit) \n\
			AND NOT EXISTS (SELECT * FROM balls WHERE balls.unit=units.unit) \n\
			AND (units.creation_date < "+db.addTime('-10 SECOND')+" OR EXISTS ( \n\
				SELECT DISTINCT address FROM units AS wunits CROSS JOIN unit_authors USING(unit) CROSS JOIN my_witnesses USING(address) \n\
				WHERE wunits."+order_column+" > units."+order_column+" \n\
				LIMIT 0,1 \n\
			)) \n\
			/* AND NOT EXISTS (SELECT * FROM unhandled_joints) */ \n\
		ORDER BY units."+order_column+" DESC", 
```

**File:** main_chain.js (L1163-1189)
```javascript
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
```

**File:** main_chain.js (L1386-1391)
```javascript
		conn.query(
			"SELECT units.*, ball FROM units LEFT JOIN balls USING(unit) \n\
			WHERE main_chain_index=? ORDER BY level, unit", [mci], 
			function(unit_rows){
				if (unit_rows.length === 0)
					throw Error("no units on mci "+mci);
```

**File:** archiving.js (L40-40)
```javascript
		conn.addQuery(arrQueries, "DELETE FROM units WHERE unit=?", [unit]);
```
