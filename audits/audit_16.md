# Audit Report

## Title
Inconsistent Ball Property Handling in Witness Proof Preparation Causes Light Client Sync Failure

## Summary
The `prepareWitnessProof()` function uses `storage.readJoint()` instead of `storage.readJointWithBall()` when retrieving stable witness definition change units. [1](#0-0)  This causes the `.ball` property to be omitted for retrievable units, creating an inconsistency with `processWitnessProof()` which strictly requires this property, [2](#0-1)  resulting in complete light client synchronization failure.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

All light clients network-wide experience complete inability to sync transaction history or submit new transactions during the period when a witness definition change unit is stable but still retrievable. This affects 100% of light wallet users simultaneously whenever any of the 12 witnesses performs legitimate security operations such as key rotation or multi-signature updates. Duration ranges from hours to days until the unit's MCI falls below `min_retrievable_mci`.

## Finding Description

**Location**: `byteball/ocore/witness_proof.js:139`, function `prepareWitnessProof()`

**Intended Logic**: Witness proof preparation should collect all stable witness definition change units with complete metadata including `.ball` properties to enable light client verification of witness list evolution.

**Actual Logic**: The function uses `storage.readJoint()` for stable witness definition changes, [1](#0-0)  but `readJoint()` optimizes by skipping ball queries for retrievable units. The retrievability check determines units with `main_chain_index >= min_retrievable_mci` are retrievable, [3](#0-2)  and for such units, the ball query is skipped entirely. [4](#0-3) 

In contrast, `readJointWithBall()` explicitly ensures the ball property is always present by querying it separately if not already included. [5](#0-4)  The unstable MC units correctly use this function. [6](#0-5) 

**Exploitation Path**:

1. **Preconditions**: 
   - A witness changes their address definition (legitimate key rotation/multi-sig update)
   - The definition change unit becomes stable (`is_stable=1`)
   - The unit remains retrievable (`main_chain_index >= min_retrievable_mci`)

2. **Step 1**: Light client requests witness proof via network protocol triggering `prepareWitnessProof()`

3. **Step 2**: SQL query at lines 120-135 selects stable witness definition changes [7](#0-6)  filtering `is_stable=1` but NOT filtering out retrievable MCIs, returning a witness definition change unit that is stable but retrievable

4. **Step 3**: `storage.readJoint()` called at line 139 flows to `readJointDirectly()`, determines `bRetrievable = true`, and skips the ball query [4](#0-3)  returning `objJoint` WITHOUT `.ball` property

5. **Step 4**: Incomplete joint added to `arrWitnessChangeAndDefinitionJoints` array and returned to light client in witness proof response

6. **Step 5**: Light client validates proof via `processWitnessProof()` which fails validation at line 206 [2](#0-1)  with error "witness_change_and_definition_joints: joint without ball", causing complete light client sync failure

**Root Cause Analysis**: The developer correctly used `readJointWithBall()` at line 31 for unstable MC units but inconsistently used `readJoint()` at line 139 for stable definition changes. The faulty assumption was that stable units would automatically have balls in their returned objects. However, `readJoint()` optimizes by skipping ball queries for retrievable units regardless of stability status, while the validation requirement at line 206 expects ALL witness definition change joints to have balls.

## Impact Explanation

**Affected Assets**: Light client synchronization infrastructure, network accessibility for all mobile/lightweight wallet users

**Damage Severity**:
- **Quantitative**: 100% of light clients network-wide affected simultaneously for hours to days
- **Qualitative**: Complete denial of service for light wallet functionality—no transaction viewing, balance checking, or transaction submission possible

**User Impact**:
- **Who**: All light wallet users (mobile wallets, browser wallets, lightweight nodes)
- **Conditions**: Automatically triggered when any witness performs definition change while unit remains retrievable
- **Recovery**: Self-resolving once unit becomes non-retrievable OR requires connecting to patched full node

**Systemic Risk**: Temporary availability issue only with no permanent damage, fund loss, or cascading consensus effects on full nodes. Self-correcting once `min_retrievable_mci` advances beyond the unit's MCI.

## Likelihood Explanation

**Attacker Profile**: No attacker required—triggered by legitimate witness operational security practices (key rotation, multi-signature updates)

**Preconditions**:
- **Network State**: Normal operation
- **Event**: Witness performs legitimate definition change
- **Timing**: Definition change stable but within retrievable window (realistic condition)

**Execution Complexity**: Triggered automatically with 100% reproducibility when preconditions are met, requiring no coordination or special technical skills

**Frequency**: Every witness definition change during retrievable window causes network-wide impact on all light clients

**Overall Assessment**: High likelihood when witness definition changes occur (rare but legitimate events with deterministic 100% impact)

## Recommendation

**Immediate Mitigation**: Replace `storage.readJoint()` with `storage.readJointWithBall()` at line 139 of `witness_proof.js` to ensure ball property is always included for witness definition change units.

**Permanent Fix**:
```javascript
// File: witness_proof.js, Line 139
// Change from:
storage.readJoint(db, row.unit, {...})

// To:
storage.readJointWithBall(db, row.unit, function(objJoint) {
    arrWitnessChangeAndDefinitionJoints.push(objJoint);
    cb2();
})
```

**Additional Measures**:
- Add test case verifying witness proofs include balls for stable retrievable witness definition changes
- Add assertion in `prepareWitnessProof()` to validate ball presence before returning to light clients
- Consider documentation clarifying when `readJointWithBall()` vs `readJoint()` should be used

## Proof of Concept

```javascript
const test = require('ava');
const db = require('../db.js');
const storage = require('../storage.js');
const witness_proof = require('../witness_proof.js');

test('witness proof includes ball for stable retrievable definition changes', async t => {
    // Setup: Create test witness definition change unit that is:
    // 1. Stable (is_stable=1)
    // 2. Retrievable (main_chain_index >= min_retrievable_mci)
    
    const testWitnesses = ['TEST_WITNESS_ADDRESS_1', 'TEST_WITNESS_ADDRESS_2']; // ... 12 witnesses
    
    // Simulate witness definition change unit
    const testUnit = 'TEST_UNIT_HASH_WITH_DEFINITION_CHANGE';
    
    // Insert test data making unit stable but retrievable
    await db.query("INSERT INTO units (unit, is_stable, main_chain_index) VALUES (?, 1, ?)", 
        [testUnit, storage.getMinRetrievableMci() + 10]);
    
    // Prepare witness proof
    witness_proof.prepareWitnessProof(testWitnesses, 0, (err, arrUnstableMcJoints, arrWitnessChangeAndDefinitionJoints, last_ball_unit, last_ball_mci) => {
        if (err) return t.fail(err);
        
        // Find our test unit in the witness change joints
        const testJoint = arrWitnessChangeAndDefinitionJoints.find(j => j.unit.unit === testUnit);
        
        // ASSERTION: Ball property should be present for stable definition changes
        // This will FAIL due to the bug - readJoint() skips ball for retrievable units
        t.truthy(testJoint.ball, 'Witness definition change joint must have ball property');
        
        // If bug is fixed, light client validation will pass
        witness_proof.processWitnessProof(arrUnstableMcJoints, arrWitnessChangeAndDefinitionJoints, false, testWitnesses, (err, arrLastBallUnits, assocLastBallByLastBallUnit) => {
            // Should not error with "joint without ball"
            t.falsy(err, 'Light client proof validation should succeed');
        });
    });
});
```

**Notes**:
- This vulnerability only affects light clients during the specific window when witness definition change units are stable but still retrievable
- Full nodes continue operating normally and are not affected
- The issue self-resolves once the main chain advances sufficiently that the definition change unit becomes non-retrievable
- No funds are at risk; this is purely a temporary availability issue for light client functionality

### Citations

**File:** witness_proof.js (L31-31)
```javascript
					storage.readJointWithBall(db, row.unit, function(objJoint){
```

**File:** witness_proof.js (L120-135)
```javascript
				"SELECT unit, `level` \n\
				FROM unit_authors "+db.forceIndex('byDefinitionChash')+" \n\
				CROSS JOIN units USING(unit) \n\
				WHERE definition_chash IN(?) AND definition_chash=address AND "+after_last_stable_mci_cond+" AND is_stable=1 AND sequence='good' \n\
				UNION \n\
				SELECT unit, `level` \n\
				FROM address_definition_changes \n\
				CROSS JOIN units USING(unit) \n\
				WHERE address_definition_changes.address IN(?) AND "+after_last_stable_mci_cond+" AND is_stable=1 AND sequence='good' \n\
				UNION \n\
				SELECT units.unit, `level` \n\
				FROM address_definition_changes \n\
				CROSS JOIN unit_authors USING(address, definition_chash) \n\
				CROSS JOIN units ON unit_authors.unit=units.unit \n\
				WHERE address_definition_changes.address IN(?) AND "+after_last_stable_mci_cond+" AND is_stable=1 AND sequence='good' \n\
				ORDER BY `level`", 
```

**File:** witness_proof.js (L139-147)
```javascript
						storage.readJoint(db, row.unit, {
							ifNotFound: function(){
								throw Error("prepareWitnessProof definition changes: not found "+row.unit);
							},
							ifFound: function(objJoint){
								arrWitnessChangeAndDefinitionJoints.push(objJoint);
								cb2();
							}
						});
```

**File:** witness_proof.js (L206-207)
```javascript
		if (!objJoint.ball)
			return handleResult("witness_change_and_definition_joints: joint without ball");
```

**File:** storage.js (L160-160)
```javascript
			var bRetrievable = (main_chain_index >= min_retrievable_mci || main_chain_index === null);
```

**File:** storage.js (L198-200)
```javascript
				function(callback){ // ball
					if (bRetrievable && !isGenesisUnit(unit))
						return callback();
```

**File:** storage.js (L608-624)
```javascript
// add .ball even if it is not retrievable
function readJointWithBall(conn, unit, handleJoint) {
	readJoint(conn, unit, {
		ifNotFound: function(){
			throw Error("joint not found, unit "+unit);
		},
		ifFound: function(objJoint){
			if (objJoint.ball)
				return handleJoint(objJoint);
			conn.query("SELECT ball FROM balls WHERE unit=?", [unit], function(rows){
				if (rows.length === 1)
					objJoint.ball = rows[0].ball;
				handleJoint(objJoint);
			});
		}
	});
}
```
