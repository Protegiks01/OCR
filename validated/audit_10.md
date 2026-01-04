# Audit Report

## Title
Inconsistent Ball Property Handling in Witness Proof Preparation Causes Light Client Sync Failure

## Summary
The `prepareWitnessProof()` function in witness_proof.js uses `storage.readJoint()` instead of `storage.readJointWithBall()` when retrieving stable witness definition change units. This causes the `.ball` property to be omitted for retrievable units, creating an inconsistency with `processWitnessProof()` validation requirements, resulting in complete light client synchronization failure.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

All light clients network-wide experience complete inability to sync transaction history during the period when a witness definition change unit is stable but still retrievable (main_chain_index ≥ min_retrievable_mci). This affects 100% of light wallet users simultaneously whenever any witness performs legitimate operations such as key rotation. Duration ranges from hours to days until the unit's MCI falls below min_retrievable_mci, at which point the issue self-resolves.

## Finding Description

**Location**: `byteball/ocore/witness_proof.js:139`, function `prepareWitnessProof()`

**Intended Logic**: Witness proof preparation should collect all stable witness definition change units with complete metadata including `.ball` properties to enable light client verification of witness list evolution.

**Actual Logic**: The function uses `storage.readJoint()` for stable witness definition changes [1](#0-0) , but `readJoint()` optimizes by skipping ball queries for retrievable units. The retrievability check determines units with `main_chain_index >= min_retrievable_mci` are retrievable [2](#0-1) , and for such units, the ball query is skipped entirely [3](#0-2) .

In contrast, `readJointWithBall()` explicitly ensures the ball property is always present by querying it separately if not already included [4](#0-3) . The unstable MC units correctly use this function [5](#0-4) .

**Exploitation Path**:

1. **Preconditions**: 
   - A witness changes their address definition (legitimate key rotation/multi-sig update)
   - The definition change unit becomes stable (`is_stable=1`)
   - The unit remains retrievable (`main_chain_index >= min_retrievable_mci`)

2. **Step 1**: Light client requests witness proof via network protocol triggering `prepareWitnessProof()`

3. **Step 2**: SQL query at lines 120-135 selects stable witness definition changes [6](#0-5)  filtering `is_stable=1` but NOT filtering out retrievable MCIs, returning a witness definition change unit that is stable but retrievable

4. **Step 3**: `storage.readJoint()` flows to `readJointDirectly()`, determines `bRetrievable = true`, and skips the ball query [3](#0-2)  returning `objJoint` WITHOUT `.ball` property

5. **Step 4**: Incomplete joint added to `arrWitnessChangeAndDefinitionJoints` array [7](#0-6)  and returned to light client in witness proof response

6. **Step 5**: Light client validates proof via `processWitnessProof()` which fails validation [8](#0-7)  with error "witness_change_and_definition_joints: joint without ball", causing complete light client sync failure

**Root Cause Analysis**: The developer correctly used `readJointWithBall()` for unstable MC units but inconsistently used `readJoint()` for stable definition changes. The faulty assumption was that stable units would automatically have balls in their returned objects. However, `readJoint()` optimizes by skipping ball queries for retrievable units regardless of stability status, while the validation requirement expects ALL witness definition change joints to have balls.

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
- **Timing**: Definition change stable but within retrievable window (realistic condition that occurs naturally as recently stabilized units are typically retrievable)

**Execution Complexity**: Triggered automatically with 100% reproducibility when preconditions are met, requiring no coordination or special technical skills

**Frequency**: Every witness definition change during retrievable window causes network-wide impact on all light clients

**Overall Assessment**: High likelihood when witness definition changes occur (rare but legitimate events with deterministic 100% impact)

## Recommendation

**Immediate Mitigation**:
Change line 139 in witness_proof.js to use `readJointWithBall()` instead of `readJoint()`: [9](#0-8) 

Replace with:
```javascript
storage.readJointWithBall(db, row.unit, function(objJoint){
    arrWitnessChangeAndDefinitionJoints.push(objJoint);
    cb2();
});
```

**Permanent Fix**: Apply the same fix as immediate mitigation. This ensures consistency with how unstable MC units are handled [5](#0-4)  and guarantees the ball property is always present for validation.

**Additional Measures**:
- Add test case verifying witness proofs include balls for all witness definition change units regardless of retrievability
- Add monitoring to detect when witness definition changes occur within retrievable window

**Validation**:
- Fix ensures all witness definition change joints include `.ball` property
- No new vulnerabilities introduced (readJointWithBall is already used safely for unstable MC units)
- Backward compatible (only adds missing data, doesn't change validation logic)
- Performance impact negligible (one additional database query per witness definition change)

## Proof of Concept

```javascript
// Test scenario demonstrating the bug
// File: test/witness_proof_ball_bug.test.js

const db = require('../db.js');
const storage = require('../storage.js');
const witnessProof = require('../witness_proof.js');

describe('Witness Proof Ball Handling Bug', function() {
    this.timeout(60000);
    
    it('should fail when stable witness definition change is retrievable', async function() {
        // Setup: Create a scenario where:
        // 1. A witness changes their definition
        // 2. The unit becomes stable
        // 3. The unit is still retrievable (main_chain_index >= min_retrievable_mci)
        
        const witnessAddress = 'WITNESS_ADDRESS_HERE';
        const arrWitnesses = [witnessAddress, /* ... 11 more witnesses */];
        
        // Simulate state where:
        // - last_stable_mci = 1000
        // - min_retrievable_mci = 950 (set to last_ball_mci of last_stable_mci)
        // - witness definition change unit has main_chain_index = 980
        // - Therefore: 980 >= 950, so bRetrievable = true
        
        // When prepareWitnessProof is called:
        witnessProof.prepareWitnessProof(arrWitnesses, 900, function(err, arrUnstableMcJoints, arrWitnessChangeAndDefinitionJoints, last_ball_unit, last_ball_mci) {
            if (err) {
                console.log('Error in prepareWitnessProof:', err);
                return;
            }
            
            // Check if witness definition change joints have .ball property
            const missingBall = arrWitnessChangeAndDefinitionJoints.some(joint => !joint.ball);
            console.log('Witness definition change joints missing ball:', missingBall);
            
            if (missingBall) {
                // Now try to process the proof (simulating light client)
                witnessProof.processWitnessProof(
                    arrUnstableMcJoints, 
                    arrWitnessChangeAndDefinitionJoints, 
                    false, 
                    arrWitnesses,
                    function(err, arrLastBallUnits, assocLastBallByLastBallUnit) {
                        // This should fail with "witness_change_and_definition_joints: joint without ball"
                        console.log('processWitnessProof error:', err);
                        assert.equal(err, 'witness_change_and_definition_joints: joint without ball');
                        console.log('BUG CONFIRMED: Light client sync fails due to missing ball property');
                    }
                );
            }
        });
    });
});
```

**Notes**:
- The PoC demonstrates the logical flow of the bug
- A complete runnable test requires a full Obyte node setup with actual witness definition change units
- The bug is evident from code inspection: `readJoint()` skips balls for retrievable units while `processWitnessProof()` requires them
- The fix is straightforward: use `readJointWithBall()` consistently

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

**File:** storage.js (L199-200)
```javascript
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
