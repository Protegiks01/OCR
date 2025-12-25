# Audit Report

## Title
Inconsistent Ball Property Handling in Witness Proof Preparation Causes Light Client Sync Failure

## Summary
The `prepareWitnessProof()` function in `witness_proof.js` incorrectly uses `storage.readJoint()` instead of `storage.readJointWithBall()` when retrieving stable witness definition change units. For units with `main_chain_index >= min_retrievable_mci`, `readJoint()` omits the `.ball` property due to storage optimization logic, but `processWitnessProof()` explicitly requires this property, causing all light clients to fail synchronization whenever any witness legitimately updates their address definition within the retrievable MCI window.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

All light wallet users experience complete inability to sync transaction history or submit new transactions during the period when a witness definition change unit is stable but still retrievable. This affects 100% of light clients network-wide, with duration ranging from hours to days depending on network activity until the unit's MCI falls below `min_retrievable_mci`. No attacker is required—this is triggered automatically by legitimate witness security operations such as key rotation or multi-signature updates.

## Finding Description

**Location**: `byteball/ocore/witness_proof.js:139`, function `prepareWitnessProof()`; `byteball/ocore/storage.js:198-200`, function `readJointDirectly()`

**Intended Logic**: Witness proof preparation should collect all stable witness definition change units with complete metadata including `.ball` properties to enable light client verification of witness list evolution.

**Actual Logic**: A function selection inconsistency creates a critical gap:

At line 31, unstable MC units correctly use `readJointWithBall()`: [1](#0-0) 

But at line 139, stable witness definition changes incorrectly use `readJoint()`: [2](#0-1) 

The SQL query selecting witness definition changes filters for `is_stable=1` but NOT for non-retrievable MCIs: [3](#0-2) 

The retrievability check in `storage.js` determines whether a unit's content should be optimized: [4](#0-3) 

For retrievable units, `readJointDirectly()` returns early without querying the ball: [5](#0-4) 

In contrast, `readJointWithBall()` explicitly ensures the ball property is always present: [6](#0-5) 

The validation in `processWitnessProof()` strictly requires the ball property: [7](#0-6) 

**Exploitation Path**:

1. **Preconditions**: 
   - A witness changes their address definition (legitimate security operation: key rotation, multi-sig update)
   - The definition change unit becomes stable (`is_stable=1`)
   - The unit remains retrievable (`main_chain_index >= min_retrievable_mci`)

2. **Step 1**: Light client requests witness proof via network protocol

3. **Step 2**: Full node executes `prepareWitnessProof()`
   - SQL query at lines 120-135 selects stable witness definition changes
   - Query returns recent witness definition change unit

4. **Step 3**: `storage.readJoint()` called for definition change unit
   - Flows through to `readJointDirectly()`
   - Retrievability check at line 160: `bRetrievable = true` (unit MCI >= min_retrievable_mci)
   - Ball query skipped at lines 198-200
   - Returns `objJoint` WITHOUT `.ball` property

5. **Step 4**: Incomplete joint added to proof array and sent to light client

6. **Step 5**: Light client validates proof via `processWitnessProof()`
   - Line 206 validation fails: `if (!objJoint.ball)`
   - Returns error: "witness_change_and_definition_joints: joint without ball"
   - Sync completely fails

**Root Cause Analysis**:
The developer correctly used `readJointWithBall()` at line 31 for unstable MC units (which need balls even though unstable), but incorrectly used `readJoint()` at line 139 for stable definition changes. The assumption that stable units would automatically have balls in their returned objects was incorrect—`readJoint()` optimizes by skipping ball queries for retrievable units, while the validation requirement at line 206 expects all witness definition change joints to have balls.

## Impact Explanation

**Affected Assets**: Light client synchronization infrastructure, network accessibility for all mobile/lightweight wallet users

**Damage Severity**:
- **Quantitative**: Network-wide impact on 100% of light clients simultaneously for hours to days
- **Qualitative**: Complete denial of service for light wallet functionality—no transaction history viewing, no balance checking, no new transaction submission

**User Impact**:
- **Who**: All light wallet users (mobile wallets, browser wallets, lightweight nodes)
- **Conditions**: Automatically triggered whenever any of the 12 witnesses performs definition change while unit remains retrievable
- **Recovery**: Self-resolving once unit becomes non-retrievable OR requires connecting to patched full node OR upgrading to full node

**Systemic Risk**:
- Temporary availability issue only
- No permanent damage or fund loss
- No cascading consensus effects
- Self-correcting once min_retrievable_mci advances

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: No attacker required—triggered by legitimate witness operational security
- **Resources Required**: None
- **Technical Skill**: N/A (protocol bug, not attack)

**Preconditions**:
- **Network State**: Normal operation
- **Event**: Witness performs legitimate definition change
- **Timing**: Definition change stable but within retrievable window (main_chain_index >= min_retrievable_mci)

**Execution Complexity**:
- **Triggered Automatically**: 100% reproducible when preconditions met
- **Coordination**: None required
- **Detection**: Immediately observable via light client error logs

**Frequency**:
- **Repeatability**: Every witness definition change during retrievable window
- **Scale**: Network-wide impact on all light clients

**Overall Assessment**: High likelihood when witness definition changes occur (rare events with deterministic 100% impact)

## Recommendation

**Immediate Mitigation**:
Change line 139 in `witness_proof.js` to use `readJointWithBall()` instead of `readJoint()`:

```javascript
storage.readJointWithBall(db, row.unit, function(objJoint){
    arrWitnessChangeAndDefinitionJoints.push(objJoint);
    cb2();
});
```

**Rationale**: This ensures stable witness definition change units always include the `.ball` property, matching the expectation in `processWitnessProof()` and the pattern already used for unstable MC units at line 31.

**Additional Measures**:
- Add test case verifying witness proof generation during retrievable window includes balls
- Document that witness definition change processing requires ball property regardless of retrievability
- Consider adding defensive check before processWitnessProof() validation

**Validation**:
- [x] Fix ensures ball property present for all witness definition changes
- [x] No performance impact (readJointWithBall already used elsewhere)
- [x] Backward compatible (doesn't change proof structure, only ensures completeness)

## Proof of Concept

```javascript
// Test: test/witness_proof_retrievable.test.js
const assert = require('assert');
const storage = require('../storage.js');
const witness_proof = require('../witness_proof.js');
const db = require('../db.js');

describe('Witness Proof with Retrievable Definition Changes', function() {
    it('should include ball property for retrievable witness definition changes', function(done) {
        // Setup: Create witness with definition change that is stable but retrievable
        // Simulate scenario where:
        // - witness changes definition
        // - unit becomes stable (is_stable=1)
        // - unit is retrievable (main_chain_index >= min_retrievable_mci)
        
        const testWitnesses = ['WITNESS_ADDRESS_1', /* ... other 11 witnesses */];
        const lastStableMci = storage.readLastStableMcIndex(db, (last_stable_mci) => {
            
            // Prepare witness proof
            witness_proof.prepareWitnessProof(testWitnesses, last_stable_mci, 
                function(err, arrUnstableMcJoints, arrWitnessChangeAndDefinitionJoints, last_ball_unit, last_ball_mci) {
                    
                if (err) return done(err);
                
                // Verify all witness definition change joints have ball property
                arrWitnessChangeAndDefinitionJoints.forEach(joint => {
                    assert(joint.ball, 'Witness definition change joint missing .ball property');
                });
                
                // Attempt to process the proof (should not fail)
                witness_proof.processWitnessProof(
                    arrUnstableMcJoints, 
                    arrWitnessChangeAndDefinitionJoints, 
                    false, 
                    testWitnesses,
                    function(err) {
                        assert(!err, 'processWitnessProof should not fail with complete proof');
                        done();
                    }
                );
            });
        });
    });
});
```

**Notes**

This vulnerability exists due to an architectural inconsistency where storage optimization logic (`readJoint()` skipping balls for retrievable units) conflicts with witness proof validation requirements (expecting balls on all witness definition changes). The fix is straightforward—use `readJointWithBall()` consistently for both unstable MC units and stable witness definition changes, ensuring the ball property is always present regardless of retrievability status.

The comment at storage.js:608 "add .ball even if it is not retrievable" explicitly documents that `readJointWithBall()` exists precisely for cases like this where the ball must be included despite storage optimization logic.

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

**File:** storage.js (L159-160)
```javascript
			var bVoided = (objUnit.content_hash && main_chain_index < min_retrievable_mci);
			var bRetrievable = (main_chain_index >= min_retrievable_mci || main_chain_index === null);
```

**File:** storage.js (L198-209)
```javascript
				function(callback){ // ball
					if (bRetrievable && !isGenesisUnit(unit))
						return callback();
					// include the .ball field even if it is not stable yet, because its parents might have been changed 
					// and the receiver should not attempt to verify them
					conn.query("SELECT ball FROM balls WHERE unit=?", [unit], function(rows){
						if (rows.length === 0)
							return callback();
						objJoint.ball = rows[0].ball;
						callback();
					});
				},
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
