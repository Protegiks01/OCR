# Audit Report

## Title
Inconsistent Ball Property Handling in Witness Proof Preparation Causes Light Client Sync Failure

## Summary
The `prepareWitnessProof()` function uses `storage.readJoint()` instead of `storage.readJointWithBall()` when retrieving stable witness definition change units, causing the `.ball` property to be omitted for retrievable units. [1](#0-0)  This creates an inconsistency with `processWitnessProof()` which strictly requires this property [2](#0-1) , resulting in complete light client synchronization failure.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

All light clients network-wide experience complete inability to sync transaction history or submit new transactions during the period when a witness definition change unit is stable but still retrievable (main_chain_index >= min_retrievable_mci). This affects 100% of light wallet users simultaneously whenever any of the 12 witnesses performs legitimate security operations such as key rotation or multi-signature updates. Duration ranges from hours to days until the unit's MCI falls below min_retrievable_mci.

## Finding Description

**Location**: `byteball/ocore/witness_proof.js:139`, function `prepareWitnessProof()`

**Intended Logic**: Witness proof preparation should collect all stable witness definition change units with complete metadata including `.ball` properties to enable light client verification of witness list evolution.

**Actual Logic**: The function uses `storage.readJoint()` for stable witness definition changes [3](#0-2) , but `readJoint()` optimizes by skipping ball queries for retrievable units [4](#0-3) . The retrievability check determines units with main_chain_index >= min_retrievable_mci are retrievable [5](#0-4) , and for such units, the ball query is skipped entirely.

In contrast, `readJointWithBall()` explicitly ensures the ball property is always present by querying it separately if not already included [6](#0-5) . The unstable MC units correctly use this function at line 31 [7](#0-6) .

**Exploitation Path**:

1. **Preconditions**: 
   - A witness changes their address definition (legitimate key rotation/multi-sig update)
   - The definition change unit becomes stable (is_stable=1)
   - The unit remains retrievable (main_chain_index >= min_retrievable_mci)

2. **Step 1**: Light client requests witness proof via network protocol
   - Light client calls history refresh triggering `prepareWitnessProof()`

3. **Step 2**: Full node executes `prepareWitnessProof()`
   - SQL query at lines 120-135 selects stable witness definition changes [8](#0-7) 
   - Query filters `is_stable=1` but does NOT filter out retrievable MCIs
   - Returns witness definition change unit that is stable but retrievable

4. **Step 3**: `storage.readJoint()` called at line 139
   - Flows to `readJointDirectly()`
   - Retrievability check: `bRetrievable = true` (MCI >= min_retrievable_mci)
   - Ball query skipped at lines 198-200 of storage.js
   - Returns `objJoint` WITHOUT `.ball` property

5. **Step 4**: Incomplete joint added to `arrWitnessChangeAndDefinitionJoints` array
   - Joint lacks required ball property
   - Returned to light client in witness proof response

6. **Step 5**: Light client validates proof via `processWitnessProof()` [9](#0-8) 
   - Validation at line 206 fails with strict check [2](#0-1) 
   - Returns error: "witness_change_and_definition_joints: joint without ball"
   - Light client sync completely fails [10](#0-9) 

**Root Cause Analysis**:

The developer correctly used `readJointWithBall()` at line 31 for unstable MC units but inconsistently used `readJoint()` at line 139 for stable definition changes. The faulty assumption was that stable units would automatically have balls in their returned objects. However, `readJoint()` optimizes by skipping ball queries for retrievable units regardless of stability status, while the validation requirement at line 206 expects ALL witness definition change joints to have balls.

## Impact Explanation

**Affected Assets**: Light client synchronization infrastructure, network accessibility for all mobile/lightweight wallet users

**Damage Severity**:
- **Quantitative**: 100% of light clients network-wide affected simultaneously for hours to days
- **Qualitative**: Complete denial of service for light wallet functionality—no transaction viewing, balance checking, or transaction submission possible

**User Impact**:
- **Who**: All light wallet users (mobile wallets, browser wallets, lightweight nodes)
- **Conditions**: Automatically triggered when any witness performs definition change while unit remains retrievable
- **Recovery**: Self-resolving once unit becomes non-retrievable OR requires connecting to patched full node

**Systemic Risk**:
- Temporary availability issue only
- No permanent damage or fund loss
- No cascading consensus effects on full nodes
- Self-correcting once min_retrievable_mci advances beyond the unit's MCI

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: No attacker required—triggered by legitimate witness operational security
- **Resources Required**: None
- **Technical Skill**: N/A (protocol bug, not attack)

**Preconditions**:
- **Network State**: Normal operation
- **Event**: Witness performs legitimate definition change (key rotation, multi-sig update)
- **Timing**: Definition change stable but within retrievable window

**Execution Complexity**:
- **Triggered Automatically**: 100% reproducible when preconditions met
- **Coordination**: None required
- **Detection**: Immediately observable via light client error logs

**Frequency**:
- **Repeatability**: Every witness definition change during retrievable window
- **Scale**: Network-wide impact on all light clients

**Overall Assessment**: High likelihood when witness definition changes occur (rare but legitimate events with deterministic 100% impact)

## Recommendation

**Immediate Mitigation**:
Change line 139 to use `storage.readJointWithBall()` instead of `storage.readJoint()` to ensure ball property is always included for witness definition change units.

**Permanent Fix**:
```javascript
// File: byteball/ocore/witness_proof.js, line 139
storage.readJointWithBall(db, row.unit, function(objJoint){
    arrWitnessChangeAndDefinitionJoints.push(objJoint);
    cb2();
});
```

**Additional Measures**:
- Add test case verifying witness definition changes during retrievable window include ball properties
- Add integration test for light client sync during witness definition changes
- Consider adding defensive check in `processWitnessProof()` with more helpful error message

## Notes

This is a legitimate protocol bug, not an attack vector. It affects network availability for light clients rather than consensus integrity or fund security. The issue self-resolves as the network progresses and units become non-retrievable, making it a temporary denial of service matching the Medium severity "Temporary Transaction Delay" category per Immunefi scope.

### Citations

**File:** witness_proof.js (L31-31)
```javascript
					storage.readJointWithBall(db, row.unit, function(objJoint){
```

**File:** witness_proof.js (L120-136)
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
				[arrWitnesses, arrWitnesses, arrWitnesses],
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

**File:** light.js (L183-185)
```javascript
	witnessProof.processWitnessProof(
		objResponse.unstable_mc_joints, objResponse.witness_change_and_definition_joints, false, arrWitnesses,
		function(err, arrLastBallUnits, assocLastBallByLastBallUnit){
```

**File:** light.js (L187-188)
```javascript
			if (err)
				return callbacks.ifError(err);
```
