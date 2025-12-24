## Title
Inconsistent Ball Property Handling in Witness Proof Preparation Causes Light Client Sync Failure

## Summary
The `prepareWitnessProof()` function in `witness_proof.js` uses `storage.readJoint()` to read stable witness definition change units, which does not populate the `.ball` property for retrievable units (recent stable units with `main_chain_index >= min_retrievable_mci`). Subsequently, `processWitnessProof()` validates these proofs and explicitly rejects joints without the `.ball` property, preventing all light clients from syncing whenever a witness changes their address definition within the retrievable MCI window.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

**Affected Assets**: Light client synchronization operations, all light wallet users

**Damage Severity**:
- **Quantitative**: All light clients network-wide are unable to sync when any of the 12 witnesses changes their address definition while the change remains within the retrievable MCI window (typically spanning several hours to days based on network activity)
- **Qualitative**: Temporary denial of service for all light clients - complete inability to sync transaction history or submit new transactions until the definition change unit becomes non-retrievable

**User Impact**:
- **Who**: All light wallet users (mobile wallets, lightweight nodes)
- **Conditions**: Triggered whenever a witness legitimately changes their address definition (e.g., multi-signature updates, key rotation for security)
- **Duration**: Sync failure persists until the definition change unit's MCI falls below `min_retrievable_mci` (potentially hours to days)
- **Recovery**: Light clients must either wait for the retrievable window to pass, connect to a patched full node, or upgrade to full node status

## Finding Description

**Location**: `byteball/ocore/witness_proof.js:139` (function `prepareWitnessProof()`) and `byteball/ocore/storage.js:199` (function `readJointDirectly()`)

**Intended Logic**: The witness proof preparation should collect all stable witness definition change units with complete data including their `.ball` properties, enabling light clients to verify witness list evolution. The proof validation should accept properly formatted proofs containing all required fields.

**Actual Logic**: The code exhibits an architectural inconsistency in storage function usage:
- Line 31 uses `readJointWithBall()` for unstable MC units, which always ensures `.ball` is present [1](#0-0) 
- Line 139 uses `readJoint()` for witness definition changes [2](#0-1) 
- For retrievable units, `readJoint()` via `readJointDirectly()` explicitly skips querying the `.ball` property [3](#0-2) 
- The SQL query at lines 120-135 correctly filters for stable units using `is_stable=1` [4](#0-3) 
- Validation in `processWitnessProof()` explicitly requires `.ball` for all witness change/definition joints and fails if absent [5](#0-4) 

**Code Evidence**:

Inconsistent function usage - `readJointWithBall()` for unstable MC units: [6](#0-5) 

Inconsistent function usage - `readJoint()` for definition changes: [2](#0-1) 

Validation expects `.ball` property for witness change joints: [5](#0-4) 

`readJoint()` skips ball query for retrievable units: [7](#0-6) 

`readJointWithBall()` always ensures `.ball` is present: [8](#0-7) 

**Exploitation Path**:

1. **Preconditions**: 
   - A witness changes their address definition (legitimate security operation)
   - The definition change unit becomes stable (confirmed by majority of witnesses)
   - The unit remains within retrievable MCI range (`main_chain_index >= min_retrievable_mci`)

2. **Step 1**: Light client requests witness proof from full node
   - Code path: Light client → full node's `prepareWitnessProof()` function

3. **Step 2**: Full node queries stable witness definition changes
   - SQL query at lines 120-135 selects units where `is_stable=1` [4](#0-3) 
   - Query finds the recent witness definition change unit

4. **Step 3**: Full node calls `storage.readJoint()` for definition change unit
   - At line 139: `storage.readJoint(db, row.unit, {...})` [9](#0-8) 
   - Internal flow: `readJoint()` → `readJointDirectly()` 
   - At line 199 of storage.js: `if (bRetrievable && !isGenesisUnit(unit)) return callback();` [10](#0-9) 
   - Ball query is skipped, returns `objJoint` WITHOUT `.ball` property

5. **Step 4**: Joint without `.ball` added to proof array
   - Line 144: `arrWitnessChangeAndDefinitionJoints.push(objJoint);` [11](#0-10) 
   - Proof sent to light client

6. **Step 5**: Light client validates proof using `processWitnessProof()`
   - Line 206: `if (!objJoint.ball)` check fails [5](#0-4) 
   - Returns error: `"witness_change_and_definition_joints: joint without ball"`
   - Light client sync fails completely

**Root Cause Analysis**:

The root cause is an architectural mismatch between storage optimization and validation requirements:

1. **Storage Design**: `readJoint()` intentionally omits `.ball` for retrievable units to optimize storage access, assuming full unit content is available and `.ball` hash is redundant [3](#0-2) 

2. **Validation Requirement**: `processWitnessProof()` explicitly requires `.ball` for all stable witness definition change units regardless of retrievability status [5](#0-4) 

3. **Function Selection Error**: `prepareWitnessProof()` uses `readJoint()` instead of `readJointWithBall()` for definition changes. The correct function (`readJointWithBall()`) exists and is already used at line 31 for unstable MC units [1](#0-0) , which always ensures `.ball` is present by querying it separately if needed [8](#0-7) 

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: No attacker required - triggered by legitimate witness operational security practices
- **Resources Required**: None - witnesses naturally update their definitions for security reasons
- **Technical Skill**: Not applicable - this is a protocol bug, not an attack

**Preconditions**:
- **Network State**: Normal operation with witness performing legitimate definition change
- **Timing**: Definition change must be stable but within retrievable MCI window (typical duration: several hours to days)

**Execution Complexity**:
- **Triggered Automatically**: Every witness definition change triggers this bug for all light clients
- **Coordination**: None required
- **Detection**: Immediately observable - light clients report sync failures with specific error message

**Frequency**:
- **Repeatability**: Occurs 100% of the time when preconditions are met
- **Scale**: Network-wide impact on all light clients simultaneously

**Overall Assessment**: High likelihood - while witness definition changes are infrequent, they are legitimate security operations, and when they occur, the bug triggers deterministically for all light clients.

## Recommendation

**Immediate Mitigation**:
Change line 139 in `witness_proof.js` from `storage.readJoint()` to `storage.readJointWithBall()`:

```javascript
// File: byteball/ocore/witness_proof.js, line 139
// BEFORE:
storage.readJoint(db, row.unit, {

// AFTER:  
storage.readJointWithBall(db, row.unit, function(objJoint){
```

This aligns the definition change reading with the pattern already used for unstable MC units at line 31.

**Additional Measures**:
- Add integration test verifying light client sync succeeds when witness changes definition while change is retrievable
- Document the requirement that witness proof preparation must always include ball hashes for stable units
- Consider refactoring to make `.ball` requirement explicit in function signatures

**Validation**:
- Fix ensures `.ball` is always present for witness definition change units in proofs
- No performance impact - `readJointWithBall()` only adds one extra query when needed
- Backward compatible - does not affect proof format or validation logic

## Proof of Concept

```javascript
// Test file: test/witness_proof_retrievable_definition_change.test.js
// Demonstrates: prepareWitnessProof() fails when witness definition change is retrievable

const witness_proof = require('../witness_proof.js');
const storage = require('../storage.js');
const db = require('../db.js');

async function testRetrievableDefinitionChangeBug() {
    // Setup: Create scenario where witness changes definition
    // and the change is stable but retrievable (main_chain_index >= min_retrievable_mci)
    
    const witnessAddress = 'WITNESS_ADDRESS_HERE';
    const arrWitnesses = [witnessAddress, /* ...11 more witnesses */];
    
    // 1. Witness posts definition change unit
    // 2. Unit becomes stable (confirmed by majority)
    // 3. Unit remains retrievable (recent, within min_retrievable_mci window)
    
    // Test: Full node prepares proof for light client
    witness_proof.prepareWitnessProof(arrWitnesses, last_stable_mci, (err, arrUnstableMcJoints, arrWitnessChangeAndDefinitionJoints, last_ball_unit, last_ball_mci) => {
        if (err) {
            console.log('prepareWitnessProof error:', err);
            return;
        }
        
        // BUG: Check if definition change joint has .ball property
        const definitionChangeJoint = arrWitnessChangeAndDefinitionJoints.find(j => 
            j.unit.messages.some(m => m.app === 'address_definition_change')
        );
        
        if (definitionChangeJoint && !definitionChangeJoint.ball) {
            console.log('BUG CONFIRMED: Definition change joint missing .ball property');
            console.log('Unit:', definitionChangeJoint.unit.unit);
            console.log('Is stable:', true);
            console.log('Is retrievable: main_chain_index >= min_retrievable_mci:', true);
        }
        
        // Test: Light client validates the proof
        witness_proof.processWitnessProof(arrUnstableMcJoints, arrWitnessChangeAndDefinitionJoints, false, arrWitnesses, (validationErr, arrLastBallUnits, assocLastBallByLastBallUnit) => {
            if (validationErr === "witness_change_and_definition_joints: joint without ball") {
                console.log('VALIDATION FAILED: Light client cannot sync');
                console.log('Error:', validationErr);
                // Test proves: Light clients cannot sync when witness definition changes are retrievable
            }
        });
    });
}
```

**Notes**

This vulnerability is triggered by legitimate witness behavior (address definition updates for security) rather than malicious activity. The impact is temporary (lasting until the definition change unit becomes non-retrievable) but affects all light clients network-wide simultaneously. The fix is straightforward - using the correct storage function (`readJointWithBall()`) that already exists and is used elsewhere in the same file for similar purposes.

The severity assessment as Medium aligns with Immunefi's "Temporary Transaction Delay ≥1 Hour" category, as the retrievable MCI window typically spans several hours to days depending on network activity.

### Citations

**File:** witness_proof.js (L31-33)
```javascript
					storage.readJointWithBall(db, row.unit, function(objJoint){
						delete objJoint.ball; // the unit might get stabilized while we were reading other units
						arrUnstableMcJoints.push(objJoint);
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

**File:** storage.js (L198-208)
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
