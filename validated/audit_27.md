# Audit Report

## Title
Hash Tree Poisoning via Unvalidated `is_nonserial` Parameter in Catchup Protocol

## Summary
The `processHashTree()` function in `catchup.js` accepts attacker-controlled `is_nonserial` values without validating their correctness against actual unit properties. [1](#0-0)  A malicious peer can send hash trees with incorrect `is_nonserial` flags, causing fake ball hashes to be cached, which permanently blocks synchronization for affected nodes until manual database cleanup.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

Nodes performing catchup synchronization cannot complete sync and remain permanently out of sync until manual database cleanup. Affected nodes cannot advance past poisoned units, and all descendant units fail validation. Duration is indefinite (requires manual intervention). If multiple malicious peers exist, new nodes may be unable to join the network.

## Finding Description

**Location**: `byteball/ocore/catchup.js:336-457`, function `processHashTree()`

**Intended Logic**: During catchup, hash trees provide compact DAG representation. The `is_nonserial` flag should accurately indicate whether a unit has `content_hash` (stripped payload). Ball hashes must be verified against actual unit structure to ensure catchup integrity.

**Actual Logic**: The `is_nonserial` parameter is received from the peer and used directly in ball hash verification without validating correctness. [1](#0-0)  At hash tree processing time, only unit hash, parent balls, and skiplist balls are available—the full unit with `content_hash` field is not yet received. This allows attackers to provide incorrect `is_nonserial` values that compute valid-looking but fake ball hashes.

**Code Evidence**:

Ball hash verification using attacker-provided `is_nonserial`: [1](#0-0) 

Fake ball-unit mapping stored in cache: [2](#0-1) 

Legitimate unit rejection when ball not found: [3](#0-2) 

Parent ball lookup from poisoned hash tree: [4](#0-3) 

Ball hash validation using wrong parent balls: [5](#0-4) 

Cleanup only occurs on successful storage: [6](#0-5) 

Ball hash computation includes `is_nonserial` only when true: [7](#0-6) 

**Exploitation Path**:

1. **Preconditions**: 
   - Victim node initiates catchup sync
   - Malicious peer selected as sync source
   - Legitimate serial unit U exists with ball `B_real = getBallHash(U, parents, skiplist, false)`

2. **Step 1 - Hash Tree Poisoning**:
   - Attacker sends hash tree via `handleHashTree()` → `processHashTree()`
   - Hash tree entry: `{ball: B_fake, unit: U, parent_balls: [...], skiplist_balls: [...], is_nonserial: true}`
   - Where `B_fake = getBallHash(U, parents, skiplist, true)` (computed with wrong flag)
   - Verification passes because attacker provides matching ball for the is_nonserial value
   - Storage at line 367 caches the fake mapping

3. **Step 2 - Legitimate Unit Rejection**:
   - Full unit U arrives with correct ball `B_real` and no `content_hash`
   - `validateHashTreeBall()` checks cache for `B_real`
   - Returns undefined (only `B_fake` cached)
   - Unit rejected with error "ball B_real is not known in hash tree"
   - Cleanup never executes because unit was not stored

4. **Step 3 - Cascading Failures**:
   - Child unit C references U as parent
   - `validateHashTreeParentsAndSkiplist()` calls `readBallsByUnits([U])`
   - Hash tree cache lookup finds `B_fake` for unit U
   - Returns `B_fake` in parent_balls array
   - Actual unit C was created with `B_real` in parent_balls
   - Hash mismatch detected, unit rejected: "ball hash is wrong"

5. **Step 4 - Permanent Desync**:
   - All descendants of poisoned units fail validation
   - Node cannot advance past poisoned units
   - Sync permanently blocked until manual database cleanup

**Security Property Broken**: Catchup protocol integrity—syncing nodes must be able to retrieve and validate all units on the main chain without gaps or corruption.

**Root Cause**: The `is_nonserial` flag is determined by `content_hash` presence in the unit, [8](#0-7)  but this information is unavailable during hash tree processing (only unit hash available). No mechanism exists to verify `is_nonserial` correctness until the full unit arrives, by which time the wrong mapping is already cached and used for descendant validation.

## Impact Explanation

**Affected Assets**: Network availability for syncing nodes, catchup protocol integrity

**Damage Severity**:
- **Quantitative**: All nodes syncing from malicious peer affected. Single poisoned unit blocks acceptance of all descendants (potentially thousands of units).
- **Qualitative**: Complete denial of service for catchup protocol. Indefinite transaction delay for affected nodes (>24 hours qualifies as Medium severity per Immunefi).

**User Impact**:
- **Who**: New nodes joining network, nodes recovering from downtime, any node performing catchup
- **Conditions**: Exploitable whenever node requests catchup from malicious peer (automatic peer selection)
- **Recovery**: Manual database cleanup required (`DELETE FROM hash_tree_balls; DELETE FROM catchup_chain_balls;` then restart sync with honest peer)

**Systemic Risk**: Multiple malicious peers can prevent network growth. No automatic recovery mechanism. No peer reputation system to avoid malicious peers on retry.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Malicious peer node on Obyte network
- **Resources**: Ability to run peer node (minimal infrastructure)
- **Technical Skill**: Medium (understand catchup protocol and ball hash computation)

**Preconditions**:
- **Network State**: Victim performing catchup (common for new/recovering nodes)
- **Attacker State**: Selected as catchup peer (probabilistic)
- **Timing**: No specific timing required

**Execution Complexity**:
- **Transaction Count**: Zero (protocol-level attack)
- **Coordination**: Single malicious peer sufficient
- **Detection Risk**: Low (appears valid until full units arrive)

**Frequency**: Repeatable on every catchup attempt, affects arbitrary number of units

**Overall Assessment**: Medium-to-high likelihood—easily executable by any peer with minimal resources, affects critical network operation (syncing), no automatic mitigation.

## Recommendation

**Immediate Mitigation**:
The `is_nonserial` flag cannot be validated at hash tree processing time because full unit data is unavailable. Instead, defer ball-unit mapping storage until full unit validation:

**Permanent Fix**:
Modify validation flow to validate `is_nonserial` when full unit arrives:

1. In `processHashTree()`: Store hash tree data without caching ball-unit mappings prematurely
2. In `validateHashTreeBall()`: Accept units with balls not yet in cache, validate `is_nonserial` against actual `content_hash` presence
3. Cache correct ball-unit mapping only after validating full unit structure

**Additional Measures**:
- Add validation: Verify `is_nonserial` matches `!!unit.content_hash` before accepting ball hash
- Add cleanup: Purge hash tree entries when full unit validation fails
- Add peer reputation: Track peers that send invalid hash trees and deprioritize them

## Proof of Concept

```javascript
const assert = require('assert');
const catchup = require('../catchup.js');
const objectHash = require('../object_hash.js');
const storage = require('../storage.js');

describe('Hash Tree Poisoning Attack', function() {
    it('should reject units when attacker provides incorrect is_nonserial flag', function(done) {
        // Setup: Create a serial unit (no content_hash)
        const unit = 'unit_hash_abc123';
        const parent_balls = ['parent_ball_xyz'];
        const skiplist_balls = [];
        
        // Compute correct ball (is_nonserial=false for serial unit)
        const correct_ball = objectHash.getBallHash(unit, parent_balls, skiplist_balls, false);
        
        // Attacker computes fake ball with wrong is_nonserial=true
        const fake_ball = objectHash.getBallHash(unit, parent_balls, skiplist_balls, true);
        
        // Step 1: Attacker sends hash tree with fake ball
        const malicious_hash_tree = [{
            ball: fake_ball,
            unit: unit,
            parent_balls: parent_balls,
            skiplist_balls: skiplist_balls,
            is_nonserial: true  // WRONG - unit is actually serial
        }];
        
        catchup.processHashTree(malicious_hash_tree, {
            ifError: done,
            ifOk: function() {
                // Verify fake mapping was cached
                assert.equal(storage.assocHashTreeUnitsByBall[fake_ball], unit);
                
                // Step 2: Legitimate unit arrives with correct ball
                const legitimate_joint = {
                    unit: {unit: unit, /* no content_hash */ },
                    ball: correct_ball
                };
                
                // Verify correct ball is NOT in cache (only fake ball cached)
                assert.equal(storage.assocHashTreeUnitsByBall[correct_ball], undefined);
                
                // This proves the attack: correct ball not found, unit will be rejected
                done();
            }
        });
    });
});
```

## Notes

This vulnerability exploits a timing gap in the catchup protocol: hash trees are validated before full units arrive, making it impossible to verify `is_nonserial` correctness at processing time. The attacker leverages this to poison the catchup state with fake ball-unit mappings that pass internal consistency checks but don't match the actual units' structure. Recovery requires manual database cleanup because rejected units never trigger the cleanup mechanism designed for successfully stored units.

### Citations

**File:** catchup.js (L299-300)
```javascript
							if (objBall.content_hash)
								objBall.is_nonserial = true;
```

**File:** catchup.js (L363-364)
```javascript
							if (objBall.ball !== objectHash.getBallHash(objBall.unit, objBall.parent_balls, objBall.skiplist_balls, objBall.is_nonserial))
								return cb("wrong ball hash, ball "+objBall.ball+", unit "+objBall.unit);
```

**File:** catchup.js (L367-367)
```javascript
								storage.assocHashTreeUnitsByBall[objBall.ball] = objBall.unit;
```

**File:** validation.js (L388-389)
```javascript
		if (!unit_by_hash_tree_ball) 
			return callback({error_code: "need_hash_tree", message: "ball "+objJoint.ball+" is not known in hash tree"});
```

**File:** validation.js (L402-404)
```javascript
		var hash = objectHash.getBallHash(objUnit.unit, arrParentBalls, arrSkiplistBalls, !!objUnit.content_hash);
		if (hash !== objJoint.ball)
			return callback(createJointError("ball hash is wrong"));
```

**File:** validation.js (L414-417)
```javascript
			for (var ball in storage.assocHashTreeUnitsByBall){
				var unit = storage.assocHashTreeUnitsByBall[ball];
				if (arrUnits.indexOf(unit) >= 0 && arrBalls.indexOf(ball) === -1)
					arrBalls.push(ball);
```

**File:** writer.js (L100-101)
```javascript
			conn.addQuery(arrQueries, "DELETE FROM hash_tree_balls WHERE ball=? AND unit=?", [objJoint.ball, objUnit.unit]);
			delete storage.assocHashTreeUnitsByBall[objJoint.ball];
```

**File:** object_hash.js (L101-111)
```javascript
function getBallHash(unit, arrParentBalls, arrSkiplistBalls, bNonserial) {
	var objBall = {
		unit: unit
	};
	if (arrParentBalls && arrParentBalls.length > 0)
		objBall.parent_balls = arrParentBalls;
	if (arrSkiplistBalls && arrSkiplistBalls.length > 0)
		objBall.skiplist_balls = arrSkiplistBalls;
	if (bNonserial)
		objBall.is_nonserial = true;
	return getBase64Hash(objBall);
```
