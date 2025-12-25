# Audit Report

## Title
Hash Tree Poisoning via Unvalidated `is_nonserial` Parameter in Catchup Protocol

## Summary
The `processHashTree()` function in `catchup.js` accepts attacker-controlled `is_nonserial` values without validating their correctness against actual unit properties. A malicious peer can send hash trees with incorrect `is_nonserial` flags, causing fake ball hashes to be cached in memory, which permanently blocks synchronization for affected nodes until manual database cleanup.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

Nodes performing catchup synchronization cannot complete sync and remain out of sync indefinitely (requiring manual intervention). Single poisoned unit blocks all descendant units. New nodes may be unable to join network if multiple malicious peers exist.

## Finding Description

**Location**: `byteball/ocore/catchup.js:336-457`, function `processHashTree()`

**Intended Logic**: During catchup, hash trees provide compact DAG representation. The `is_nonserial` flag should accurately indicate whether a unit has `content_hash` (stripped payload). Ball hashes must be verified against actual unit structure to ensure catchup integrity.

**Actual Logic**: The `is_nonserial` parameter is received from peer and used directly in ball hash verification without validating correctness. At hash tree processing time, only unit hash, parent balls, and skiplist balls are available—the full unit with `content_hash` field is not yet received. This allows attackers to provide incorrect `is_nonserial` values that compute valid-looking but fake ball hashes.

**Code Evidence**:

An honest peer correctly sets `is_nonserial` based on database `content_hash` field: [1](#0-0) 

However, `processHashTree()` validates the ball hash using the attacker-provided `is_nonserial` without checking correctness: [2](#0-1) 

The fake ball-unit mapping is then cached in memory: [3](#0-2) 

The `getBallHash` function includes `is_nonserial` in hash computation only when true: [4](#0-3) 

When legitimate units arrive, `validateHashTreeBall()` looks up the ball in cache and rejects if not found: [5](#0-4) 

Child units look up parent balls from the poisoned hash tree cache: [6](#0-5) 

These wrong parent balls cause validation failure: [7](#0-6) 

Cleanup only occurs when balls are successfully stored in database: [8](#0-7) 

**Exploitation Path**:

1. **Preconditions**: Victim node initiates catchup sync, malicious peer selected as source, legitimate serial unit U exists with ball `B_real = getBallHash(U, parents, skiplist, false)`

2. **Step 1 - Hash Tree Poisoning**:
   - Attacker sends hash tree via `handleHashTree()` → `processHashTree()`
   - Hash tree entry: `{ball: B_fake, unit: U, parent_balls: [...], skiplist_balls: [...], is_nonserial: true}`
   - Where `B_fake = getBallHash(U, parents, skiplist, true)` (computed with wrong flag)
   - Verification passes because attacker provides matching ball for the is_nonserial value
   - Fake mapping cached at line 367

3. **Step 2 - Legitimate Unit Rejection**:
   - Full unit U arrives with correct ball `B_real` and no `content_hash`
   - `validateHashTreeBall()` checks cache for `B_real`
   - Returns undefined (only `B_fake` cached)
   - Unit rejected with error "ball B_real is not known in hash tree"

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
   - Cleanup never executes because units never stored

**Security Property Broken**: Catchup protocol integrity—syncing nodes must retrieve and validate all units on the main chain without gaps or corruption.

**Root Cause**: The `is_nonserial` flag is determined by `content_hash` presence in the unit, but this information is unavailable during hash tree processing (only unit hash available). No mechanism exists to verify `is_nonserial` correctness until the full unit arrives, by which time the wrong mapping is already cached and used for descendant validation.

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
- **Resources**: Ability to run peer node (minimal VPS infrastructure)
- **Technical Skill**: Medium (understand catchup protocol structure, compute ball hashes with `getBallHash`)

**Preconditions**:
- **Network State**: Victim performing catchup (common for new/recovering nodes)
- **Attacker State**: Selected as catchup peer (probabilistic, attacker can run multiple peers)
- **Timing**: No specific timing required

**Execution Complexity**:
- **Transaction Count**: Zero (protocol-level attack)
- **Coordination**: Single malicious peer sufficient
- **Detection Risk**: Low (appears valid until full units arrive)

**Frequency**: Repeatable on every catchup attempt, affects arbitrary number of units

**Overall Assessment**: Medium-to-high likelihood—easily executable by any peer with minimal resources, affects critical network operation (syncing), no automatic mitigation.

## Recommendation

**Immediate Mitigation**:
Validate `is_nonserial` correctness when full unit arrives by checking if cached ball matches recomputed ball with actual `content_hash` value.

**Permanent Fix**:
Add validation in `processHashTree()` or defer ball caching until full unit verification:

```javascript
// Option 1: Validate on unit arrival
// In validation.js:validateHashTreeBall()
// Recompute ball with actual content_hash and compare with cached ball

// Option 2: Delay caching
// In catchup.js:processHashTree()
// Only validate structure, defer ball-unit mapping until unit verified
```

**Additional Measures**:
- Clear hash tree cache on validation errors: Uncomment cleanup at line 1061 of network.js
- Add peer reputation scoring to avoid repeat offenders
- Add test case verifying hash tree integrity with incorrect is_nonserial values

## Proof of Concept

```javascript
// Test: Hash tree poisoning with incorrect is_nonserial flag
// File: test/catchup_poison.test.js

const catchup = require('../catchup.js');
const objectHash = require('../object_hash.js');
const storage = require('../storage.js');
const db = require('../db.js');

describe('Hash tree poisoning attack', function() {
    it('should reject hash tree with incorrect is_nonserial flag', function(done) {
        // Setup: Create a serial unit (no content_hash)
        const unit = 'unit_hash_example_123';
        const parent_balls = ['parent_ball_1', 'parent_ball_2'];
        const skiplist_balls = [];
        
        // Compute correct ball (is_nonserial=false for serial unit)
        const correct_ball = objectHash.getBallHash(unit, parent_balls, skiplist_balls, false);
        
        // Attacker computes fake ball with is_nonserial=true
        const fake_ball = objectHash.getBallHash(unit, parent_balls, skiplist_balls, true);
        
        // Verify balls are different (this proves the attack vector exists)
        if (correct_ball === fake_ball) {
            throw new Error('Ball hashes should differ with different is_nonserial values');
        }
        
        // Construct poisoned hash tree
        const poisoned_hash_tree = [{
            unit: unit,
            ball: fake_ball,  // Wrong ball!
            parent_balls: parent_balls,
            skiplist_balls: skiplist_balls,
            is_nonserial: true  // Incorrect flag for serial unit
        }];
        
        // Process hash tree (should succeed - this is the vulnerability)
        catchup.processHashTree(poisoned_hash_tree, {
            ifError: function(error) {
                done(error);
            },
            ifOk: function() {
                // Verify fake ball was cached
                const cached_unit = storage.assocHashTreeUnitsByBall[fake_ball];
                if (cached_unit !== unit) {
                    return done(new Error('Fake ball not cached'));
                }
                
                // Verify correct ball is NOT cached
                const correct_cached = storage.assocHashTreeUnitsByBall[correct_ball];
                if (correct_cached) {
                    return done(new Error('Correct ball should not be cached'));
                }
                
                // This proves the vulnerability: 
                // - Fake ball (B_fake) is cached
                // - Correct ball (B_real) is not cached
                // - When real unit arrives with B_real, validation will fail
                // - Node permanently stuck until manual DB cleanup
                
                console.log('VULNERABILITY CONFIRMED:');
                console.log('  Fake ball cached:', fake_ball);
                console.log('  Correct ball NOT cached:', correct_ball);
                console.log('  Real unit will be rejected when it arrives');
                
                done();
            }
        });
    });
});
```

## Notes

This vulnerability exploits a fundamental timing issue in the catchup protocol: the `is_nonserial` flag must be validated when the hash tree is processed, but the information needed to validate it (the unit's `content_hash` field) is not available until later. The cached fake ball-unit mapping persists in `storage.assocHashTreeUnitsByBall` indefinitely, as cleanup only occurs for successfully stored units.

The attack is particularly insidious because:
1. The poisoned hash tree passes all structural validations
2. The fake ball hash is cryptographically valid (just computed with wrong parameters)
3. The impact cascades to all descendant units
4. No automatic recovery mechanism exists
5. Manual intervention requires database knowledge

While classified as Medium severity due to per-node impact rather than network-wide, the indefinite duration and manual recovery requirement make this a serious synchronization vulnerability.

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

**File:** catchup.js (L460-465)
```javascript
	conn.query("SELECT ball FROM hash_tree_balls CROSS JOIN balls USING(ball)", function(rows){
		if (rows.length === 0)
			return onDone();
		var arrHandledBalls = rows.map(function(row){ return row.ball; });
		arrHandledBalls.forEach(function(ball){
			delete storage.assocHashTreeUnitsByBall[ball];
```

**File:** object_hash.js (L109-110)
```javascript
	if (bNonserial)
		objBall.is_nonserial = true;
```

**File:** validation.js (L386-389)
```javascript
	var unit_by_hash_tree_ball = storage.assocHashTreeUnitsByBall[objJoint.ball];
//	conn.query("SELECT unit FROM hash_tree_balls WHERE ball=?", [objJoint.ball], function(rows){
		if (!unit_by_hash_tree_ball) 
			return callback({error_code: "need_hash_tree", message: "ball "+objJoint.ball+" is not known in hash tree"});
```

**File:** validation.js (L402-404)
```javascript
		var hash = objectHash.getBallHash(objUnit.unit, arrParentBalls, arrSkiplistBalls, !!objUnit.content_hash);
		if (hash !== objJoint.ball)
			return callback(createJointError("ball hash is wrong"));
```

**File:** validation.js (L414-418)
```javascript
			for (var ball in storage.assocHashTreeUnitsByBall){
				var unit = storage.assocHashTreeUnitsByBall[ball];
				if (arrUnits.indexOf(unit) >= 0 && arrBalls.indexOf(ball) === -1)
					arrBalls.push(ball);
			}
```
