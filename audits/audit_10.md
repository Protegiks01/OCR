# Audit Report

## Title
Ball Hash Validation Bypass in Catchup Chain Processing Enables Denial of Service

## Summary
The `processCatchupChain()` function in `catchup.js` validates unit hashes but never computes or verifies ball hashes for stable joints in catchup chains. An attacker can send internally consistent but incorrectly computed ball hashes, which get stored in the database and cause the victim node to repeatedly request non-existent hash trees from honest peers, preventing synchronization until manual intervention.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

**Affected Assets**: Node synchronization capability, network participation for syncing nodes

**Damage Severity**:
- **Quantitative**: Victim node unable to complete synchronization until `catchup_chain_balls` table is manually cleared or node restarts and connects to honest peer. Attack can persist for hours or days.
- **Qualitative**: Temporary denial of service affecting only syncing nodes. No fund loss or permanent network damage.

**User Impact**:
- **Who**: Any full node attempting to catch up from behind (newly started nodes, nodes that were offline, nodes recovering from network partition)
- **Conditions**: Node must request catchup from a malicious peer that responds first
- **Recovery**: Manual database cleanup (`DELETE FROM catchup_chain_balls`) or node restart with connection to honest peer required

**Systemic Risk**: During network partitions or high node churn, multiple nodes syncing simultaneously could be affected if attacker operates popular peer node.

## Finding Description

**Location**: `byteball/ocore/catchup.js`, function `processCatchupChain()`, lines 173-191

**Intended Logic**: The catchup mechanism should validate that all received ball hashes are correctly computed from `getBallHash(unit, parent_balls, skiplist_balls, is_nonserial)` before storing them. This ensures the catchup chain represents valid, retrievable history.

**Actual Logic**: The function only validates unit hashes via `hasValidHashes()` and checks ball consistency (each ball matches the previous unit's `last_ball` field), but never computes or validates the actual ball hash value. The `last_ball` field itself is user-controlled and unvalidated during catchup.

**Code Evidence**:

The validation function only checks unit hash, not ball hash: [1](#0-0) 

The catchup processing loop validates unit hashes but not ball hashes: [2](#0-1) 

The proper ball hash validation function exists but is never called during catchup: [3](#0-2) 

In contrast, proofchain balls ARE properly validated with `getBallHash()`: [4](#0-3) 

**Exploitation Path**:

1. **Preconditions**: 
   - Victim node is behind and needs to sync
   - Attacker operates a peer node that can respond to catchup requests
   - Attacker knows valid unit structures and witness lists

2. **Step 1**: Victim requests catchup
   - Victim sends catchup request to peers with `{witnesses, last_stable_mci, last_known_mci}` [5](#0-4) 

3. **Step 2**: Attacker crafts malicious catchup chain
   - Creates valid units with correct unit hashes (computed via `getUnitHash()`)
   - Sets arbitrary `last_ball` and `last_ball_unit` fields in unit data
   - Sets `objJoint.ball` to match these arbitrary values (internally consistent)
   - Ball hashes don't match `getBallHash(unit, parent_balls, skiplist_balls)` computation
   - First ball must be genesis or already known by victim to pass initial check

4. **Step 3**: Victim processes catchup chain
   - `processCatchupChain()` validates unit hashes only (line 180)
   - Ball consistency checks pass because attacker made them match (line 184-188)
   - Incorrect ball hashes stored in `catchup_chain_balls` table (line 242-245) [6](#0-5) 

5. **Step 4**: Victim attempts hash tree request
   - Victim queries first two balls from `catchup_chain_balls` [7](#0-6) 
   - Sends `get_hash_tree` request with non-existent ball hashes
   - Honest peers check database for these balls and return error [8](#0-7) 
   - Error handling causes retry after delay [9](#0-8) 
   - Same incorrect balls remain in table, causing infinite retry loop
   - Catchup stalls indefinitely until manual intervention

**Security Property Broken**: 
- **Last Ball Chain Integrity**: The last ball chain must consist of correctly computed ball hashes that can be verified and retrieved from the network
- **Catchup Completeness**: Syncing nodes must be able to retrieve all necessary data to complete synchronization without manual intervention

**Root Cause Analysis**: 
The catchup protocol trusts that ball hashes in catchup chains are correct without verification. While proofchain balls receive proper validation (line 145), stable joints in `stable_last_ball_joints` only have their unit hashes validated. The code assumes internal consistency (ball matching previous last_ball) implies correctness, but an attacker can create internally consistent chains with incorrect ball hashes. The validation function `validateHashTreeParentsAndSkiplist()` exists for proper ball hash validation but is only called during full unit validation after storage, not during catchup chain processing.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Operator of peer node in P2P network
- **Resources Required**: Running one or more peer nodes that respond to catchup requests
- **Technical Skill**: Medium - requires understanding catchup protocol format, ability to construct valid unit structures with correct unit hashes but arbitrary ball values

**Preconditions**:
- **Network State**: Victim node must be behind current network state (new node, offline node, network partition recovery)
- **Attacker State**: Must be connected as peer and selected/respond first for catchup request
- **Timing**: Opportunistic - triggered whenever victim falls behind

**Execution Complexity**:
- **Transaction Count**: Single catchup response message containing crafted chain
- **Coordination**: None required - single peer can execute
- **Detection Risk**: Low - appears as normal catchup response, failure only becomes apparent during hash tree request phase

**Frequency**:
- **Repeatability**: Unlimited - can be repeated on every catchup attempt if attacker continues responding
- **Scale**: Can affect multiple victims if attacker operates popular peer node

**Overall Assessment**: Medium likelihood - requires victim to select malicious peer for catchup, but attack has low cost, low technical barrier, and is repeatable.

## Recommendation

**Immediate Mitigation**:
Validate ball hashes during catchup chain processing before storing in `catchup_chain_balls` table.

**Permanent Fix**:
Add ball hash validation to `processCatchupChain()` for stable joints, similar to existing proofchain validation:

```javascript
// In catchup.js, within the stable joints loop (after line 180)
// Validate ball hash is correctly computed
if (!storage.isGenesisUnit(objUnit.unit) && objUnit.parent_units) {
    storage.readBallsByUnits(db, objUnit.parent_units, function(arrParentBalls) {
        var computed_ball;
        if (objJoint.skiplist_units) {
            storage.readBallsByUnits(db, objJoint.skiplist_units, function(arrSkiplistBalls) {
                computed_ball = objectHash.getBallHash(objUnit.unit, arrParentBalls, arrSkiplistBalls, !!objUnit.content_hash);
                if (computed_ball !== objJoint.ball)
                    return callbacks.ifError("ball hash mismatch for unit " + objUnit.unit);
            });
        } else {
            computed_ball = objectHash.getBallHash(objUnit.unit, arrParentBalls, [], !!objUnit.content_hash);
            if (computed_ball !== objJoint.ball)
                return callbacks.ifError("ball hash mismatch for unit " + objUnit.unit);
        }
    });
}
```

**Additional Measures**:
- Add test case verifying catchup chains with incorrect ball hashes are rejected
- Add monitoring for repeated catchup failures from same peer
- Consider rate limiting catchup requests to mitigate DoS impact

**Validation**:
- Fix prevents storage of incorrect ball hashes in catchup_chain_balls
- Malicious peers identified by repeated catchup failures
- No impact on performance for honest catchup chains
- Backward compatible with existing protocol

## Proof of Concept

```javascript
// Test: test/catchup_ball_validation.test.js
// Demonstrates that processCatchupChain accepts invalid ball hashes

const catchup = require('../catchup.js');
const validation = require('../validation.js');
const objectHash = require('../object_hash.js');
const db = require('../db.js');

describe('Catchup ball hash validation', function() {
    
    it('should reject catchup chain with invalid ball hashes', function(done) {
        
        // Create a valid unit structure
        const validUnit = {
            unit: 'VALID_UNIT_HASH',
            version: '1.0',
            alt: '1',
            authors: [{ address: 'AUTHOR_ADDRESS', authentifiers: {r: 'sig'} }],
            messages: [{ app: 'text', payload: 'test' }],
            parent_units: ['PARENT_UNIT'],
            last_ball: 'ARBITRARY_BALL_HASH',  // Attacker-controlled
            last_ball_unit: 'LAST_BALL_UNIT',
            headers_commission: 344,
            payload_commission: 157
        };
        
        // Compute correct unit hash
        validUnit.unit = objectHash.getUnitHash(validUnit);
        
        // Create joint with INCORRECT ball hash
        const maliciousJoint = {
            unit: validUnit,
            ball: 'INCORRECT_BALL_HASH'  // Does not match getBallHash()
        };
        
        // Verify unit hash is valid
        assert(validation.hasValidHashes(maliciousJoint));
        
        // Create catchup chain
        const catchupChain = {
            status: 'ok',
            unstable_mc_joints: [],
            stable_last_ball_joints: [maliciousJoint],
            witness_change_and_definition_joints: [],
            proofchain_balls: []
        };
        
        // Process catchup chain - should reject but currently accepts
        catchup.processCatchupChain(catchupChain, 'malicious_peer', witnessArr, {
            ifError: function(error) {
                // Should reach here with ball validation error
                assert(error.includes('ball hash'));
                done();
            },
            ifOk: function() {
                // Currently reaches here - VULNERABILITY
                db.query("SELECT * FROM catchup_chain_balls WHERE ball=?", 
                    ['INCORRECT_BALL_HASH'], 
                    function(rows) {
                        assert(rows.length > 0);  // Incorrect ball was stored!
                        done(new Error('Catchup accepted invalid ball hash'));
                    }
                );
            }
        });
    });
});
```

**Notes**

This vulnerability affects only the catchup synchronization path, not normal unit validation. The issue arises because catchup chains transmit `{unit, ball}` pairs without the `parent_balls` and `skiplist_balls` data needed to compute ball hashes. The code assumes ball values are correct if they're internally consistent, but an attacker can craft consistent chains with arbitrary ball values.

The proper validation function `validateHashTreeParentsAndSkiplist()` exists and is used during normal unit validation after units are stored, but catchup processing stores balls before this validation occurs. This creates a window where invalid balls can enter the `catchup_chain_balls` table.

The impact is limited to DoS of syncing nodes - no funds can be stolen and the network continues operating normally for synchronized nodes. However, it can significantly delay network recovery during high churn periods or after network partitions.

### Citations

**File:** validation.js (L38-49)
```javascript
function hasValidHashes(objJoint){
	var objUnit = objJoint.unit;
	try {
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return false;
	}
	catch(e){
		console.log("failed to calc unit hash: "+e);
		return false;
	}
	return true;
}
```

**File:** validation.js (L396-435)
```javascript
function validateHashTreeParentsAndSkiplist(conn, objJoint, callback){
	if (!objJoint.ball)
		return callback();
	var objUnit = objJoint.unit;
	
	function validateBallHash(arrParentBalls, arrSkiplistBalls){
		var hash = objectHash.getBallHash(objUnit.unit, arrParentBalls, arrSkiplistBalls, !!objUnit.content_hash);
		if (hash !== objJoint.ball)
			return callback(createJointError("ball hash is wrong"));
		callback();
	}
	
	function readBallsByUnits(arrUnits, handleList){
		conn.query("SELECT ball FROM balls WHERE unit IN(?) ORDER BY ball", [arrUnits], function(rows){
			var arrBalls = rows.map(function(row){ return row.ball; });
			if (arrBalls.length === arrUnits.length)
				return handleList(arrBalls);
			// we have to check in hash_tree_balls too because if we were synced, went offline, and now starting to catch up, our parents will have no ball yet
			for (var ball in storage.assocHashTreeUnitsByBall){
				var unit = storage.assocHashTreeUnitsByBall[ball];
				if (arrUnits.indexOf(unit) >= 0 && arrBalls.indexOf(ball) === -1)
					arrBalls.push(ball);
			}
			arrBalls.sort();
			handleList(arrBalls);
		});
	}
	
	readBallsByUnits(objUnit.parent_units, function(arrParentBalls){
		if (arrParentBalls.length !== objUnit.parent_units.length)
			return callback(createJointError("some parents not found in balls nor in hash tree")); // while the child is found in hash tree
		if (!objJoint.skiplist_units)
			return validateBallHash(arrParentBalls, []);
		readBallsByUnits(objJoint.skiplist_units, function(arrSkiplistBalls){
			if (arrSkiplistBalls.length !== objJoint.skiplist_units.length)
				return callback(createJointError("some skiplist balls not found"));
			validateBallHash(arrParentBalls, arrSkiplistBalls);
		});
	});
}
```

**File:** catchup.js (L143-146)
```javascript
				for (var i=0; i<catchupChain.proofchain_balls.length; i++){
					var objBall = catchupChain.proofchain_balls[i];
					if (objBall.ball !== objectHash.getBallHash(objBall.unit, objBall.parent_balls, objBall.skiplist_balls, objBall.is_nonserial))
						return callbacks.ifError("wrong ball hash: unit "+objBall.unit+", ball "+objBall.ball);
```

**File:** catchup.js (L173-191)
```javascript
			// stable joints
			var arrChainBalls = [];
			for (var i=0; i<catchupChain.stable_last_ball_joints.length; i++){
				var objJoint = catchupChain.stable_last_ball_joints[i];
				var objUnit = objJoint.unit;
				if (!objJoint.ball)
					return callbacks.ifError("stable but no ball");
				if (!validation.hasValidHashes(objJoint))
					return callbacks.ifError("invalid hash");
				if (objUnit.unit !== last_ball_unit)
					return callbacks.ifError("not the last ball unit");
				if (objJoint.ball !== last_ball)
					return callbacks.ifError("not the last ball");
				if (objUnit.last_ball_unit){
					last_ball_unit = objUnit.last_ball_unit;
					last_ball = objUnit.last_ball;
				}
				arrChainBalls.push(objJoint.ball);
			}
```

**File:** catchup.js (L240-245)
```javascript
				},
				function(cb){ // validation complete, now write the chain for future downloading of hash trees
					var arrValues = arrChainBalls.map(function(ball){ return "("+db.escape(ball)+")"; });
					db.query("INSERT INTO catchup_chain_balls (ball) VALUES "+arrValues.join(', '), function(){
						cb();
					});
```

**File:** catchup.js (L268-273)
```javascript
	db.query(
		"SELECT is_stable, is_on_main_chain, main_chain_index, ball FROM balls JOIN units USING(unit) WHERE ball IN(?,?)", 
		[from_ball, to_ball], 
		function(rows){
			if (rows.length !== 2)
				return callbacks.ifError("some balls not found");
```

**File:** network.js (L1975-1979)
```javascript
					storage.readLastStableMcIndex(db, function(last_stable_mci){
						storage.readLastMainChainIndex(function(last_known_mci){
							myWitnesses.readMyWitnesses(function(arrWitnesses){
								var params = {witnesses: arrWitnesses, last_stable_mci: last_stable_mci, last_known_mci: last_known_mci};
								sendRequest(ws, 'catchup', params, true, handleCatchupChain);
```

**File:** network.js (L2018-2040)
```javascript
function requestNextHashTree(ws){
	eventBus.emit('catchup_next_hash_tree');
	db.query("SELECT ball FROM catchup_chain_balls ORDER BY member_index LIMIT 2", function(rows){
		if (rows.length === 0)
			return comeOnline();
		if (rows.length === 1){
			db.query("DELETE FROM catchup_chain_balls WHERE ball=?", [rows[0].ball], function(){
				comeOnline();
			});
			return;
		}
		var from_ball = rows[0].ball;
		var to_ball = rows[1].ball;
		
		// don't send duplicate requests
		for (var tag in ws.assocPendingRequests)
			if (ws.assocPendingRequests[tag].request.command === 'get_hash_tree'){
				console.log("already requested hash tree from this peer");
				return;
			}
		sendRequest(ws, 'get_hash_tree', {from_ball: from_ball, to_ball: to_ball}, true, handleHashTree);
	});
}
```

**File:** network.js (L2042-2046)
```javascript
function handleHashTree(ws, request, response){
	if (response.error){
		console.log('get_hash_tree got error response: '+response.error);
		waitTillHashTreeFullyProcessedAndRequestNext(ws); // after 1 sec, it'll request the same hash tree, likely from another peer
		return;
```
