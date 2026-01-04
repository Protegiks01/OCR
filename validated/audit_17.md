# Audit Report

## Title
Ball Hash Validation Bypass in Catchup Chain Processing Enables Synchronization Denial of Service

## Summary
The `processCatchupChain()` function in catchup.js validates unit hashes but omits cryptographic validation of ball hashes for stable joints, unlike proofchain and hash tree processing which properly validate ball hashes using `getBallHash()`. Malicious P2P peers can inject fabricated ball hashes that pass internal consistency checks, causing victim nodes to enter persistent retry loops when requesting non-existent hash trees from honest peers, preventing synchronization until manual database cleanup.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

**Affected Assets**: Node synchronization capability for catchup nodes

**Damage Severity**:
- Victim nodes cannot complete catchup synchronization indefinitely
- Attack persists across restarts (fabricated balls remain in `catchup_chain_balls` table)
- Only affects nodes performing catchup (new nodes or nodes recovering from downtime)
- No fund loss or impact on already-synchronized nodes
- Requires manual database cleanup: `DELETE FROM catchup_chain_balls`

**User Impact**:
- **Who**: Full nodes performing catchup synchronization after being offline or during initial sync
- **Conditions**: Must select malicious peer for catchup response
- **Recovery**: Manual database intervention required

## Finding Description

**Location**: `byteball/ocore/catchup.js:173-191`, function `processCatchupChain()`

**Intended Logic**: Catchup chains should cryptographically validate ball hashes by computing `getBallHash(unit, parent_balls, skiplist_balls, is_nonserial)` and comparing against received values, ensuring all ball references are verifiable and retrievable from honest network peers.

**Actual Logic**: The function validates unit hashes via `hasValidHashes()` and checks internal consistency (current ball matches previous `last_ball` field), but never cryptographically validates that `last_ball` field values actually match `getBallHash()` computation, unlike proofchain and hash tree processing.

**Code Evidence:**

The `hasValidHashes()` function only validates unit hash, not ball hash: [1](#0-0) 

Catchup stable joint processing validates unit hash but blindly trusts `last_ball` fields without cryptographic verification: [2](#0-1) 

In contrast, proofchain balls ARE cryptographically validated using `getBallHash()`: [3](#0-2) 

Hash tree balls are also cryptographically validated using `getBallHash()`: [4](#0-3) 

The source of unvalidated balls comes from `processWitnessProof()` which builds the mapping from unstable MC joints' `last_ball` fields without validation: [5](#0-4) 

Unvalidated balls are stored for future hash tree requests: [6](#0-5) 

**Exploitation Path:**

1. **Preconditions**: 
   - Victim node behind network state initiates catchup
   - Attacker operates P2P peer node
   - Catchup request sent to attacker's peer: [7](#0-6) 

2. **Step 1**: Victim sends catchup request with witness list and MCI range

3. **Step 2**: Attacker crafts malicious catchup response containing:
   - Units with valid unit hashes (pass `hasValidHashes()` check)
   - Arbitrary `last_ball` and `last_ball_unit` fields not matching `getBallHash()` computation
   - `objJoint.ball` values matching the arbitrary `last_ball` values (internally consistent)
   - First ball as genesis or victim's last known stable ball (passes validation)

4. **Step 3**: Victim processes catchup chain via `processCatchupChain()`: [8](#0-7) 
   - Unit hash validation passes (line 180)
   - Internal consistency checks pass (lines 184-185: current ball matches previous last_ball)
   - No validation that `last_ball = getBallHash(last_ball_unit, ...)`
   - Fabricated balls stored in `catchup_chain_balls` table

5. **Step 4**: Victim requests hash trees using fabricated balls: [9](#0-8) 

6. **Step 5**: Honest peers query for fabricated balls and return error: [10](#0-9) 

7. **Step 6**: Error triggers retry loop with 100ms intervals: [11](#0-10) 
   
   The retry mechanism continues indefinitely: [12](#0-11) 

8. **Result**: Persistent retry as all honest peers lack fabricated balls. No automatic cleanup mechanism exists for failed catchup attempts.

**Security Property Broken**: 
- **Ball Hash Integrity**: All ball hashes must be cryptographically verifiable using `getBallHash()` and retrievable from honest network peers
- **Catchup Completeness**: Syncing nodes must complete synchronization without manual intervention under normal network conditions

**Root Cause Analysis**: 
Inconsistent validation - proofchain balls and hash tree balls are cryptographically validated using `getBallHash()`, but stable joint balls in catchup chains are only validated for unit hash correctness and internal consistency. The `last_ball` field from units is user-controlled data that flows through `processWitnessProof()` into `assocLastBallByLastBallUnit` without cryptographic validation, allowing injection of internally consistent but cryptographically incorrect ball references.

## Impact Explanation

**Affected Assets**: Node synchronization capability

**Damage Severity**:
- **Quantitative**: Victim nodes enter indefinite retry loop. Attack persists across node restarts. Multiple syncing nodes can be affected if attacker operates well-connected peer(s).
- **Qualitative**: Temporary DoS affecting only catchup nodes. Prevents network growth and recovery from outages. No cascade to already-synchronized nodes.

**User Impact**:
- **Who**: New nodes or nodes recovering from downtime performing catchup synchronization
- **Conditions**: Must randomly select malicious peer for catchup response
- **Recovery**: Requires manual database cleanup via `DELETE FROM catchup_chain_balls` statement

**Systemic Risk**: During network partitions or high node churn, multiple syncing nodes vulnerable simultaneously. No impact on operational nodes. Can delay network recovery if attacker controls popular peers.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: P2P network peer operator (untrusted actor within threat model)
- **Resources Required**: Single peer node capable of responding to catchup protocol requests
- **Technical Skill**: Medium - requires understanding catchup protocol, unit structure, and ability to craft internally consistent but cryptographically invalid ball references

**Preconditions**:
- **Network State**: Victim must be behind current network state and initiate catchup
- **Attacker Position**: Victim must select attacker's peer for catchup response
- **First Ball Constraint**: Must use genesis or victim's last known stable ball as starting point

**Execution Complexity**:
- **Transaction Count**: Single catchup response message
- **Coordination**: None required
- **Detection Risk**: Low during attack (appears as normal catchup failure)

**Frequency**:
- **Repeatability**: High - attack persists in victim database across restarts
- **Scale**: Per-victim - each syncing node can be independently targeted

**Overall Assessment**: Medium likelihood - requires victim to select malicious peer, but attack has minimal cost, low technical barrier, and high persistence once successful.

## Recommendation

**Immediate Mitigation**:
Add cryptographic ball hash validation in `processCatchupChain()` for stable joints, consistent with proofchain and hash tree validation:

```javascript
// File: byteball/ocore/catchup.js
// In processCatchupChain(), stable joints loop at lines 173-191

if (objUnit.last_ball_unit) {
    // Read parent balls and skiplist balls for last_ball_unit
    // Compute expected ball hash using getBallHash()
    // Verify objUnit.last_ball matches computed hash
    // Reject catchup chain if mismatch
}
```

**Permanent Fix**:
Refactor catchup chain validation to use consistent cryptographic verification for all ball types (proofchain, hash tree, and stable joints) using `objectHash.getBallHash()`.

**Additional Measures**:
- Add database cleanup on catchup failure after timeout
- Add monitoring to detect catchup retry loops
- Add test case verifying fabricated ball hashes are rejected

**Validation**:
- Fix prevents fabricated ball hashes from entering catchup_chain_balls table
- Maintains backward compatibility with honest peers
- Performance impact minimal (additional getBallHash() calls only during catchup)

## Notes

This is a **valid Medium severity vulnerability** per Immunefi Obyte scope (Temporary Transaction Delay ≥1 Hour). The vulnerability stems from inconsistent validation patterns where proofchain and hash tree balls receive cryptographic validation, but stable joint balls in catchup chains do not. This allows malicious peers to inject fabricated ball references that pass internal consistency checks but cannot be resolved by honest network peers, causing indefinite synchronization failure for catchup nodes.

The attack is realistic and exploitable by any P2P peer operator with minimal technical sophistication. While impact is limited to nodes performing catchup (no fund loss or impact on synchronized nodes), the persistence of the attack across restarts and lack of automatic recovery mechanisms justifies Medium severity classification.

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

**File:** catchup.js (L110-130)
```javascript
function processCatchupChain(catchupChain, peer, arrWitnesses, callbacks){
	if (catchupChain.status === "current")
		return callbacks.ifCurrent();
	if (!Array.isArray(catchupChain.unstable_mc_joints))
		return callbacks.ifError("no unstable_mc_joints");
	if (!Array.isArray(catchupChain.stable_last_ball_joints))
		return callbacks.ifError("no stable_last_ball_joints");
	if (catchupChain.stable_last_ball_joints.length === 0)
		return callbacks.ifError("stable_last_ball_joints is empty");
	if (!catchupChain.witness_change_and_definition_joints)
		catchupChain.witness_change_and_definition_joints = [];
	if (!Array.isArray(catchupChain.witness_change_and_definition_joints))
		return callbacks.ifError("witness_change_and_definition_joints must be array");
	if (!catchupChain.proofchain_balls)
		catchupChain.proofchain_balls = [];
	if (!Array.isArray(catchupChain.proofchain_balls))
		return callbacks.ifError("proofchain_balls must be array");
	
	witnessProof.processWitnessProof(
		catchupChain.unstable_mc_joints, catchupChain.witness_change_and_definition_joints, true, arrWitnesses,
		function(err, arrLastBallUnits, assocLastBallByLastBallUnit){
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

**File:** catchup.js (L241-245)
```javascript
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

**File:** catchup.js (L363-364)
```javascript
							if (objBall.ball !== objectHash.getBallHash(objBall.unit, objBall.parent_balls, objBall.skiplist_balls, objBall.is_nonserial))
								return cb("wrong ball hash, ball "+objBall.ball+", unit "+objBall.unit);
```

**File:** witness_proof.js (L189-192)
```javascript
		if (objUnit.last_ball_unit && arrFoundWitnesses.length >= constants.MAJORITY_OF_WITNESSES){
			arrLastBallUnits.push(objUnit.last_ball_unit);
			assocLastBallByLastBallUnit[objUnit.last_ball_unit] = objUnit.last_ball;
		}
```

**File:** network.js (L1975-1983)
```javascript
					storage.readLastStableMcIndex(db, function(last_stable_mci){
						storage.readLastMainChainIndex(function(last_known_mci){
							myWitnesses.readMyWitnesses(function(arrWitnesses){
								var params = {witnesses: arrWitnesses, last_stable_mci: last_stable_mci, last_known_mci: last_known_mci};
								sendRequest(ws, 'catchup', params, true, handleCatchupChain);
							}, 'wait');
						});
					});
				});
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

**File:** network.js (L2042-2060)
```javascript
function handleHashTree(ws, request, response){
	if (response.error){
		console.log('get_hash_tree got error response: '+response.error);
		waitTillHashTreeFullyProcessedAndRequestNext(ws); // after 1 sec, it'll request the same hash tree, likely from another peer
		return;
	}
	console.log('received hash tree from '+ws.peer);
	var hashTree = response;
	catchup.processHashTree(hashTree.balls, {
		ifError: function(error){
			sendError(ws, error);
			waitTillHashTreeFullyProcessedAndRequestNext(ws); // after 1 sec, it'll request the same hash tree, likely from another peer
		},
		ifOk: function(){
			requestNewMissingJoints(ws, hashTree.balls.map(function(objBall){ return objBall.unit; }));
			waitTillHashTreeFullyProcessedAndRequestNext(ws);
		}
	});
}
```

**File:** network.js (L2075-2088)
```javascript
function waitTillHashTreeFullyProcessedAndRequestNext(ws){
	setTimeout(function(){
	//	db.query("SELECT COUNT(*) AS count FROM hash_tree_balls LEFT JOIN units USING(unit) WHERE units.unit IS NULL", function(rows){
		//	var count = Object.keys(storage.assocHashTreeUnitsByBall).length;
			if (!haveManyUnhandledHashTreeBalls()){
				findNextPeer(ws, function(next_ws){
					requestNextHashTree(next_ws);
				});
			}
			else
				waitTillHashTreeFullyProcessedAndRequestNext(ws);
	//	});
	}, 100);
}
```
