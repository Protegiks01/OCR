# Audit Report

## Title
Ball Hash Validation Bypass in Catchup Chain Processing Enables Denial of Service

## Summary
The `processCatchupChain()` function validates unit hashes but never verifies ball hashes for stable joints in catchup chains. This allows malicious peers to inject internally consistent but incorrectly computed ball hashes, causing victim nodes to endlessly retry failed hash tree requests, preventing synchronization until manual database intervention.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

Syncing nodes become unable to complete catchup when receiving fabricated ball hashes from malicious peers. The attack causes indefinite retry loops as victims request non-existent hash trees from honest peers. Recovery requires manual database cleanup (`DELETE FROM catchup_chain_balls`) or node restart with connection to different peers, potentially lasting hours or days.

**Affected**: All full nodes attempting catchup synchronization (new nodes, offline nodes, post-partition recovery)

## Finding Description

**Location**: `byteball/ocore/catchup.js`, function `processCatchupChain()`, lines 173-191

**Intended Logic**: Catchup chains should validate that received ball hashes match the cryptographic computation `getBallHash(unit, parent_balls, skiplist_balls, is_nonserial)` before storage, ensuring retrievability from the network.

**Actual Logic**: The function only validates unit hashes via `hasValidHashes()` and checks internal consistency (each ball matches previous `last_ball` field), but never computes or validates actual ball hash values. The `last_ball` field itself is user-controlled and unvalidated.

**Code Evidence**:

The validation function only checks unit hash, not ball hash: [1](#0-0) 

The catchup processing validates unit hashes but not ball hashes at line 180, and updates last_ball from unvalidated user fields at lines 186-189: [2](#0-1) 

In contrast, proofchain balls ARE properly validated with `getBallHash()`: [3](#0-2) 

Unvalidated balls get stored in the database: [4](#0-3) 

**Exploitation Path**:

1. **Preconditions**: 
   - Victim node behind network state, needs catchup
   - Attacker operates peer node responding to catchup requests

2. **Step 1**: Victim requests catchup with witness list and MCI range: [5](#0-4) 

3. **Step 2**: Attacker crafts malicious catchup chain
   - Creates valid units with correct unit hashes (via `getUnitHash()`)
   - Sets arbitrary `last_ball` and `last_ball_unit` fields
   - Sets `objJoint.ball` to match these arbitrary values (internally consistent)
   - Ball hashes don't match `getBallHash()` computation
   - First ball must be genesis or known by victim

4. **Step 3**: Victim processes and stores fabricated balls
   - Unit hash validation passes (line 180)
   - Internal consistency checks pass (lines 184-188)
   - Incorrect balls stored in `catchup_chain_balls` (lines 242-245)

5. **Step 4**: Victim requests hash tree with non-existent balls [6](#0-5) 

6. **Step 5**: Honest peers reject request as balls don't exist: [7](#0-6) 

7. **Step 6**: Error triggers retry after delay, cycling through peers endlessly: [8](#0-7) [9](#0-8) 

**Security Property Broken**: 
- **Last Ball Chain Integrity**: Ball hashes must be cryptographically correct and retrievable from network
- **Catchup Completeness**: Syncing nodes must complete synchronization without manual intervention

**Root Cause**: The catchup protocol trusts ball hash correctness through internal consistency rather than cryptographic validation. While proofchain receives proper validation, stable joints only validate unit hashes, allowing attackers to create internally consistent chains with fabricated ball hashes.

## Impact Explanation

**Affected Assets**: Node synchronization capability, network participation

**Damage Severity**:
- **Quantitative**: Victim unable to sync until manual intervention. Attack persists across restarts as fabricated balls remain in database. Multiple nodes affected if attacker operates popular peer.
- **Qualitative**: Temporary DoS affecting only syncing nodes. No fund loss or permanent network damage.

**User Impact**:
- **Who**: Full nodes catching up from behind
- **Conditions**: Must request catchup from malicious peer
- **Recovery**: Manual database cleanup or restart with honest peer connection

**Systemic Risk**: During network partitions or high node churn, multiple syncing nodes vulnerable if attacker operates well-connected peer.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: P2P network peer operator
- **Resources**: Single peer node responding to catchup requests
- **Technical Skill**: Medium - requires understanding catchup protocol and unit structure

**Preconditions**:
- Victim must be behind and initiate catchup
- Attacker must be selected for catchup response

**Execution Complexity**:
- Single catchup response message
- No coordination required
- Low detection risk

**Overall Assessment**: Medium likelihood - requires victim to select malicious peer, but attack has low cost, low barrier, and is repeatable.

## Recommendation

**Immediate Mitigation**:
Add ball hash validation to `processCatchupChain()` for stable joints:

```javascript
// In catchup.js, function processCatchupChain(), add after line 180:
if (objJoint.ball !== objectHash.getBallHash(objUnit.unit, 
    objUnit.parent_balls, objUnit.skiplist_balls, objUnit.content_hash ? true : false))
    return callbacks.ifError("invalid ball hash");
```

**Additional Measures**:
- Add test case verifying catchup chain with incorrect ball hashes is rejected
- Add monitoring for repeated hash tree request failures
- Document that catchup_chain_balls may need manual cleanup after attack

## Proof of Concept

Due to the complexity of mocking the P2P catchup protocol, a full runnable PoC would require extensive test infrastructure. The vulnerability is demonstrated through code analysis:

1. Unit hash validation exists but ball hash validation is absent in stable joint processing
2. Proofchain validation (line 145) shows the correct validation pattern using `getBallHash()`
3. This pattern is never applied to stable joints (lines 173-191)
4. The retry mechanism (lines 2043-2087) creates indefinite loops for non-existent balls

The fix is straightforward: apply the same `getBallHash()` validation used for proofchain balls to stable joints during catchup processing.

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

**File:** network.js (L1975-1979)
```javascript
					storage.readLastStableMcIndex(db, function(last_stable_mci){
						storage.readLastMainChainIndex(function(last_known_mci){
							myWitnesses.readMyWitnesses(function(arrWitnesses){
								var params = {witnesses: arrWitnesses, last_stable_mci: last_stable_mci, last_known_mci: last_known_mci};
								sendRequest(ws, 'catchup', params, true, handleCatchupChain);
```

**File:** network.js (L2018-2038)
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
```

**File:** network.js (L2042-2046)
```javascript
function handleHashTree(ws, request, response){
	if (response.error){
		console.log('get_hash_tree got error response: '+response.error);
		waitTillHashTreeFullyProcessedAndRequestNext(ws); // after 1 sec, it'll request the same hash tree, likely from another peer
		return;
```

**File:** network.js (L2075-2087)
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
```
