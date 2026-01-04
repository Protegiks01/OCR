# Audit Report

## Title
Ball Hash Validation Bypass in Catchup Chain Processing Enables Synchronization Denial of Service

## Summary
The `processCatchupChain()` function in `catchup.js` validates unit hashes but omits cryptographic validation of ball hashes for stable joints, unlike proofchain and hash tree processing which properly validate ball hashes using `getBallHash()`. Malicious P2P peers can inject fabricated ball hashes that pass internal consistency checks, causing victim nodes to enter endless retry loops when requesting non-existent hash trees from honest peers, preventing synchronization until manual database cleanup.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

**Affected Assets**: Node synchronization capability, network participation for new/recovering nodes

**Damage Severity**:
- **Quantitative**: Victim nodes cannot complete catchup synchronization. Attack persists across restarts as fabricated balls remain in `catchup_chain_balls` table. Multiple nodes can be affected if attacker operates well-connected peer.
- **Qualitative**: Temporary DoS affecting only nodes performing catchup (new nodes, nodes recovering from downtime). No fund loss or impact on already-synchronized nodes, but prevents network growth and recovery from outages.

**User Impact**:
- **Who**: Full nodes performing catchup synchronization after being offline or during initial sync
- **Conditions**: Must randomly select malicious peer for catchup response
- **Recovery**: Requires manual database cleanup (`DELETE FROM catchup_chain_balls`) or reconnection to different peer set

**Systemic Risk**: During network partitions or high node churn, multiple syncing nodes vulnerable. No cascade to synchronized nodes. Can delay network recovery if attacker controls popular peers.

## Finding Description

**Location**: `byteball/ocore/catchup.js:173-191`, function `processCatchupChain()`

**Intended Logic**: Catchup chains should cryptographically validate ball hashes by computing `getBallHash(unit, parent_balls, skiplist_balls, is_nonserial)` and comparing against received values, ensuring hash trees are retrievable from honest peers.

**Actual Logic**: The function validates unit hashes via `hasValidHashes()` and checks internal consistency (current ball matches previous `last_ball` field), but never cryptographically validates that `last_ball` field values match `getBallHash()` computation.

**Code Evidence**:

The `hasValidHashes()` function only validates unit hash: [1](#0-0) 

Catchup stable joint processing validates unit hash but blindly trusts `last_ball` fields: [2](#0-1) 

In contrast, proofchain balls ARE cryptographically validated: [3](#0-2) 

Hash tree balls are also cryptographically validated: [4](#0-3) 

Unvalidated balls are stored for future hash tree requests: [5](#0-4) 

**Exploitation Path**:

1. **Preconditions**: 
   - Victim node behind network state initiates catchup
   - Attacker operates P2P peer node
   - Catchup request sent to attacker's peer: [6](#0-5) 

2. **Step 1**: Victim sends catchup request with witness list and MCI range

3. **Step 2**: Attacker crafts malicious catchup response containing:
   - Units with valid unit hashes (pass `hasValidHashes()` check at line 180)
   - Arbitrary `last_ball` and `last_ball_unit` fields not matching `getBallHash()` computation
   - `objJoint.ball` values matching the arbitrary `last_ball` values (internally consistent)
   - First ball as genesis or victim's last known stable ball (passes validation at lines 163-170)

4. **Step 3**: Victim processes catchup chain:
   - Unit hash validation passes (line 180)
   - Internal consistency checks pass (lines 184-185: current ball matches previous last_ball)
   - No validation that `last_ball = getBallHash(last_ball_unit, ...)`
   - Fabricated balls stored in `catchup_chain_balls` table (lines 242-245)

5. **Step 4**: Victim requests hash trees using fabricated balls: [7](#0-6) 

6. **Step 5**: Honest peers query for fabricated balls and return error: [8](#0-7) 

7. **Step 6**: Error triggers retry loop with 100ms intervals: [9](#0-8) [10](#0-9) 

8. **Result**: Endless retry as all honest peers lack fabricated balls. No automatic cleanup mechanism exists.

**Security Property Broken**: 
- **Last Ball Chain Integrity**: Ball hashes must be cryptographically verifiable and retrievable from honest network peers
- **Catchup Completeness**: Syncing nodes must complete synchronization without manual intervention under normal network conditions

**Root Cause Analysis**: Inconsistent validation - proofchain balls (lines 145-146) and hash tree balls (line 363-364) are cryptographically validated using `getBallHash()`, but stable joint balls are only validated for unit hash correctness and internal consistency. The `last_ball` field from units is user-controlled and never validated against cryptographic hash computation, allowing injection of internally consistent but cryptographically incorrect ball references.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: P2P network peer operator (untrusted actor within threat model)
- **Resources Required**: Single peer node capable of responding to catchup protocol requests
- **Technical Skill**: Medium - requires understanding catchup protocol, unit structure, and ability to craft internally consistent but cryptographically invalid ball references

**Preconditions**:
- **Network State**: Victim must be behind current network state and initiate catchup
- **Attacker Position**: Victim must select attacker's peer for catchup response (random peer selection increases attack surface)
- **First Ball Constraint**: Must use genesis or victim's last known stable ball as starting point (lines 207-224)

**Execution Complexity**:
- **Transaction Count**: Single catchup response message
- **Coordination**: None required
- **Detection Risk**: Low during attack (appears as normal catchup), higher post-attack if investigated

**Frequency**:
- **Repeatability**: High - attack persists in victim database across restarts
- **Scale**: Per-victim - each syncing node can be independently targeted

**Overall Assessment**: Medium likelihood - requires victim to select malicious peer, but attack has minimal cost, low technical barrier, and high persistence once successful. Likelihood increases if attacker operates multiple well-connected peers.

## Recommendation

**Immediate Mitigation**:
Add cryptographic ball hash validation for stable joints in `processCatchupChain()`:

```javascript
// File: byteball/ocore/catchup.js
// Lines 186-189 - Replace blind trust with validation

if (objUnit.last_ball_unit){
    // Compute expected ball hash from parent balls and skiplist balls
    storage.readJointWithBall(db, objUnit.last_ball_unit, function(objLastBallJoint){
        var arrParentBalls = /* retrieve parent balls */;
        var arrSkiplistBalls = /* retrieve skiplist balls if any */;
        var computed_ball = objectHash.getBallHash(
            objUnit.last_ball_unit, 
            arrParentBalls, 
            arrSkiplistBalls, 
            objLastBallJoint.unit.content_hash ? true : false
        );
        if (computed_ball !== objUnit.last_ball)
            return callbacks.ifError("last_ball does not match getBallHash() computation");
        
        last_ball_unit = objUnit.last_ball_unit;
        last_ball = objUnit.last_ball;
        // continue processing...
    });
}
```

**Permanent Fix**:
Apply same validation pattern used for proofchain balls (lines 145-146) and hash tree balls (line 363-364) to stable joint processing. Ensure all ball hashes in catchup protocol are cryptographically validated before storage.

**Additional Measures**:
- Add automatic cleanup timeout for stale `catchup_chain_balls` entries (e.g., remove entries older than 24 hours)
- Add monitoring to detect repeated hash tree request failures from same stored balls
- Consider adding test coverage for catchup protocol with invalid ball hashes

**Validation**:
- Verify fix prevents fabricated ball hashes from being stored
- Ensure no performance regression from additional validation
- Confirm backward compatibility with existing valid catchup chains

## Proof of Concept

Due to the complexity of setting up a full P2P network environment with catchup protocol simulation, a complete runnable test would require significant test infrastructure beyond the scope of this report. However, the exploitation path is clearly demonstrable:

1. Create catchup response with valid unit hashes but arbitrary `last_ball` values
2. Ensure internal consistency: `objJoint.ball === last_ball` from previous unit
3. Submit to `processCatchupChain()` 
4. Observe: Unit hash validation passes, internal checks pass, but balls are not retrievable from network
5. Result: Victim enters endless retry loop requesting non-existent hash trees

The vulnerability is confirmed by code analysis showing missing `getBallHash()` validation for stable joints (lines 173-191) while present for proofchain (lines 145-146) and hash tree processing (line 363-364).

---

## Notes

This vulnerability represents an **inconsistency in validation rigor** across different parts of the catchup protocol rather than a fundamental protocol design flaw. The fix is straightforward: apply the same cryptographic validation already used for proofchain and hash tree balls to stable joint ball hashes. The impact is limited to syncing nodes and does not affect already-synchronized network participants, correctly classified as Medium severity per Immunefi scope.

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

**File:** catchup.js (L363-364)
```javascript
							if (objBall.ball !== objectHash.getBallHash(objBall.unit, objBall.parent_balls, objBall.skiplist_balls, objBall.is_nonserial))
								return cb("wrong ball hash, ball "+objBall.ball+", unit "+objBall.unit);
```

**File:** network.js (L1975-1982)
```javascript
					storage.readLastStableMcIndex(db, function(last_stable_mci){
						storage.readLastMainChainIndex(function(last_known_mci){
							myWitnesses.readMyWitnesses(function(arrWitnesses){
								var params = {witnesses: arrWitnesses, last_stable_mci: last_stable_mci, last_known_mci: last_known_mci};
								sendRequest(ws, 'catchup', params, true, handleCatchupChain);
							}, 'wait');
						});
					});
```

**File:** network.js (L2018-2039)
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
```

**File:** network.js (L2042-2046)
```javascript
function handleHashTree(ws, request, response){
	if (response.error){
		console.log('get_hash_tree got error response: '+response.error);
		waitTillHashTreeFullyProcessedAndRequestNext(ws); // after 1 sec, it'll request the same hash tree, likely from another peer
		return;
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
