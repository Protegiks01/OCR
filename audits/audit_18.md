# Audit Report

## Title
Ball Hash Validation Bypass in Catchup Chain Processing Enables Persistent Synchronization Denial of Service

## Summary
The `processCatchupChain()` function in `catchup.js` validates unit hashes but omits cryptographic validation of ball hashes for stable joints, creating an inconsistency with proofchain and hash tree processing which properly validate using `getBallHash()`. Malicious P2P peers can inject fabricated ball hashes that pass internal consistency checks, causing victim nodes to enter persistent retry loops when requesting non-existent hash trees from honest peers.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay

**Affected Parties**: New nodes and nodes recovering from downtime attempting catchup synchronization. Already-synchronized nodes are unaffected.

**Damage Quantification**: Victim nodes cannot complete catchup synchronization indefinitely (exceeds ≥1 day threshold). Attack persists across node restarts as fabricated balls remain in `catchup_chain_balls` database table. Recovery requires manual database cleanup or reconnection attempt with different peer set.

**Systemic Risk**: During network partitions or periods of high node churn, multiple syncing nodes become vulnerable if attacker operates well-connected peers. Does not cascade to already-synchronized nodes or impact fund security.

## Finding Description

**Location**: `byteball/ocore/catchup.js:173-191`, function `processCatchupChain()`

**Intended Logic**: Catchup chains should cryptographically validate ball hashes by computing `getBallHash(unit, parent_balls, skiplist_balls, is_nonserial)` and comparing against received values, ensuring hash trees are retrievable from honest peers.

**Actual Logic**: The function validates unit hashes via `hasValidHashes()` and checks internal consistency (current ball matches previous `last_ball` field), but never cryptographically validates that `last_ball` field values match `getBallHash()` computation.

**Code Evidence**:

The `hasValidHashes()` function only validates unit hash, not ball hash: [1](#0-0) 

Catchup stable joint processing validates unit hash but blindly trusts `last_ball` fields without cryptographic verification: [2](#0-1) 

In contrast, proofchain balls ARE cryptographically validated using `getBallHash()`: [3](#0-2) 

Hash tree balls are also cryptographically validated using `getBallHash()`: [4](#0-3) 

Unvalidated balls are stored in `catchup_chain_balls` table for future hash tree requests: [5](#0-4) 

**Exploitation Path**:

1. **Preconditions**: 
   - Victim node behind network state initiates catchup
   - Attacker operates P2P peer node
   - Catchup request received by attacker's peer: [6](#0-5) 

2. **Step 1**: Victim sends catchup request with witness list and MCI range to attacker's peer

3. **Step 2**: Attacker crafts malicious catchup response containing units with:
   - Valid unit hashes (pass `hasValidHashes()` check)
   - Arbitrary `last_ball` and `last_ball_unit` fields not matching actual `getBallHash()` computation
   - `objJoint.ball` values matching the arbitrary `last_ball` values (internally consistent chain)

4. **Step 3**: Victim processes catchup chain where validation passes because:
   - Unit hash validation passes (line 180)
   - Internal consistency passes (lines 184-185: current ball matches previous last_ball)
   - NO cryptographic validation that `last_ball = getBallHash(last_ball_unit, ...)`
   - Fabricated balls stored in database (lines 242-245)

5. **Step 4**: Victim requests hash trees using fabricated balls: [7](#0-6) 

6. **Step 5**: Honest peers query database for fabricated balls and return error: [8](#0-7) 

7. **Step 6**: Error triggers retry loop with 100ms intervals: [9](#0-8) [10](#0-9) 

8. **Persistence**: Fabricated balls persist across restarts as `checkCatchupLeftovers()` continues catchup from stored state: [11](#0-10) 

9. **Result**: Endless retry as all honest peers lack fabricated balls. No automatic cleanup mechanism exists except database migration.

**Security Property Broken**:
- **Last Ball Chain Integrity**: Ball hashes must be cryptographically verifiable and retrievable from honest network peers
- **Catchup Completeness**: Syncing nodes must complete synchronization without manual intervention under normal network conditions

**Root Cause Analysis**: Inconsistent validation approach - proofchain balls and hash tree balls are cryptographically validated using `getBallHash()`, but stable joint balls in catchup chains are only validated for unit hash correctness and internal consistency. The `last_ball` field from units is attacker-controlled data never validated against cryptographic hash computation, allowing injection of internally consistent but cryptographically incorrect ball references.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: P2P network peer operator (untrusted actor per threat model)
- **Resources Required**: Single peer node capable of responding to catchup protocol requests
- **Technical Skill**: Medium - requires understanding catchup protocol format and ability to craft internally consistent but cryptographically invalid ball references

**Preconditions**:
- Victim must be behind current network state and initiate catchup
- Victim must select attacker's peer for catchup response (random selection)
- First ball must be genesis or victim's last known stable ball (validated at lines 207-224)

**Execution Complexity**:
- Single catchup response message required
- No coordination or timing requirements
- Low detection risk during attack (appears as normal catchup traffic)

**Persistence**:
- Attack persists in victim database across restarts
- Cleanup requires manual intervention or database migration
- Can affect multiple victims if attacker operates well-connected peer

**Overall Assessment**: Medium likelihood - requires victim to randomly select malicious peer, but attack has minimal cost, low technical barrier, and high persistence once successful.

## Recommendation

**Immediate Mitigation**:

Add cryptographic ball hash validation to catchup chain stable joint processing to match proofchain and hash tree validation:

```javascript
// File: byteball/ocore/catchup.js
// Location: Lines 173-191 in processCatchupChain()

// After line 185, add ball hash validation:
if (objUnit.last_ball_unit) {
    // Validate that last_ball matches cryptographic hash
    storage.readJoint(db, objUnit.last_ball_unit, function(objLastBallJoint) {
        var computed_ball = objectHash.getBallHash(
            objLastBallJoint.unit.unit,
            objLastBallJoint.parent_balls,
            objLastBallJoint.skiplist_balls,
            objLastBallJoint.unit.content_hash ? true : false
        );
        if (objUnit.last_ball !== computed_ball)
            return callbacks.ifError("last_ball does not match getBallHash computation");
        // Continue processing...
    });
}
```

**Permanent Fix**:

Ensure consistent validation across all catchup components:
1. Apply cryptographic ball hash validation to all ball references in catchup chains
2. Add database constraint or cleanup mechanism to prevent persistent invalid balls
3. Implement timeout or error count limit for hash tree request retries
4. Add monitoring to detect repeated hash tree request failures

**Additional Measures**:
- Add test case verifying fabricated ball hashes are rejected in catchup chains
- Add alert when node enters extended retry loop for same hash tree
- Document validation requirements for all catchup protocol messages

## Proof of Concept

A complete PoC would require:

1. Setting up test Obyte network with attacker peer and victim node
2. Crafting catchup response with units having valid unit hashes but fabricated ball hashes
3. Demonstrating victim stores fabricated balls in `catchup_chain_balls`
4. Showing victim enters retry loop when requesting hash trees from honest peers
5. Verifying attack persists across victim node restart

The attack path is clearly documented with specific code citations. Implementation would involve constructing unit objects with valid unit hashes (pass `hasValidHashes()`) but arbitrary `last_ball` values that don't match `getBallHash()` computation, then sending as catchup response.

## Notes

This vulnerability demonstrates a validation inconsistency where proofchain balls (lines 145-146) and hash tree balls (line 363-364) receive cryptographic validation using `getBallHash()`, but catchup chain stable joints (lines 173-191) do not. The `last_ball` and `last_ball_unit` fields from received units are trusted without verification, allowing malicious peers to inject fabricated ball references that cause persistent synchronization failures. The issue specifically affects the catchup synchronization path and does not impact normal unit validation or already-synchronized nodes.

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

**File:** network.js (L1926-1943)
```javascript
function checkCatchupLeftovers(){
	db.query(
		"SELECT 1 FROM hash_tree_balls \n\
		UNION \n\
		SELECT 1 FROM catchup_chain_balls \n\
		LIMIT 1",
		function(rows){
			if (rows.length === 0)
				return console.log('no leftovers');
			console.log('have catchup leftovers from the previous run');
			findNextPeer(null, function(ws){
				console.log('will request leftovers from '+ws.peer);
				if (!bCatchingUp && !bWaitingForCatchupChain)
					requestCatchup(ws);
			});
		}
	);
}
```

**File:** network.js (L1945-1987)
```javascript
function requestCatchup(ws){
	console.log("will request catchup from "+ws.peer);
	eventBus.emit('catching_up_started');
//	if (conf.storage === 'sqlite')
//		db.query("PRAGMA cache_size=-200000", function(){});
	catchup.purgeHandledBallsFromHashTree(db, function(){
		db.query(
			"SELECT hash_tree_balls.unit FROM hash_tree_balls LEFT JOIN units USING(unit) WHERE units.unit IS NULL ORDER BY ball_index", 
			function(tree_rows){ // leftovers from previous run
				if (tree_rows.length > 0){
					bCatchingUp = true;
					console.log("will request balls found in hash tree");
					requestNewMissingJoints(ws, tree_rows.map(function(tree_row){ return tree_row.unit; }));
					waitTillHashTreeFullyProcessedAndRequestNext(ws);
					return;
				}
				db.query("SELECT 1 FROM catchup_chain_balls LIMIT 1", function(chain_rows){ // leftovers from previous run
					if (chain_rows.length > 0){
						bCatchingUp = true;
						requestNextHashTree(ws);
						return;
					}
					// we are not switching to catching up mode until we receive a catchup chain - don't allow peers to throw us into 
					// catching up mode by just sending a ball
					
					// to avoid duplicate requests, we are raising this flag before actually sending the request 
					// (will also reset the flag only after the response is fully processed)
					bWaitingForCatchupChain = true;
					
					console.log('will read last stable mci for catchup');
					storage.readLastStableMcIndex(db, function(last_stable_mci){
						storage.readLastMainChainIndex(function(last_known_mci){
							myWitnesses.readMyWitnesses(function(arrWitnesses){
								var params = {witnesses: arrWitnesses, last_stable_mci: last_stable_mci, last_known_mci: last_known_mci};
								sendRequest(ws, 'catchup', params, true, handleCatchupChain);
							}, 'wait');
						});
					});
				});
			}
		);
	});
}
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
