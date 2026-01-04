# Audit Report

## Title
Ball Hash Validation Bypass in Catchup Chain Processing Enables Persistent Synchronization Denial of Service

## Summary
The `processCatchupChain()` function in catchup.js validates unit hashes but omits cryptographic validation of ball hashes for stable joints, unlike proofchain and hash tree processing which properly validate ball hashes using `getBallHash()`. [1](#0-0)  Malicious P2P peers can inject fabricated ball hashes that pass internal consistency checks, causing victim nodes to enter persistent retry loops when requesting non-existent hash trees from honest peers, preventing synchronization until manual database cleanup.

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
- **Conditions**: Must select malicious peer for catchup response (random peer selection)
- **Recovery**: Manual database intervention required

## Finding Description

**Location**: `byteball/ocore/catchup.js:173-191`, function `processCatchupChain()`

**Intended Logic**: Catchup chains should cryptographically validate ball hashes by computing `getBallHash(unit, parent_balls, skiplist_balls, is_nonserial)` and comparing against received values, ensuring all ball references are verifiable and retrievable from honest network peers.

**Actual Logic**: The function validates unit hashes via `hasValidHashes()` and checks internal consistency (current ball matches previous `last_ball` field), but never cryptographically validates that `last_ball` field values actually match `getBallHash()` computation.

**Code Evidence**:

The `hasValidHashes()` function only validates unit hash, not ball hash: [2](#0-1) 

Catchup stable joint processing validates unit hash but blindly trusts `last_ball` fields without cryptographic verification: [3](#0-2) 

In contrast, proofchain balls ARE cryptographically validated using `getBallHash()`: [4](#0-3) 

Hash tree balls are also cryptographically validated using `getBallHash()`: [5](#0-4) 

The source of unvalidated balls comes from `processWitnessProof()` which builds the mapping from unstable MC joints' `last_ball` fields without validation: [6](#0-5) 

Unvalidated balls are stored for future hash tree requests: [7](#0-6) 

**Exploitation Path**:

1. **Preconditions**: 
   - Victim node behind network state initiates catchup [8](#0-7) 
   - Attacker operates P2P peer node with corrupted database containing fabricated ball values
   - Catchup request sent to attacker's peer

2. **Step 1**: Victim sends catchup request with witness list and MCI range

3. **Step 2**: Attacker's peer responds with catchup chain containing units with fabricated `last_ball` fields (attacker can modify their own database to inject arbitrary ball values into the balls table, which then get included in catchup responses via `readJointWithBall()`) [9](#0-8) 

4. **Step 3**: Victim processes catchup chain where:
   - Unit hash validation passes (hasValidHashes checks only unit hash)
   - Internal consistency checks pass (current ball matches previous last_ball)
   - No validation that `last_ball = getBallHash(last_ball_unit, ...)`
   - Fabricated balls stored in `catchup_chain_balls` table

5. **Step 4**: Victim requests hash trees using fabricated balls [10](#0-9) 

6. **Step 5**: Honest peers query for fabricated balls and return error [11](#0-10) 

7. **Step 6**: Error triggers retry loop with 100ms intervals [12](#0-11) 
   
   The retry mechanism continues indefinitely [13](#0-12) 

8. **Result**: Persistent retry as all honest peers lack fabricated balls. No automatic cleanup mechanism exists for failed catchup attempts.

**Security Property Broken**: 
- **Ball Hash Integrity**: All ball hashes must be cryptographically verifiable using `getBallHash()` and retrievable from honest network peers
- **Catchup Completeness**: Syncing nodes must complete synchronization without manual intervention under normal network conditions

**Root Cause Analysis**: 
Inconsistent validation across catchup subsystems. Proofchain balls and hash tree balls undergo cryptographic validation via `getBallHash()` comparison, but stable joint balls in catchup chains are only validated for unit hash correctness and internal consistency. The `last_ball` field from units flows through `processWitnessProof()` into `assocLastBallByLastBallUnit` without cryptographic validation, allowing injection of internally consistent but cryptographically incorrect ball references when an attacker corrupts their own database.

## Impact Explanation

**Affected Assets**: Node synchronization capability for catchup nodes

**Damage Severity**:
- **Quantitative**: Victim nodes enter indefinite retry loop. Attack persists across node restarts because fabricated balls remain in `catchup_chain_balls` table. Multiple syncing nodes can be affected if attacker operates well-connected peer(s).
- **Qualitative**: Temporary DoS affecting only catchup nodes (new nodes or nodes recovering from downtime). Prevents network growth and recovery from outages. No cascade effect to already-synchronized nodes.

**User Impact**:
- **Who**: New nodes or nodes recovering from downtime performing catchup synchronization
- **Conditions**: Must randomly select malicious peer for catchup response
- **Recovery**: Requires manual database cleanup via `DELETE FROM catchup_chain_balls` statement and restart

**Systemic Risk**: During network partitions or high node churn, multiple syncing nodes vulnerable simultaneously. No impact on operational nodes. Can delay network recovery if attacker controls popular peers.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: P2P network peer operator (untrusted actor within threat model)
- **Resources Required**: Single peer node capable of responding to catchup protocol requests, ability to modify own database
- **Technical Skill**: Medium - requires understanding catchup protocol, unit structure, database manipulation, and ability to craft internally consistent but cryptographically invalid ball references

**Preconditions**:
- **Network State**: Victim must be behind current network state and initiate catchup (common for new nodes or nodes recovering from downtime)
- **Attacker Position**: Victim must select attacker's peer for catchup response (random selection from connected peers)
- **First Ball Constraint**: Must use genesis or victim's last known stable ball as starting point (learned from catchup request)

**Execution Complexity**:
- **Transaction Count**: Single catchup response message
- **Coordination**: None required
- **Detection Risk**: Low during attack (appears as normal catchup failure to external observers)

**Frequency**:
- **Repeatability**: High - attack persists in victim database across restarts, requiring manual intervention
- **Scale**: Per-victim - each syncing node can be independently targeted

**Overall Assessment**: Medium likelihood - requires victim to select malicious peer from pool of available peers, but attack has minimal cost, low technical barrier (just database modification), and high persistence once successful.

## Recommendation

**Immediate Mitigation**:
Add cryptographic ball hash validation for stable joints in `processCatchupChain()` to match the validation performed for proofchain and hash tree balls:

```javascript
// In catchup.js:processCatchupChain(), after line 189
if (objUnit.last_ball_unit) {
    // Cryptographically validate the last_ball matches getBallHash computation
    storage.readUnitProps(db, objUnit.last_ball_unit, function(objLastBallUnitProps){
        storage.readJoint(db, objUnit.last_ball_unit, {
            ifFound: function(objLastBallJoint){
                var computed_ball = objectHash.getBallHash(
                    objUnit.last_ball_unit,
                    objLastBallJoint.unit.parent_units ? objLastBallJoint.parent_balls : null,
                    objLastBallJoint.skiplist_balls,
                    objLastBallUnitProps.content_hash ? true : false
                );
                if (computed_ball !== objUnit.last_ball)
                    return callbacks.ifError("last_ball cryptographic validation failed");
                // Continue processing...
            }
        });
    });
}
```

**Permanent Fix**:
Implement consistent ball hash validation across all catchup subsystems (witness proof, proofchain, hash tree, and stable joints) using the same `getBallHash()` cryptographic validation.

**Additional Measures**:
- Add automatic cleanup of stale `catchup_chain_balls` entries after repeated hash tree request failures
- Add monitoring to detect nodes stuck in catchup retry loops
- Add test case verifying ball hash validation in catchup chains
- Consider adding timeout mechanism to exit catchup mode after extended failures

**Validation**:
- Fix prevents injection of fabricated ball hashes
- No impact on normal catchup operation (real balls pass validation)
- Backward compatible with existing network
- Performance impact minimal (one additional getBallHash computation per stable joint)

## Proof of Concept

```javascript
// test/catchup_ball_validation.test.js
const catchup = require('../catchup.js');
const db = require('../db.js');
const objectHash = require('../object_hash.js');

describe('Catchup ball hash validation', function(){
    it('should reject catchup chain with fabricated ball hashes', function(done){
        // Setup: Create catchup chain with valid unit hashes but fabricated last_ball values
        var fakeBall = objectHash.getBase64Hash({fake: 'ball'});
        var catchupChain = {
            unstable_mc_joints: [/* valid unstable MC joints */],
            stable_last_ball_joints: [{
                unit: {
                    unit: 'validUnitHash',
                    last_ball_unit: 'genesisUnit',
                    last_ball: fakeBall, // Fabricated ball that doesn't match getBallHash()
                    // ... other valid unit fields
                },
                ball: fakeBall // Internally consistent with unit.last_ball
            }],
            witness_change_and_definition_joints: [],
            proofchain_balls: []
        };
        
        // Execute: Process catchup chain
        catchup.processCatchupChain(catchupChain, 'test_peer', testWitnesses, {
            ifError: function(err){
                // Verify: Should reject due to ball hash mismatch
                assert(err.includes('ball') || err.includes('hash'), 'Expected ball validation error');
                
                // Verify: Fabricated balls NOT stored in catchup_chain_balls
                db.query("SELECT * FROM catchup_chain_balls WHERE ball=?", [fakeBall], function(rows){
                    assert.equal(rows.length, 0, 'Fabricated ball should not be stored');
                    done();
                });
            },
            ifOk: function(){
                assert.fail('Should have rejected fabricated ball hashes');
            },
            ifCurrent: function(){
                assert.fail('Should not mark as current with invalid balls');
            }
        });
    });
});
```

## Notes

This vulnerability demonstrates an inconsistency in validation rigor across different catchup subsystems. While proofchain balls and hash tree balls receive cryptographic validation via `getBallHash()`, stable joint balls in catchup chains rely only on internal consistency checks. This creates an attack surface where malicious peers can inject references to non-existent balls by corrupting their own database, causing victim nodes to become permanently stuck in synchronization retry loops until manual database intervention.

The attack is particularly insidious because:
1. It affects only syncing nodes, not operational nodes, making detection difficult
2. The fabricated balls pass all consistency checks and are persisted to database
3. The retry loop appears as normal network issues to casual observers  
4. Recovery requires manual database surgery by node operators

The fix is straightforward: apply the same `getBallHash()` cryptographic validation used for proofchain and hash tree balls to stable joint balls in catchup chains, ensuring all ball references are cryptographically correct and retrievable from honest peers.

### Citations

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

**File:** catchup.js (L242-245)
```javascript
					var arrValues = arrChainBalls.map(function(ball){ return "("+db.escape(ball)+")"; });
					db.query("INSERT INTO catchup_chain_balls (ball) VALUES "+arrValues.join(', '), function(){
						cb();
					});
```

**File:** catchup.js (L269-273)
```javascript
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

**File:** witness_proof.js (L189-192)
```javascript
		if (objUnit.last_ball_unit && arrFoundWitnesses.length >= constants.MAJORITY_OF_WITNESSES){
			arrLastBallUnits.push(objUnit.last_ball_unit);
			assocLastBallByLastBallUnit[objUnit.last_ball_unit] = objUnit.last_ball;
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

**File:** storage.js (L609-624)
```javascript
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
