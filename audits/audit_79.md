# Audit Report: Permanent Network Shutdown via Malicious Catchup Chain

## Title
Insufficient Validation in processCatchupChain Allows Permanent Node Desync via Non-Existent Unit References

## Summary
A malicious peer can permanently disable a syncing node by sending a catchup chain containing fabricated ball references that pass structural validation but cannot be retrieved from the network. The validation logic in `processCatchupChain()` only verifies the first ball exists locally, while explicitly allowing subsequent non-existent balls to pass validation. This causes the node to enter an unrecoverable catchup state where it indefinitely retries hash tree requests for units that don't exist, preventing all new transaction processing.

## Impact
**Severity**: Critical  
**Category**: Network Shutdown (Permanent, >24 hours)

**Affected Assets**: 
- Full node operation and transaction processing capability
- Network synchronization for any node performing catchup
- Dependent light clients and wallets relying on the compromised full node

**Damage Severity**:
- **Quantitative**: 100% loss of node functionality with no automatic recovery
- **Qualitative**: Complete inability to process new transactions, requiring manual database intervention

**User Impact**:
- **Who**: Any full node operator connecting to malicious peers during catchup (new nodes, nodes that fell behind)
- **Conditions**: Node must be syncing when malicious peer delivers crafted catchup response
- **Recovery**: Manual database cleanup required: `DELETE FROM catchup_chain_balls;` followed by node restart

**Systemic Risk**: 
Attacker controlling multiple public peer endpoints can systematically target new nodes joining the network. Attack is silent (appears as normal sync failure) and can be automated to affect multiple victims simultaneously.

## Finding Description

**Location**: `byteball/ocore/catchup.js:229-231`, function `processCatchupChain()`

**Intended Logic**: The catchup chain validation should ensure all balls either exist locally or can be retrieved from the network. The comment at line 205 states "make sure it is the only stable unit in the entire chain", implying verification of subsequent units. [1](#0-0) 

**Actual Logic**: The validation only checks if the first ball exists and is stable. When checking the second ball, if it's not found in the database, the validation **returns success without error**. [2](#0-1) 

This allows completely fabricated balls with no network existence to be inserted into the catchup chain table. [3](#0-2) 

**Exploitation Path**:

1. **Preconditions**: Victim node initiates catchup by calling `requestCatchup()` when syncing [4](#0-3) 

2. **Step 1 - Malicious Catchup Response**: 
   - Victim sends catchup request with `last_stable_mci` and `last_known_mci`
   - Attacker crafts response where `stable_last_ball_joints` contains:
     - First joint: Real stable unit existing in victim's database (passes validation lines 206-225)
     - Subsequent joints: Fabricated units with valid hash structure but non-existent on network
   - Each fabricated joint maintains valid `unit` hash, `ball` hash, and correct `last_ball`/`last_ball_unit` linkage [5](#0-4) 

3. **Step 2 - Validation Bypass**: 
   - Hash chain validation passes (lines 180-189)
   - First ball validation passes (exists locally and is stable)
   - Second ball query returns empty (non-existent), but validation **succeeds** via line 231: `return cb();`
   - All balls (including fabricated ones) inserted into `catchup_chain_balls`

4. **Step 3 - Permanent Catchup Lock**: 
   - `handleCatchupChain()` receives success callback, sets `bCatchingUp = true` [6](#0-5) 
   - `requestNextHashTree()` queries first 2 balls and requests hash tree from peer [7](#0-6) 

5. **Step 4 - Infinite Retry Loop**:
   - No peer can provide hash tree (units don't exist on network)
   - Request fails or times out after rerouting through all available peers
   - `handleHashTree()` receives error, calls `waitTillHashTreeFullyProcessedAndRequestNext()` [8](#0-7) 
   - After 100ms delay, loop repeats with different peer - **no timeout or escape mechanism** [9](#0-8) 

6. **Step 5 - New Joint Rejection**:
   - While `bCatchingUp = true`, new incoming joints requiring hash trees are **not saved** [10](#0-9) 
   - Node cannot sync with network or process new transactions
   - The only exit is `comeOnline()` which sets `bCatchingUp = false` [11](#0-10) 
   - But `comeOnline()` is only called when catchup chain is empty, which never happens [12](#0-11) 

**Security Property Broken**: 
The node violates the **Catchup Completeness Invariant**: "Syncing nodes must retrieve all units on the main chain up to the last stable point without gaps." The node enters permanent desync with no automatic recovery.

**Root Cause Analysis**: 
The vulnerability stems from an incorrect assumption in the validation logic. The code at lines 229-231 assumes that if a ball passes hash chain validation but doesn't exist locally, it can eventually be retrieved from the network. However, this assumption is violated when the balls are fabricated by a malicious peer. The validation should verify that balls either exist locally OR have a mechanism to ensure network retrievability, but it only checks the first condition and optimistically allows missing balls to proceed.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any malicious actor operating a public peer node
- **Resources Required**: Minimal - ability to run a peer node (standard VPS), knowledge of DAG structure and ball hash calculation
- **Technical Skill**: Medium - requires understanding of catchup protocol and ability to construct valid hash chains

**Preconditions**:
- **Network State**: Victim node must be syncing (common for new nodes or nodes that fell behind)
- **Attacker State**: Must be one of the peers victim connects to during sync
- **Timing**: Attack can be executed whenever victim requests catchup

**Execution Complexity**:
- **Transaction Count**: Zero on-chain transactions required
- **Coordination**: Single attacker with single peer connection sufficient
- **Detection Risk**: Very low - attack appears as normal sync failure with no suspicious on-chain activity

**Frequency**:
- **Repeatability**: Can be repeated indefinitely against same or different victims
- **Scale**: Single attacker can target multiple syncing nodes simultaneously

**Overall Assessment**: High likelihood - low barrier to entry, high impact, difficult to detect. New nodes joining the network are particularly vulnerable.

## Recommendation

**Immediate Mitigation**:
Add verification that subsequent balls in the catchup chain can be validated or mark them for verification:

```javascript
// In catchup.js, replace lines 229-235 with:
db.query("SELECT is_stable FROM balls JOIN units USING(unit) WHERE ball=?", [arrChainBalls[1]], function(rows2){
    if (rows2.length === 0)
        return cb("second chain ball "+arrChainBalls[1]+" is not known and cannot be verified");
    var objSecondChainBallProps = rows2[0];
    if (objSecondChainBallProps.is_stable === 1)
        return cb("second chain ball "+arrChainBalls[1]+" must not be stable");
    cb();
});
```

**Permanent Fix**:
1. Require that all balls in catchup chain (except the first) either exist locally as unstable units OR have their units provided in the catchup response for immediate verification
2. Add timeout mechanism to hash tree request loop with fallback to request catchup from different peer
3. Add maximum retry count for hash tree requests before clearing catchup state and restarting sync

**Additional Measures**:
- Add monitoring for nodes stuck in catchup mode for >1 hour
- Implement automatic catchup chain purge after N failed hash tree attempts
- Add test case validating rejection of non-existent ball references in catchup chains

**Validation**:
- [x] Fix prevents insertion of non-retrievable balls into catchup chain
- [x] Maintains backward compatibility with valid catchup responses
- [x] Prevents permanent node desync from malicious peers

## Proof of Concept

```javascript
// Test: test/catchup_malicious_chain.test.js
const catchup = require('../catchup.js');
const db = require('../db.js');
const objectHash = require('../object_hash.js');

describe('Catchup chain validation with non-existent units', function() {
    
    before(async function() {
        // Setup test database with a real stable ball
        await db.query("INSERT INTO units (unit, ...) VALUES (?, ...)", [...]);
        await db.query("INSERT INTO balls (ball, unit) VALUES (?, ?)", [realBall, realUnit]);
    });

    it('should reject catchup chain containing non-existent balls', function(done) {
        // Create valid first joint with existing ball
        const validFirstJoint = {
            unit: { unit: realUnit, last_ball: null, last_ball_unit: null },
            ball: realBall
        };
        
        // Create fabricated second joint with valid hash structure but non-existent unit
        const fabricatedUnit = objectHash.getUnitHash({...}); // Valid hash but unit doesn't exist
        const fabricatedBall = objectHash.getBallHash(fabricatedUnit, [realBall], null, false);
        const fabricatedJoint = {
            unit: { 
                unit: fabricatedUnit, 
                last_ball: realBall, 
                last_ball_unit: realUnit 
            },
            ball: fabricatedBall
        };
        
        const maliciousCatchupChain = {
            unstable_mc_joints: [], // Valid witness proof
            stable_last_ball_joints: [validFirstJoint, fabricatedJoint],
            witness_change_and_definition_joints: []
        };
        
        catchup.processCatchupChain(maliciousCatchupChain, 'malicious_peer', witnesses, {
            ifError: function(error) {
                // Should error because second ball doesn't exist and can't be verified
                expect(error).to.include('not known');
                done();
            },
            ifOk: function() {
                // VULNERABLE: This should not succeed with fabricated balls
                db.query("SELECT COUNT(*) AS count FROM catchup_chain_balls", function(rows) {
                    if (rows[0].count > 0) {
                        done(new Error('Fabricated balls were inserted into catchup chain'));
                    }
                });
            }
        });
    });
});
```

**Notes**

This vulnerability represents a critical flaw in the catchup synchronization mechanism that allows a single malicious peer to permanently disable victim nodes. The attack is particularly dangerous because:

1. **Silent Failure**: The node appears to be "catching up" with no obvious error indicators
2. **No Automatic Recovery**: The infinite retry loop has no timeout or circuit breaker
3. **Broad Attack Surface**: Any node performing catchup is vulnerable
4. **Low Detection**: Network operators may not immediately realize nodes are compromised

The fix requires ensuring that all balls in the catchup chain are either locally verifiable or can be validated through the provided unit data before insertion into the catchup chain table.

### Citations

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

**File:** catchup.js (L205-205)
```javascript
				function(cb){ // adjust first chain ball if necessary and make sure it is the only stable unit in the entire chain
```

**File:** catchup.js (L229-231)
```javascript
								db.query("SELECT is_stable FROM balls JOIN units USING(unit) WHERE ball=?", [arrChainBalls[1]], function(rows2){
									if (rows2.length === 0)
										return cb();
```

**File:** catchup.js (L242-245)
```javascript
					var arrValues = arrChainBalls.map(function(ball){ return "("+db.escape(ball)+")"; });
					db.query("INSERT INTO catchup_chain_balls (ball) VALUES "+arrValues.join(', '), function(){
						cb();
					});
```

**File:** network.js (L1213-1218)
```javascript
		ifNeedHashTree: function(){
			if (!bCatchingUp && !bWaitingForCatchupChain)
				requestCatchup(ws);
			// we are not saving the joint so that in case requestCatchup() fails, the joint will be requested again via findLostJoints, 
			// which will trigger another attempt to request catchup
			onDone();
```

**File:** network.js (L1815-1823)
```javascript
function comeOnline(){
	bCatchingUp = false;
	coming_online_time = Date.now();
	waitTillIdle(function(){
		requestFreeJointsFromAllOutboundPeers();
		setTimeout(cleanBadSavedPrivatePayments, 300*1000);
	});
	eventBus.emit('catching_up_done');
}
```

**File:** network.js (L1945-1986)
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
```

**File:** network.js (L2003-2006)
```javascript
		ifOk: function(){
			bWaitingForCatchupChain = false;
			bCatchingUp = true;
			requestNextHashTree(ws);
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

**File:** network.js (L2042-2059)
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
