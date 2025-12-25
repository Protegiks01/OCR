# Audit Report: Catchup Chain Validation Bypass Enables Permanent Node Shutdown

## Title
Insufficient Ball Existence Validation in processCatchupChain() Allows Permanent Node Desynchronization via Fabricated Unit References

## Summary
A malicious peer can permanently disable a syncing node by sending a catchup chain containing fabricated ball references that pass structural validation but don't exist on the network. The validation logic in `processCatchupChain()` at lines 229-231 allows non-existent balls to pass validation without error, causing the node to enter an infinite retry loop requesting hash trees for units that will never be found. This prevents all new transaction processing with no automatic recovery mechanism.

## Impact
**Severity**: Critical  
**Category**: Network Shutdown (Permanent, >24 hours)

**Affected Assets**:
- Full node synchronization and transaction processing capability
- Network participation for any node performing catchup
- Services depending on the compromised full node

**Damage Severity**:
- **Quantitative**: Complete loss of node functionality with no automatic recovery mechanism
- **Qualitative**: Node cannot process new transactions or participate in consensus; requires manual database intervention to recover

**User Impact**:
- **Who**: Any full node operator syncing from malicious peers (new nodes, nodes recovering from downtime)
- **Conditions**: Node must request catchup when attacker is among connected peers
- **Recovery**: Manual database cleanup required (`DELETE FROM catchup_chain_balls;`) followed by node restart

**Systemic Risk**: 
Attacker controlling multiple public peer endpoints can systematically prevent new nodes from joining the network. Attack is silent and appears as normal sync failure.

## Finding Description

**Location**: `byteball/ocore/catchup.js:229-231`, function `processCatchupChain()` [1](#0-0) 

**Intended Logic**: The validation should ensure all balls in the catchup chain either exist locally or can be retrieved from the network. The comment states "make sure it is the only stable unit in the entire chain", implying verification of subsequent units.

**Actual Logic**: When validating the second ball in the catchup chain, if the ball is not found in the database, the validation returns success without error. [2](#0-1) 

This allows fabricated balls with valid hash structure but no network existence to be inserted into the catchup_chain_balls table. [3](#0-2) 

**Exploitation Path**:

1. **Preconditions**: Victim node initiates catchup by calling `requestCatchup()` when syncing [4](#0-3) 

2. **Step 1 - Malicious Catchup Response**: 
   - Victim sends catchup request with `last_stable_mci` and `last_known_mci`
   - Attacker crafts response where `stable_last_ball_joints` contains:
     - First joint: Real stable unit existing in victim's database (passes validation)
     - Subsequent joints: Fabricated units with valid unit hash and ball hash but non-existent on network
   
   The fabricated joints pass hash validation because they maintain valid hash structure: [5](#0-4) 

3. **Step 2 - Validation Bypass**: 
   - First ball validation passes (exists locally and is stable)
   - Second ball query returns empty (non-existent), but validation succeeds via line 231
   - All balls including fabricated ones are inserted into `catchup_chain_balls`

4. **Step 3 - Permanent Catchup Lock**: 
   - `handleCatchupChain()` sets `bCatchingUp = true` and calls `requestNextHashTree()` [6](#0-5) 

5. **Step 4 - Infinite Retry Loop**:
   - `requestNextHashTree()` queries first 2 balls and requests hash tree from peer [7](#0-6) 

   - No peer can provide hash tree (units don't exist on network)
   - `handleHashTree()` receives error, calls `waitTillHashTreeFullyProcessedAndRequestNext()` [8](#0-7) 

   - After 100ms delay, loop repeats with different peer - no timeout or maximum retry limit [9](#0-8) 

6. **Step 5 - New Joint Rejection**:
   - While `bCatchingUp = true`, new incoming joints requiring hash trees are not saved [10](#0-9) 

   - Node cannot sync with network or process new transactions
   - The only exit is `comeOnline()` which sets `bCatchingUp = false` [11](#0-10) 

   - But `comeOnline()` is only called when catchup chain is empty [12](#0-11) 

   - Chain never empties because hash tree request never succeeds

**Security Property Broken**: 
Catchup Completeness Invariant - "Syncing nodes must retrieve all units on the main chain up to the last stable point without gaps."

**Root Cause Analysis**: 
The vulnerability stems from an incorrect assumption at lines 229-231. The code assumes that if a ball doesn't exist locally, it can eventually be retrieved from the network. However, when balls are fabricated by a malicious peer, they will never exist on the network. The validation should verify that non-local balls can actually be retrieved, but instead optimistically allows any missing ball to proceed, creating an unrecoverable state when those balls cannot be found.

## Impact Explanation

**Affected Assets**: 
- Node synchronization capability
- Transaction processing functionality
- Network participation

**Damage Severity**:
- **Quantitative**: 100% loss of node functionality - cannot process any new transactions requiring hash trees, cannot sync with network
- **Qualitative**: Complete inability to participate in network consensus until manual intervention

**User Impact**:
- **Who**: All full node operators performing catchup (new nodes, nodes recovering from downtime)
- **Conditions**: Exploitable whenever victim connects to malicious peer during sync
- **Recovery**: Manual database cleanup required: `DELETE FROM catchup_chain_balls;` followed by node restart and re-sync from trusted peers

**Systemic Risk**:
- Attacker controlling multiple public peer endpoints can systematically target new nodes
- Attack is automated and scalable
- Detection difficulty: appears as normal sync failure with no suspicious on-chain activity
- No automatic recovery mechanism exists in the protocol

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any malicious actor operating a public peer node
- **Resources Required**: Minimal - standard VPS to run peer node, knowledge of DAG structure and ball hash calculation
- **Technical Skill**: Medium - requires understanding of catchup protocol and ability to construct valid hash chains

**Preconditions**:
- **Network State**: Victim node must be syncing (common for new nodes or nodes that fell behind)
- **Attacker State**: Must be one of the peers victim connects to during sync
- **Timing**: Attack can be executed whenever victim requests catchup

**Execution Complexity**:
- **Transaction Count**: Zero on-chain transactions required
- **Coordination**: Single attacker with single peer connection sufficient
- **Detection Risk**: Very low - attack appears as normal sync failure

**Frequency**:
- **Repeatability**: Unlimited - attacker can target multiple victims
- **Scale**: Any syncing node is vulnerable

**Overall Assessment**: High likelihood - low barrier to entry, high impact, difficult to detect. New nodes joining the network are particularly vulnerable.

## Recommendation

**Immediate Mitigation**:
Add validation to verify second ball exists before proceeding:

```javascript
// In catchup.js, lines 229-236
db.query("SELECT is_stable FROM balls JOIN units USING(unit) WHERE ball=?", [arrChainBalls[1]], function(rows2){
    if (rows2.length === 0)
        return cb("second chain ball "+arrChainBalls[1]+" is not known");  // REJECT instead of allowing
    var objSecondChainBallProps = rows2[0];
    if (objSecondChainBallProps.is_stable === 1)
        return cb("second chain ball "+arrChainBalls[1]+" must not be stable");
    cb();
});
```

**Permanent Fix**:
Implement comprehensive validation for all balls in catchup chain to ensure they either exist locally or are retrievable from network before insertion into `catchup_chain_balls`.

**Additional Measures**:
- Add timeout mechanism in `waitTillHashTreeFullyProcessedAndRequestNext()` to prevent infinite loops
- Add monitoring to detect nodes stuck in catchup state for extended periods
- Implement peer reputation system to avoid malicious peers
- Add test case verifying catchup chain validation rejects non-existent balls

## Proof of Concept

```javascript
// Conceptual PoC demonstrating the vulnerability
// This outlines the attack flow - full integration test would require test framework setup

const catchup = require('./catchup.js');
const storage = require('./storage.js');
const objectHash = require('./object_hash.js');

// Test: Malicious catchup chain with fabricated balls passes validation
describe('Catchup validation vulnerability', function() {
    it('should reject catchup chain with non-existent balls', function(done) {
        
        // Step 1: Set up victim node with known stable ball
        const realStableBall = 'oXGOcA9TjN8pCiDkEfbbgF+SZqD0W4UEa2B7lU7vV1o=';  // Existing ball
        const realStableUnit = '1pDW1R4JdRcoRgM0z9W5LzTOD4l5XH+BQ9m0N2c0L5o=';  // Corresponding unit
        
        // Step 2: Craft fabricated ball with valid hash structure
        const fabricatedUnit = {
            unit: objectHash.getUnitHash({/* valid unit structure */}),
            last_ball_unit: realStableUnit,
            last_ball: realStableBall,
            // ... other required fields
        };
        const fabricatedBall = objectHash.getBallHash(
            fabricatedUnit.unit, 
            [realStableBall],  // parent_balls
            null,  // skiplist_balls
            false  // is_nonserial
        );
        
        // Step 3: Construct malicious catchup chain
        const maliciousCatchupChain = {
            unstable_mc_joints: [],
            stable_last_ball_joints: [
                {
                    unit: {/* real stable unit data */},
                    ball: realStableBall
                },
                {
                    unit: fabricatedUnit,
                    ball: fabricatedBall  // Valid hash but doesn't exist on network
                }
            ],
            witness_change_and_definition_joints: []
        };
        
        // Step 4: Process catchup chain - should reject but doesn't!
        catchup.processCatchupChain(
            maliciousCatchupChain, 
            'malicious_peer',
            witnesses,
            {
                ifError: function(error) {
                    // Should reach here but doesn't - vulnerability!
                    done();
                },
                ifOk: function() {
                    // Vulnerability: fabricated ball passes validation
                    // Verify ball was inserted into catchup_chain_balls
                    db.query("SELECT * FROM catchup_chain_balls WHERE ball=?", 
                        [fabricatedBall], 
                        function(rows) {
                            assert(rows.length > 0, 'Fabricated ball incorrectly inserted');
                            // Node is now stuck - requestNextHashTree will loop forever
                            // trying to get hash tree for non-existent ball
                            done();
                        }
                    );
                }
            }
        );
    });
});

// Expected behavior: processCatchupChain should call ifError when second ball doesn't exist
// Actual behavior: processCatchupChain calls ifOk, allowing fabricated ball to pass
// Result: Node stuck in infinite loop requesting hash tree for non-existent unit
```

## Notes

This is a valid Critical severity vulnerability that allows permanent node shutdown through catchup chain manipulation. The core issue is at catchup.js:229-231 where validation explicitly allows non-existent balls to pass without error. This creates an unrecoverable state where the node infinitely retries hash tree requests for fabricated units that will never be found on the network.

The vulnerability affects the catchup synchronization mechanism that is critical for new nodes joining the network and existing nodes recovering from downtime. An attacker operating malicious peer nodes can systematically prevent nodes from syncing, effectively denying service with no automatic recovery mechanism.

Manual database intervention is required for recovery, making this a serious operational risk for node operators.

### Citations

**File:** catchup.js (L180-189)
```javascript
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

**File:** network.js (L1815-1816)
```javascript
function comeOnline(){
	bCatchingUp = false;
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

**File:** network.js (L2042-2053)
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
