# Audit Report

## Title
**Missing MCI Range Validation in Catchup Protocol Enables Memory Exhaustion DoS**

## Summary
The `readHashTree()` function in `catchup.js` lacks validation on Main Chain Index (MCI) range size, allowing malicious peers to request hash trees spanning arbitrary MCI ranges. [1](#0-0)  This causes the targeted node to query and accumulate potentially millions of unit records in memory, leading to memory exhaustion and node crash or severe degradation.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

**Affected Assets**: Individual full nodes, network availability for syncing peers

**Damage Severity**:
- **Quantitative**: With a network having 500,000 stable MCIs and 10 units/MCI, an attacker requesting a range from MCI 100 to MCI 500,000 would cause the node to load ~5 million unit records. At approximately 200-300 bytes per unit object (including ball hash, unit hash, parent_balls array, skiplist_balls array), this represents 1-1.5 GB in the `arrBalls` array alone. JSON stringification for network transmission can double memory usage to 2-3 GB, likely causing memory exhaustion on nodes with limited RAM.

- **Qualitative**: Individual node becomes unresponsive or crashes, requiring manual restart. During processing, the global mutex blocks all other catchup requests, preventing legitimate peers from syncing.

**User Impact**:
- **Who**: Operators of attacked full nodes, peers attempting to sync from attacked nodes
- **Conditions**: Any subscribed peer can execute the attack with minimal resources
- **Recovery**: Manual node restart required; attacker can immediately repeat the attack

**Systemic Risk**: If multiple publicly accessible nodes are attacked simultaneously, network-wide sync operations could be disrupted for ≥1 hour, meeting Medium severity threshold. However, this does not constitute a network-wide shutdown as witness nodes (typically operated by trusted parties with resources) are less likely to be vulnerable.

## Finding Description

**Location**: `byteball/ocore/catchup.js:256-334`, function `readHashTree()`

**Intended Logic**: The catchup protocol should allow peers to request hash trees for efficient synchronization, with reasonable limits to prevent resource exhaustion.

**Actual Logic**: The function validates that both ball hashes exist and are stable, and checks that `from_mci < to_mci` [2](#0-1) , but critically **does not validate the range size** (to_mci - from_mci). While `MAX_CATCHUP_CHAIN_LENGTH` is defined as 1,000,000 [3](#0-2) , this constant is used in `prepareCatchupChain()` but **not enforced in `readHashTree()`**.

**Code Evidence**:

The database query retrieves ALL units in the requested range without any LIMIT clause: [4](#0-3) 

All results are accumulated in the `arrBalls` array in memory: [5](#0-4) 

The network handler only checks subscription status before calling `readHashTree()`: [6](#0-5) 

A global mutex prevents concurrent hash tree requests but doesn't prevent a single malicious request from exhausting resources: [7](#0-6) 

The entire response is JSON stringified for network transmission: [8](#0-7) 

**Exploitation Path**:

1. **Preconditions**: 
   - Attacker establishes WebSocket connection to target full node
   - Network has accumulated substantial history (e.g., 500,000+ stable MCIs)

2. **Step 1**: Attacker subscribes to the node
   - Sends `subscribe` message with valid `subscription_id` and `library_version`
   - Subscription validated at [9](#0-8) 
   - Node responds with "subscribed"

3. **Step 2**: Attacker obtains two valid ball hashes
   - `from_ball` at low MCI (e.g., MCI 100)  
   - `to_ball` at high MCI (e.g., MCI 1,000,000)
   - These are publicly available from network explorers or previous sync operations

4. **Step 3**: Attacker sends malicious `get_hash_tree` request
   - Request processed by handler at [10](#0-9) 
   - Only subscription check performed (line 3071)
   - Global mutex acquired (line 3074), blocking all other catchup requests

5. **Step 4**: Node processes the unbounded request
   - `readHashTree()` validates balls exist and are stable ✓
   - Checks `from_mci < to_mci` (100 < 1,000,000) ✓
   - **Missing check**: Range size validation
   - Queries database for ALL units between MCI 100 and 1,000,000
   - For each unit, performs 2 additional queries (parents + skiplist)
   - Accumulates all results in `arrBalls` array
   - Memory consumption grows to multiple GB
   - Node becomes unresponsive or crashes with out-of-memory error
   - Global mutex remains held, blocking all catchup operations

**Security Property Broken**: 
Resource exhaustion protection - The protocol should enforce reasonable limits on resource-intensive operations to maintain node availability.

**Root Cause Analysis**: 
The `readHashTree()` function was designed for legitimate catchup where clients request consecutive catchup chain elements of bounded size. However, it exposes this functionality through the network layer without enforcing the `MAX_CATCHUP_CHAIN_LENGTH` limit that is used elsewhere in the catchup protocol. The code implicitly assumes honest peers will only request reasonable ranges, but malicious peers can exploit this missing validation.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any peer with network access
- **Resources Required**: WebSocket client, two valid ball hashes (publicly available), minimal bandwidth
- **Technical Skill**: Low (basic WebSocket programming)

**Preconditions**:
- **Network State**: Network must have accumulated sufficient history (>100K MCIs) for significant impact
- **Attacker State**: Ability to connect to target node (standard P2P access)
- **Timing**: No timing requirements; exploitable 24/7

**Execution Complexity**:
- **Transaction Count**: Zero blockchain transactions needed
- **Coordination**: None required; single-peer attack
- **Detection Risk**: Difficult to distinguish from legitimate sync requests until memory usage spikes

**Frequency**:
- **Repeatability**: Unlimited; can be repeated immediately after node restart
- **Scale**: Can target multiple publicly accessible full nodes

**Overall Assessment**: High likelihood - trivial to execute, low barrier to entry, repeatable attack.

## Recommendation

**Immediate Mitigation**:
Add range size validation in `readHashTree()` function:

```javascript
// File: catchup.js, in readHashTree() after line 285
if (to_mci - from_mci > MAX_CATCHUP_CHAIN_LENGTH)
    return callbacks.ifError("requested range too large: " + (to_mci - from_mci) + " MCIs, max is " + MAX_CATCHUP_CHAIN_LENGTH);
```

**Additional Measures**:
- Add rate limiting per peer for hash tree requests
- Implement streaming response instead of accumulating all results in memory
- Add monitoring/alerting for abnormally large hash tree requests
- Consider adding pagination to hash tree responses

**Validation**:
The fix should ensure that `readHashTree()` enforces the same `MAX_CATCHUP_CHAIN_LENGTH` limit used in `prepareCatchupChain()`, preventing unbounded queries while maintaining legitimate sync functionality.

## Notes

**Severity Classification**: The claim categorizes this as **Critical - Network Shutdown**, but the evidence supports **Medium - Temporary Transaction Delay**. Per Immunefi scope, Critical requires "network unable to confirm new transactions for >24 hours" with all nodes halted. This vulnerability affects individual nodes, not the entire network. While multiple nodes could be attacked simultaneously, there is insufficient evidence that this would cause >24 hour network-wide shutdown (witnesses are typically operated by trusted parties with resources, not all nodes are publicly accessible, and nodes can be restarted). However, it clearly meets Medium severity threshold (temporary delay ≥1 hour) as attacking multiple nodes would disrupt sync operations and potentially delay transaction confirmation.

**Proof of Concept**: The claim provides a clear exploitation path but lacks a complete runnable test. A proper PoC would require a test script that:
1. Starts a test node with realistic MCI history
2. Connects as a malicious peer
3. Subscribes successfully
4. Sends a `get_hash_tree` request with large MCI range
5. Demonstrates memory exhaustion or node unresponsiveness

The vulnerability is nevertheless valid based on clear code evidence showing missing validation.

### Citations

**File:** catchup.js (L14-14)
```javascript
var MAX_CATCHUP_CHAIN_LENGTH = 1000000; // how many MCIs long
```

**File:** catchup.js (L256-334)
```javascript
function readHashTree(hashTreeRequest, callbacks){
	if (!hashTreeRequest)
		return callbacks.ifError("no hash tree request");
	var from_ball = hashTreeRequest.from_ball;
	var to_ball = hashTreeRequest.to_ball;
	if (typeof from_ball !== 'string')
		return callbacks.ifError("no from_ball");
	if (typeof to_ball !== 'string')
		return callbacks.ifError("no to_ball");
	var start_ts = Date.now();
	var from_mci;
	var to_mci;
	db.query(
		"SELECT is_stable, is_on_main_chain, main_chain_index, ball FROM balls JOIN units USING(unit) WHERE ball IN(?,?)", 
		[from_ball, to_ball], 
		function(rows){
			if (rows.length !== 2)
				return callbacks.ifError("some balls not found");
			for (var i=0; i<rows.length; i++){
				var props = rows[i];
				if (props.is_stable !== 1)
					return callbacks.ifError("some balls not stable");
				if (props.is_on_main_chain !== 1)
					return callbacks.ifError("some balls not on mc");
				if (props.ball === from_ball)
					from_mci = props.main_chain_index;
				else if (props.ball === to_ball)
					to_mci = props.main_chain_index;
			}
			if (from_mci >= to_mci)
				return callbacks.ifError("from is after to");
			var arrBalls = [];
			var op = (from_mci === 0) ? ">=" : ">"; // if starting from 0, add genesis itself
			db.query(
				"SELECT unit, ball, content_hash FROM units LEFT JOIN balls USING(unit) \n\
				WHERE main_chain_index "+op+" ? AND main_chain_index<=? ORDER BY main_chain_index, `level`", 
				[from_mci, to_mci], 
				function(ball_rows){
					async.eachSeries(
						ball_rows,
						function(objBall, cb){
							if (!objBall.ball)
								throw Error("no ball for unit "+objBall.unit);
							if (objBall.content_hash)
								objBall.is_nonserial = true;
							delete objBall.content_hash;
							db.query(
								"SELECT ball FROM parenthoods LEFT JOIN balls ON parent_unit=balls.unit WHERE child_unit=? ORDER BY ball", 
								[objBall.unit],
								function(parent_rows){
									if (parent_rows.some(function(parent_row){ return !parent_row.ball; }))
										throw Error("some parents have no balls");
									if (parent_rows.length > 0)
										objBall.parent_balls = parent_rows.map(function(parent_row){ return parent_row.ball; });
									db.query(
										"SELECT ball FROM skiplist_units LEFT JOIN balls ON skiplist_unit=balls.unit WHERE skiplist_units.unit=? ORDER BY ball", 
										[objBall.unit],
										function(srows){
											if (srows.some(function(srow){ return !srow.ball; }))
												throw Error("some skiplist units have no balls");
											if (srows.length > 0)
												objBall.skiplist_balls = srows.map(function(srow){ return srow.ball; });
											arrBalls.push(objBall);
											cb();
										}
									);
								}
							);
						},
						function(){
							console.log("readHashTree for "+JSON.stringify(hashTreeRequest)+" took "+(Date.now()-start_ts)+'ms');
							callbacks.ifOk(arrBalls);
						}
					);
				}
			);
		}
	);
}
```

**File:** network.js (L109-109)
```javascript
	var message = JSON.stringify([type, content]);
```

**File:** network.js (L2980-3009)
```javascript
		case 'subscribe':
			if (!ValidationUtils.isNonemptyObject(params))
				return sendErrorResponse(ws, tag, 'no params');
			var subscription_id = params.subscription_id;
			if (typeof subscription_id !== 'string')
				return sendErrorResponse(ws, tag, 'no subscription_id');
			if ([...wss.clients].concat(arrOutboundPeers).some(function(other_ws) { return (other_ws.subscription_id === subscription_id); })){
				if (ws.bOutbound)
					db.query("UPDATE peers SET is_self=1 WHERE peer=?", [ws.peer]);
				sendErrorResponse(ws, tag, "self-connect");
				return ws.close(1000, "self-connect");
			}
			if (conf.bLight){
				//if (ws.peer === exports.light_vendor_url)
				//    sendFreeJoints(ws);
				return sendErrorResponse(ws, tag, "I'm light, cannot subscribe you to updates");
			}
			if (typeof params.library_version !== 'string') {
				sendErrorResponse(ws, tag, "invalid library_version: " + params.library_version);
				return ws.close(1000, "invalid library_version");
			}
			if (version2int(params.library_version) < version2int(constants.minCoreVersionForFullNodes))
				ws.old_core = true;
			if (ws.old_core){ // can be also set in 'version'
				sendJustsaying(ws, 'upgrade_required');
				sendErrorResponse(ws, tag, "old core (full)");
				return ws.close(1000, "old core (full)");
			}
			ws.bSubscribed = true;
			sendResponse(ws, tag, "subscribed");
```

**File:** network.js (L3070-3088)
```javascript
		case 'get_hash_tree':
			if (!ws.bSubscribed)
				return sendErrorResponse(ws, tag, "not subscribed, will not serve get_hash_tree");
			var hashTreeRequest = params;
			mutex.lock(['get_hash_tree_request'], function(unlock){
				if (!ws || ws.readyState !== ws.OPEN) // may be already gone when we receive the lock
					return process.nextTick(unlock);
				catchup.readHashTree(hashTreeRequest, {
					ifError: function(error){
						sendErrorResponse(ws, tag, error);
						unlock();
					},
					ifOk: function(arrBalls){
						// we have to wrap arrBalls into an object because the peer will check .error property first
						sendResponse(ws, tag, {balls: arrBalls});
						unlock();
					}
				});
			});
```
