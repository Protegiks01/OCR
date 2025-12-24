# Audit Report

## Title
Hash Tree Poisoning via Unvalidated `is_nonserial` Parameter in Catchup Protocol

## Summary
The `processHashTree()` function in `catchup.js` accepts attacker-controlled `is_nonserial` values without validating their correctness against actual unit properties. A malicious peer can send hash trees with incorrect `is_nonserial` flags, causing fake ball hashes to be cached. This poisons the catchup state, preventing legitimate units from being accepted and triggering cascading validation failures for all descendant units, permanently blocking sync for affected nodes.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

**Affected Parties**: Nodes performing catchup synchronization (new nodes joining network, nodes recovering from downtime)

**Damage**: Affected nodes cannot complete sync and remain permanently out of sync until manual database cleanup. If multiple malicious peers exist, new nodes may be unable to join the network. Cascading failures affect all units referencing poisoned units as ancestors.

**Duration**: Indefinite (requires manual intervention to recover)

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: During catchup, hash trees provide compact DAG representation. The `is_nonserial` flag should accurately indicate whether a unit has `content_hash` (stripped payload). Ball hashes must be verified against actual unit structure.

**Actual Logic**: The `is_nonserial` parameter is received from the peer and used directly in ball hash verification without validation. At hash tree processing time, only unit hash, ball hash, parent balls, and skiplist balls are available - the full unit with `content_hash` field is not yet received. This allows attackers to provide incorrect `is_nonserial` values that compute valid-looking but fake ball hashes.

**Code Evidence**:

Ball hash verification using attacker-provided `is_nonserial`: [2](#0-1) 

Fake ball-unit mapping stored in cache: [3](#0-2) 

Legitimate unit rejection when ball not found: [4](#0-3) 

Parent ball lookup from poisoned hash tree: [5](#0-4) 

Ball hash validation using wrong parent balls: [6](#0-5) 

Failed cleanup allows fake entries to persist: [7](#0-6) 

**Exploitation Path**:

1. **Preconditions**: 
   - Victim node initiates catchup sync
   - Malicious peer selected as sync source
   - Legitimate serial unit U exists with ball `B_real = getBallHash(U, parents, skiplist, false)`

2. **Step 1 - Hash Tree Poisoning**:
   - Attacker sends hash tree via `handleHashTree()` → `processHashTree()`
   - Hash tree entry: `{ball: B_fake, unit: U, parent_balls: [...], skiplist_balls: [...], is_nonserial: true}`
   - Where `B_fake = getBallHash(U, parents, skiplist, true)` (computed with wrong flag)
   - Verification at line 363 passes: `B_fake === getBallHash(U, [...], [...], true)` ✓
   - Line 367 stores: `storage.assocHashTreeUnitsByBall[B_fake] = U`

3. **Step 2 - Legitimate Unit Rejection**:
   - Full unit U arrives with correct ball `B_real`
   - `validateHashTreeBall()` checks: `storage.assocHashTreeUnitsByBall[B_real]`
   - Returns undefined (only `B_fake` cached)
   - Line 389 rejects unit: "ball B_real is not known in hash tree"
   - Commented-out cleanup (line 1060-1061) means `B_fake` persists

4. **Step 3 - Cascading Failures**:
   - Child unit C references U as parent
   - `validateHashTreeParentsAndSkiplist()` calls `readBallsByUnits([U])`
   - Lines 414-417 search hash tree cache, find `B_fake` for unit U
   - Returns `B_fake` in parent_balls array
   - Line 402 computes: `getBallHash(C, [B_fake, ...], [...], ...)`
   - Actual unit C was created with `B_real` in parent_balls
   - Hash mismatch detected, line 404 rejects: "ball hash is wrong"

5. **Step 4 - Permanent Desync**:
   - All descendants of poisoned units fail validation
   - Node cannot advance past poisoned units
   - Sync permanently blocked until manual database cleanup

**Security Property Broken**: Catchup protocol integrity - syncing nodes must be able to retrieve and validate all units on the main chain without gaps or corruption.

**Root Cause**: The `is_nonserial` flag is determined by `content_hash` presence in the unit, but this information is unavailable during hash tree processing (only unit hash available). No mechanism exists to verify `is_nonserial` correctness until the full unit arrives, by which time the wrong mapping is already cached and used for descendant validation.

## Impact Explanation

**Affected Assets**: Network availability for syncing nodes, catchup protocol integrity

**Damage Severity**:
- **Quantitative**: All nodes syncing from malicious peer affected. Single poisoned unit blocks acceptance of all descendants (potentially thousands of units).
- **Qualitative**: Complete denial of service for catchup protocol. Indefinite transaction delay for affected nodes (>24 hours).

**User Impact**:
- **Who**: New nodes joining network, nodes recovering from downtime, any node performing catchup
- **Conditions**: Exploitable whenever node requests catchup from malicious peer (automatic peer selection)
- **Recovery**: Manual database cleanup required (delete `hash_tree_balls` and `catchup_chain_balls` tables, restart sync with honest peer)

**Systemic Risk**: Multiple malicious peers can prevent network growth. No automatic recovery. No rate limiting or peer reputation system.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Malicious peer node on Obyte network
- **Resources**: Ability to run peer node (minimal infrastructure)
- **Technical Skill**: Medium (understand catchup protocol and ball hash computation)

**Preconditions**:
- **Network State**: Victim performing catchup (common for new/recovering nodes)
- **Attacker State**: Selected as catchup peer (probabilistic)
- **Timing**: No specific timing required

**Execution Complexity**:
- **Transaction Count**: Zero (protocol-level attack)
- **Coordination**: Single malicious peer sufficient
- **Detection Risk**: Low (appears valid until full units arrive)

**Frequency**: Repeatable on every catchup attempt, affects arbitrary number of units

**Overall Assessment**: High likelihood - easily executable by any peer with minimal resources, affects critical network operation (syncing), no automatic mitigation.

## Recommendation

**Immediate Mitigation**:
Defer ball-unit mapping storage until full unit validation confirms `is_nonserial` correctness: [8](#0-7) 

Store hash tree balls in temporary database table, verify `is_nonserial` matches actual `content_hash` presence when full unit arrives.

**Permanent Fix**:
1. Add validation in `processHashTree()` to mark hash tree entries as unverified
2. In `validateHashTreeBall()`, verify `is_nonserial` correctness:
   - When unit has `content_hash`, ball must be computed with `is_nonserial=true`
   - When unit lacks `content_hash`, ball must be computed with `is_nonserial=false`
3. Reject units where hash tree `is_nonserial` doesn't match actual unit structure
4. Purge incorrectly-flagged hash tree entries

**Additional Measures**:
- Uncomment and fix cleanup logic at [7](#0-6) 
- Add test case verifying rejection of hash trees with incorrect `is_nonserial`
- Implement peer reputation system to blacklist peers sending invalid hash trees
- Add monitoring for hash tree validation failures

## Proof of Concept

**Note**: A complete runnable PoC would require:
1. Setting up two Obyte nodes (victim and malicious peer)
2. Modifying malicious peer's `readHashTree()` to send incorrect `is_nonserial`
3. Initiating catchup from victim to malicious peer
4. Observing unit rejection with "ball is not known in hash tree"
5. Observing cascading failures for child units

The vulnerability is evident from code analysis without requiring full PoC implementation, as the execution path is deterministic and the missing validation is clear.

---

## Notes

This vulnerability affects the catchup protocol's integrity but does not cause network-wide shutdown. The severity is **Medium** (not Critical as claimed) because it creates "Temporary Transaction Delay ≥1 Day" for affected syncing nodes, not network-wide consensus failure. Already-synced nodes continue operating normally. The impact escalates with multiple malicious peers but remains node-specific rather than system-wide.

### Citations

**File:** catchup.js (L336-476)
```javascript
function processHashTree(arrBalls, callbacks){
	if (!Array.isArray(arrBalls))
		return callbacks.ifError("no balls array");
	mutex.lock(["hash_tree"], function(unlock){
		
		db.query("SELECT 1 FROM hash_tree_balls LIMIT 1", function(ht_rows){
			//if (ht_rows.length > 0) // duplicate
			//    return unlock();
			
			db.takeConnectionFromPool(function(conn){
				
				conn.query("BEGIN", function(){
					
					var max_mci = null;
					async.eachSeries(
						arrBalls,
						function(objBall, cb){
							if (typeof objBall.ball !== "string")
								return cb("no ball");
							if (typeof objBall.unit !== "string")
								return cb("no unit");
							if (!storage.isGenesisUnit(objBall.unit)){
								if (!Array.isArray(objBall.parent_balls))
									return cb("no parents");
							}
							else if (objBall.parent_balls)
								return cb("genesis with parents?");
							if (objBall.ball !== objectHash.getBallHash(objBall.unit, objBall.parent_balls, objBall.skiplist_balls, objBall.is_nonserial))
								return cb("wrong ball hash, ball "+objBall.ball+", unit "+objBall.unit);

							function addBall(){
								storage.assocHashTreeUnitsByBall[objBall.ball] = objBall.unit;
								// insert even if it already exists in balls, because we need to define max_mci by looking outside this hash tree
								conn.query("INSERT "+conn.getIgnore()+" INTO hash_tree_balls (ball, unit) VALUES(?,?)", [objBall.ball, objBall.unit], function(){
									cb();
									//console.log("inserted unit "+objBall.unit, objBall.ball);
								});
							}
							
							function checkSkiplistBallsExist(){
								if (!objBall.skiplist_balls)
									return addBall();
								conn.query(
									"SELECT ball FROM hash_tree_balls WHERE ball IN(?) UNION SELECT ball FROM balls WHERE ball IN(?)",
									[objBall.skiplist_balls, objBall.skiplist_balls],
									function(rows){
										if (rows.length !== objBall.skiplist_balls.length)
											return cb("some skiplist balls not found");
										addBall();
									}
								);
							}

							if (!objBall.parent_balls)
								return checkSkiplistBallsExist();
							conn.query("SELECT ball FROM hash_tree_balls WHERE ball IN(?)", [objBall.parent_balls], function(rows){
								//console.log(rows.length+" rows", objBall.parent_balls);
								if (rows.length === objBall.parent_balls.length)
									return checkSkiplistBallsExist();
								var arrFoundBalls = rows.map(function(row) { return row.ball; });
								var arrMissingBalls = _.difference(objBall.parent_balls, arrFoundBalls);
								conn.query(
									"SELECT ball, main_chain_index, is_on_main_chain FROM balls JOIN units USING(unit) WHERE ball IN(?)", 
									[arrMissingBalls], 
									function(rows2){
										if (rows2.length !== arrMissingBalls.length)
											return cb("some parents not found, unit "+objBall.unit);
										for (var i=0; i<rows2.length; i++){
											var props = rows2[i];
											if (props.is_on_main_chain === 1 && (props.main_chain_index > max_mci || max_mci === null))
												max_mci = props.main_chain_index;
										}
										checkSkiplistBallsExist();
									}
								);
							});
						},
						function(error){
							
							function finish(err){
								conn.query(err ? "ROLLBACK" : "COMMIT", function(){
									conn.release();
									unlock();
									err ? callbacks.ifError(err) : callbacks.ifOk();
								});
							}

							if (error)
								return finish(error);
							
							// it is ok that max_mci === null as the 2nd tree does not touch finished balls
							//if (max_mci === null && !storage.isGenesisUnit(arrBalls[0].unit))
							//    return finish("max_mci not defined");
							
							// check that the received tree matches the first pair of chain elements
							conn.query(
								"SELECT ball, main_chain_index \n\
								FROM catchup_chain_balls LEFT JOIN balls USING(ball) LEFT JOIN units USING(unit) \n\
								ORDER BY member_index LIMIT 2", 
								function(rows){
									
									if (rows.length !== 2)
										return finish("expecting to have 2 elements in the chain");
									// removed: the main chain might be rebuilt if we are sending new units while syncing
								//	if (max_mci !== null && rows[0].main_chain_index !== null && rows[0].main_chain_index !== max_mci)
								//		return finish("max mci doesn't match first chain element: max mci = "+max_mci+", first mci = "+rows[0].main_chain_index);
									if (rows[1].ball !== arrBalls[arrBalls.length-1].ball)
										return finish("tree root doesn't match second chain element");
									// remove the oldest chain element, we now have hash tree instead
									conn.query("DELETE FROM catchup_chain_balls WHERE ball=?", [rows[0].ball], function(){
										
										purgeHandledBallsFromHashTree(conn, finish);
									});
								}
							);
						}
					);
				});
			});
		});
	});
}

function purgeHandledBallsFromHashTree(conn, onDone){
	conn.query("SELECT ball FROM hash_tree_balls CROSS JOIN balls USING(ball)", function(rows){
		if (rows.length === 0)
			return onDone();
		var arrHandledBalls = rows.map(function(row){ return row.ball; });
		arrHandledBalls.forEach(function(ball){
			delete storage.assocHashTreeUnitsByBall[ball];
		});
		conn.query("DELETE FROM hash_tree_balls WHERE ball IN(?)", [arrHandledBalls], function(){
			onDone();
		});
	});
}

exports.prepareCatchupChain = prepareCatchupChain;
exports.processCatchupChain = processCatchupChain;
exports.readHashTree = readHashTree;
exports.processHashTree = processHashTree;
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

**File:** validation.js (L414-417)
```javascript
			for (var ball in storage.assocHashTreeUnitsByBall){
				var unit = storage.assocHashTreeUnitsByBall[ball];
				if (arrUnits.indexOf(unit) >= 0 && arrBalls.indexOf(ball) === -1)
					arrBalls.push(ball);
```

**File:** network.js (L1060-1061)
```javascript
					//	if (objJoint.ball)
					//		db.query("DELETE FROM hash_tree_balls WHERE ball=? AND unit=?", [objJoint.ball, objJoint.unit.unit]);
```
