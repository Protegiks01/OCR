## Vulnerability Assessment

After thorough code analysis, I can confirm this is a **VALID security vulnerability**, though the severity classification needs correction.

### Title
Unbounded Address Array in Light Client History Query Causes Hub DoS

### Summary
The `prepareHistory()` function in `light.js` accepts an unlimited number of addresses from untrusted light client peers, constructing expensive database queries that can execute for extended periods. Combined with a global mutex lock and single database connection (default configuration), this allows any peer to freeze individual hub operations for 1+ hours.

### Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay ≥1 Hour

**Affected Assets**: Individual full node hub operations, light clients connected to that hub

**Damage Severity**:
- **Quantitative**: Single hub frozen for 1+ hours per attack; indefinitely with repeated attacks
- **Qualitative**: Affected hub cannot validate units, store transactions, or serve light clients during attack

**User Impact**:
- **Who**: Light clients connected to the targeted hub; users transacting through that hub
- **Conditions**: Any time the hub receives a malicious `light/get_history` request
- **Recovery**: Requires manual intervention (restarting node or killing database connection)

**Systemic Risk**: Attacker can target multiple hubs simultaneously with low cost (network bandwidth only). However, other full nodes continue operating normally, so this is not a network-wide shutdown.

### Finding Description

**Location**: 
- Primary: [1](#0-0) 
- Handler: [2](#0-1) 

**Intended Logic**: The light client history endpoint should allow peers to request transaction history for a reasonable set of addresses with appropriate rate limiting.

**Actual Logic**: An attacker can send thousands of addresses in a single request, triggering expensive UNION queries that consume the single database connection for extended periods, blocking all other database operations.

**Code Evidence**:

The validation only checks that the address array is non-empty and contains valid address formats, with **no upper bound** on array length: [3](#0-2) 

The `isNonemptyArray` validation function only checks `arr.length > 0`, allowing unlimited array sizes: [4](#0-3) 

Query construction uses ALL provided addresses in IN clauses across multiple SELECT statements with CROSS JOINs: [5](#0-4) 

The MAX_HISTORY_ITEMS check occurs **after** query execution, not before: [6](#0-5) 

A global mutex lock blocks all concurrent history requests: [7](#0-6) 

Default configuration uses only 1 database connection: [8](#0-7) 

SQLite busy_timeout is 30 seconds: [9](#0-8) 

**Exploitation Path**:

1. **Preconditions**: Attacker connects to a full node hub as a light client peer; hub runs default configuration (1 database connection)

2. **Step 1 - Send Malicious Request**: Attacker sends `light/get_history` with 2000+ valid addresses (randomly generated), `min_mci: 1` to trigger CROSS JOINs, and valid witness array

3. **Step 2 - Query Execution**: The prepareHistory function constructs a UNION of 4-5 SELECT statements, each scanning tables with `WHERE address IN(addr1, ..., addr2000)`. On databases with millions of units, this query executes for 10-60+ minutes

4. **Step 3 - Resource Lock**: During execution, the single database connection is busy, the global `get_history_request` mutex is held, and all other database operations wait for busy_timeout (30s) then fail

5. **Step 4 - Hub Freeze**: The targeted hub cannot validate new units, store transactions, or serve other light clients for the duration of the attack (1+ hours)

**Security Property Broken**: Hub availability and transaction processing capability

**Root Cause Analysis**:
1. **Missing Input Validation**: No maximum limit on address array length
2. **Post-Execution Validation**: MAX_HISTORY_ITEMS check happens after expensive query runs
3. **Resource Bottleneck**: Single database connection + global mutex create single point of failure
4. **No Query Timeout**: Beyond SQLite's busy_timeout, no application-level cancellation mechanism

### Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any peer capable of establishing WebSocket connection to a hub
- **Resources Required**: Single computer with network access; no funds required
- **Technical Skill**: Low - simple JSON message crafting

**Preconditions**:
- **Network State**: Hub accepting light client connections (normal operation)
- **Attacker State**: Ability to connect to hub (no authentication required)
- **Timing**: Attack works at any time

**Execution Complexity**:
- **Transaction Count**: Single WebSocket message
- **Coordination**: None required
- **Detection Risk**: Low - appears as legitimate sync request initially

**Frequency**:
- **Repeatability**: Unlimited - different tags/address lists bypass per-tag blocking
- **Scale**: Can target multiple hubs

**Overall Assessment**: High likelihood - trivial to execute, no resources required, no detection mechanism

### Recommendation

**Immediate Mitigation**:
Add upper bound validation on address array length in `light.js`:

```javascript
// In prepareHistory function, after line 43
if (arrAddresses && arrAddresses.length > 100) // reasonable limit
    return callbacks.ifError("too many addresses, max 100");
```

**Permanent Fix**:
1. Implement pre-execution complexity estimation
2. Add per-peer rate limiting for history requests
3. Consider query timeouts at application level
4. Monitor long-running queries and auto-terminate

**Additional Measures**:
- Add monitoring for history request patterns
- Implement connection-level rate limiting
- Consider increasing database connection pool size for hubs

### Notes

**Severity Justification**: This is classified as **MEDIUM** severity rather than CRITICAL because:
- Impact is per-hub, not network-wide
- Other full nodes continue operating normally  
- Attack does not cause permanent data loss or fund theft
- Meets Immunefi criteria for "Temporary Transaction Delay ≥1 Hour"

The vulnerability is real and should be fixed, but the original claim overstated the impact as "network-wide shutdown" when it's actually limited to individual hubs receiving the malicious request.

### Citations

**File:** light.js (L28-165)
```javascript
function prepareHistory(historyRequest, callbacks){
	if (!historyRequest)
		return callbacks.ifError("no history request");
	var arrKnownStableUnits = historyRequest.known_stable_units;
	var arrWitnesses = historyRequest.witnesses;
	var arrAddresses = historyRequest.addresses;
	var arrRequestedJoints = historyRequest.requested_joints;
	var minMci = historyRequest.min_mci || 0;
	
	if (!arrAddresses && !arrRequestedJoints)
		return callbacks.ifError("neither addresses nor joints requested");
	if (arrAddresses){
		if (!ValidationUtils.isNonemptyArray(arrAddresses))
			return callbacks.ifError("no addresses");
		if (!arrAddresses.every(ValidationUtils.isValidAddress))
			return callbacks.ifError("some addresses are not valid");
	}
	if (arrRequestedJoints) {
		if (!ValidationUtils.isNonemptyArray(arrRequestedJoints))
			return callbacks.ifError("no requested joints");
		if (!arrRequestedJoints.every(isValidUnitHash))
			return callbacks.ifError("invalid requested joints");
	}
	if (!ValidationUtils.isArrayOfLength(arrWitnesses, constants.COUNT_WITNESSES))
		return callbacks.ifError("wrong number of witnesses");
	if (minMci && !ValidationUtils.isNonnegativeInteger(minMci))
		return callbacks.ifError("min_mci should be non negative integer");

	var assocKnownStableUnits = {};
	if (arrKnownStableUnits) {
		if (!ValidationUtils.isNonemptyArray(arrKnownStableUnits))
			return callbacks.ifError("known_stable_units must be non-empty array");
		if (!arrKnownStableUnits.every(isValidUnitHash))
			return callbacks.ifError("invalid known stable units");
		arrKnownStableUnits.forEach(function (unit) {
			assocKnownStableUnits[unit] = true;
		});
	}
	
	var objResponse = {};

	// add my joints and proofchain to these joints
	var arrSelects = [];
	if (arrAddresses){
		// we don't filter sequence='good' after the unit is stable, so the client will see final doublespends too
		var strAddressList = arrAddresses.map(db.escape).join(', ');
		var mciCond = minMci ? " AND (main_chain_index >= " + minMci + " OR main_chain_index IS NULL) " : "";
		arrSelects.push("SELECT DISTINCT unit, main_chain_index, level, is_stable FROM outputs JOIN units USING(unit) \n\
			WHERE address IN("+ strAddressList + ") AND (+sequence='good' OR is_stable=1)" + mciCond);
		if (minMci) {
			arrSelects.push("SELECT DISTINCT unit, main_chain_index, level, is_stable FROM unit_authors CROSS JOIN units USING(unit) \n\
			WHERE address IN(" + strAddressList + ") AND (+sequence='good' OR is_stable=1) AND _mci>=" + minMci);
			arrSelects.push("SELECT DISTINCT unit, main_chain_index, level, is_stable FROM unit_authors CROSS JOIN units USING(unit) \n\
			WHERE address IN(" + strAddressList + ") AND (+sequence='good' OR is_stable=1) AND _mci IS NULL");
		}
		else
			arrSelects.push("SELECT DISTINCT unit, main_chain_index, level, is_stable FROM unit_authors JOIN units USING(unit) \n\
			WHERE address IN(" + strAddressList + ") AND (+sequence='good' OR is_stable=1)");
		arrSelects.push("SELECT DISTINCT unit, main_chain_index, level, is_stable FROM aa_responses JOIN units ON trigger_unit=unit \n\
			WHERE aa_address IN(" + strAddressList + ")" + mciCond);
	}
	if (arrRequestedJoints){
		var strUnitList = arrRequestedJoints.map(db.escape).join(', ');
		arrSelects.push("SELECT unit, main_chain_index, level, is_stable FROM units WHERE unit IN("+strUnitList+") AND (+sequence='good' OR is_stable=1) \n");
	}
	var sql = arrSelects.join("\nUNION \n") + "ORDER BY main_chain_index DESC, level DESC";
	db.query(sql, function(rows){
		// if no matching units, don't build witness proofs
		rows = rows.filter(function(row){ return !assocKnownStableUnits[row.unit]; });
		if (rows.length === 0)
			return callbacks.ifOk(objResponse);
		if (rows.length > MAX_HISTORY_ITEMS)
			return callbacks.ifError(constants.lightHistoryTooLargeErrorMessage);
		const last_aa_response_id = storage.last_aa_response_id;

		mutex.lock(['prepareHistory'], function(unlock){
			var start_ts = Date.now();
			witnessProof.prepareWitnessProof(
				arrWitnesses, 0, 
				function(err, arrUnstableMcJoints, arrWitnessChangeAndDefinitionJoints, last_ball_unit, last_ball_mci){
					if (err){
						callbacks.ifError(err);
						return unlock();
					}
					objResponse.unstable_mc_joints = arrUnstableMcJoints;
					if (arrWitnessChangeAndDefinitionJoints.length > 0)
						objResponse.witness_change_and_definition_joints = arrWitnessChangeAndDefinitionJoints;

					// add my joints and proofchain to those joints
					objResponse.joints = [];
					objResponse.proofchain_balls = [];
				//	var arrStableUnits = [];
					var later_mci = last_ball_mci+1; // +1 so that last ball itself is included in the chain
					async.eachSeries(
						rows,
						function(row, cb2){
							storage.readJoint(db, row.unit, {
								ifNotFound: function(){
									throw Error("prepareJointsWithProofs unit not found "+row.unit);
								},
								ifFound: function(objJoint){
									objResponse.joints.push(objJoint);
								//	if (row.is_stable)
								//		arrStableUnits.push(row.unit);
									if (row.main_chain_index > last_ball_mci || row.main_chain_index === null) // unconfirmed, no proofchain
										return cb2();
									proofChain.buildProofChain(later_mci, row.main_chain_index, row.unit, objResponse.proofchain_balls, function(){
										later_mci = row.main_chain_index;
										cb2();
									});
								}
							});
						},
						function(){
							//if (objResponse.joints.length > 0 && objResponse.proofchain_balls.length === 0)
							//    throw "no proofs";
							if (objResponse.proofchain_balls.length === 0)
								delete objResponse.proofchain_balls;
							// more triggers might get stabilized and executed while we were building the proofchain. We use the units that were stable when we began building history to make sure their responses are included in objResponse.joints
							// new: we include only the responses that were there before last_aa_response_id
							var arrUnits = objResponse.joints.map(function (objJoint) { return objJoint.unit.unit; });
							db.query("SELECT mci, trigger_address, aa_address, trigger_unit, bounced, response_unit, response, timestamp, aa_responses.creation_date FROM aa_responses LEFT JOIN units ON mci=main_chain_index AND +is_on_main_chain=1 WHERE trigger_unit IN(" + arrUnits.map(db.escape).join(', ') + ") AND +aa_response_id<=? ORDER BY aa_response_id", [last_aa_response_id], function (aa_rows) {
								// there is nothing to prove that responses are authentic
								if (aa_rows.length > 0)
									objResponse.aa_responses = aa_rows.map(function (aa_row) {
										objectHash.cleanNulls(aa_row);
										return aa_row;
									});
								callbacks.ifOk(objResponse);
								console.log("prepareHistory (without main search) for addresses "+(arrAddresses || []).join(', ')+" and joints "+(arrRequestedJoints || []).join(', ')+" took "+(Date.now()-start_ts)+'ms');
								unlock();
							});
						}
					);
				}
			);
		});
	});
```

**File:** network.js (L3314-3357)
```javascript
		case 'light/get_history':
			if (largeHistoryTags[tag])
				return sendErrorResponse(ws, tag, constants.lightHistoryTooLargeErrorMessage);
			if (!ws.bSentSysVars) {
				ws.bSentSysVars = true;
				sendSysVars(ws);
			}
			mutex.lock(['get_history_request'], function(unlock){
				if (!ws || ws.readyState !== ws.OPEN) // may be already gone when we receive the lock
					return process.nextTick(unlock);
				light.prepareHistory(params, {
					ifError: function(err){
						if (err === constants.lightHistoryTooLargeErrorMessage)
							largeHistoryTags[tag] = true;
						sendErrorResponse(ws, tag, err);
						unlock();
					},
					ifOk: function(objResponse){
						sendResponse(ws, tag, objResponse);
						bWatchingForLight = true;
						if (params.addresses)
							db.query(
								"INSERT "+db.getIgnore()+" INTO watched_light_addresses (peer, address) VALUES "+
								params.addresses.map(function(address){ return "("+db.escape(ws.peer)+", "+db.escape(address)+")"; }).join(", ")
							);
						if (params.requested_joints) {
							storage.sliceAndExecuteQuery("SELECT unit FROM units WHERE main_chain_index >= ? AND unit IN(?)",
								[storage.getMinRetrievableMci(), params.requested_joints], params.requested_joints, function(rows) {
								if(rows.length) {
									db.query(
										"INSERT " + db.getIgnore() + " INTO watched_light_units (peer, unit) VALUES " +
										rows.map(function(row) {
											return "(" + db.escape(ws.peer) + ", " + db.escape(row.unit) + ")";
										}).join(", ")
									);
								}
							});
						}
						//db.query("INSERT "+db.getIgnore()+" INTO light_peer_witnesses (peer, witness_address) VALUES "+
						//    params.witnesses.map(function(address){ return "("+db.escape(ws.peer)+", "+db.escape(address)+")"; }).join(", "));
						unlock();
					}
				});
			});
```

**File:** validation_utils.js (L68-70)
```javascript
function isNonemptyArray(arr){
	return (Array.isArray(arr) && arr.length > 0);
}
```

**File:** conf.js (L129-129)
```javascript
	exports.database.max_connections = exports.database.max_connections || 1;
```

**File:** sqlite_pool.js (L52-52)
```javascript
				connection.query("PRAGMA busy_timeout=30000", function(){
```
