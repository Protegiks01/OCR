# Audit Report

## Title
Missing Size Validation for `skiplist_units` Array Enables Database Bloat via Unhandled Joints

## Summary
The `saveUnhandledJointAndDependencies()` function in `joint_storage.js` stores entire joint objects without validating the size of `skiplist_units` arrays. When a malicious peer sends joints with missing parent units, validation terminates early before ball hash verification, allowing arbitrarily large `skiplist_units` arrays (containing 100,000+ unit hashes) to be serialized and stored as multi-megabyte JSON blobs in the database, causing resource exhaustion and processing delays.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay

**Affected Assets**: Database storage capacity, node processing resources, network synchronization speed

**Damage Severity**:
- **Quantitative**: Each malicious joint stores ~9MB JSON (5MB unit + 4MB skiplist array). Within the 1-hour purge window, 1000 such joints consume 9GB database storage. At 100 joints/minute, exhausts typical node storage capacity in hours.
- **Qualitative**: Database bloat degrades query performance; JSON parsing operations cause CPU spikes; memory pressure from loading large blobs.

**User Impact**:
- **Who**: All nodes receiving malicious joints from attacker peers; users submitting legitimate transactions
- **Conditions**: Attacker continuously sends malicious joints faster than 1-hour purge rate
- **Recovery**: Automatic purge after 1 hour per joint, but ongoing attack sustains bloat; manual database cleanup required

**Systemic Risk**: Coordinated attack from multiple malicious peers amplifies impact; cascading delays as nodes struggle to process backlog of legitimate units.

## Finding Description

**Location**: `byteball/ocore/joint_storage.js`, function `saveUnhandledJointAndDependencies()` [1](#0-0) 

**Intended Logic**: Unhandled joints with missing parent units should be temporarily stored with size limits to prevent database bloat.

**Actual Logic**: The validation flow only checks unit size (≤5MB) but not the full joint size. When parent units are missing, validation returns "unresolved_dependency" error before ball hash validation executes. The ball hash validation would detect invalid `skiplist_units` arrays, but it's never reached. The entire joint, including potentially enormous `skiplist_units` arrays, is serialized via `JSON.stringify()` and stored without size constraints.

**Exploitation Path**:

1. **Preconditions**: Attacker operates malicious peer node with P2P connection to victim node.

2. **Step 1**: Attacker crafts malicious joint with:
   - Valid unit structure (≤5MB per MAX_UNIT_LENGTH)
   - Ball hash field (any value - won't be verified)
   - `skiplist_units` array with 100,000+ unit hashes (4.4MB+)
   - Parent unit references that don't exist in victim's database

3. **Step 2**: Joint received via network without size validation [2](#0-1) . No check on full joint size before processing.

4. **Step 3**: Validation begins in `validation.js:validate()` [3](#0-2) . Joint structure validation only checks that `skiplist_units` is a non-empty array (line 94-96), with NO maximum count validation.

5. **Step 4**: Unit size validation checks only `headers_commission + payload_commission <= MAX_UNIT_LENGTH` [4](#0-3) . The `skiplist_units` array is NOT included in this size calculation.

6. **Step 5**: Parent validation in `validateParentsExistAndOrdered()` detects missing parents and returns error code "unresolved_dependency" [5](#0-4) .

7. **Step 6**: Validation terminates early, calling `ifNeedParentUnits()` callback [6](#0-5) . The `validateHashTreeParentsAndSkiplist()` function at line 275 is NEVER reached.

8. **Step 7**: Ball hash validation in `validateHashTreeParentsAndSkiplist()` [7](#0-6)  would have verified ball hash integrity (line 401-404), which would detect the invalid `skiplist_units` array, but this validation is skipped.

9. **Step 8**: `saveUnhandledJointAndDependencies()` is invoked [8](#0-7) , executing `JSON.stringify(objJoint)` to serialize the entire joint including the massive `skiplist_units` array [9](#0-8) .

10. **Step 9**: The 9MB+ JSON blob is inserted into the `unhandled_joints` table [10](#0-9) , which uses TEXT column with no size constraint.

11. **Outcome**: Database accumulates large JSON blobs. Repeated attacks within the 1-hour purge window [11](#0-10)  cause storage exhaustion and query performance degradation, delaying legitimate transaction processing.

**Security Property Broken**: Resource management invariant - the system should reject or limit storage of arbitrarily large data from untrusted peers to prevent resource exhaustion attacks.

**Root Cause Analysis**: 
- Missing maximum count validation on `skiplist_units` array elements (contrast with `parent_units` which has `MAX_PARENTS_PER_UNIT` check at validation.js:472-473) [12](#0-11) 
- Validation flow assumes joints requiring parent resolution will be fully validated later, but ball hash validation is skipped when parents are missing
- Normal protocol operation generates only ~log10(MCI) skiplist units (typically <10 elements) [13](#0-12) , but no code enforces this bound
- No full joint size validation before storage, only unit component size

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Operator of malicious peer node with P2P network connectivity
- **Resources Required**: Single peer connection; ability to craft valid unit structures (no cryptographic signatures needed for unhandled joints)
- **Technical Skill**: Medium - requires understanding of joint structure format and skiplist_units field

**Preconditions**:
- **Network State**: Target node accepting peer connections (default configuration)
- **Attacker State**: Established P2P connection to victim node
- **Timing**: No specific timing requirements; attack sustainable over extended periods

**Execution Complexity**:
- **Transaction Count**: 1000+ malicious joints to achieve significant database bloat
- **Coordination**: Single attacker sufficient; multiple malicious peers amplify effect
- **Detection Risk**: High after analysis - unusual joint sizes and missing parents pattern visible in logs

**Frequency**:
- **Repeatability**: Unlimited - attacker can continuously generate arbitrary joints
- **Scale**: Network-wide if multiple nodes targeted simultaneously

**Overall Assessment**: High likelihood - low technical barrier, no economic cost, sustainable attack model with direct network performance impact.

## Recommendation

**Immediate Mitigation**:
Add maximum count validation for `skiplist_units` array in `validation.js`:

```javascript
// In validation.js, around line 94-99
if ("skiplist_units" in objJoint){
    if (!isNonemptyArray(objJoint.skiplist_units))
        return callbacks.ifJointError("missing or empty skiplist array");
    if (objJoint.skiplist_units.length > constants.MAX_SKIPLIST_UNITS)
        return callbacks.ifJointError("too many skiplist units");
}
```

Define `MAX_SKIPLIST_UNITS` in `constants.js` with a reasonable value like 100 (normal operation uses ~7-10 elements).

**Permanent Fix**:
Implement full joint size validation before storage in `network.js` or `joint_storage.js`:

```javascript
// Validate total joint size before saveUnhandledJointAndDependencies()
var jointSize = JSON.stringify(objJoint).length;
if (jointSize > constants.MAX_JOINT_SIZE) {
    return callbacks.ifJointError("joint too large");
}
```

**Additional Measures**:
- Add monitoring to detect peers sending abnormally large joints
- Implement peer reputation system to ban repeat offenders
- Add test case verifying joints with excessive `skiplist_units` are rejected
- Database migration: Add CHECK constraint on json column size (if database supports it)

**Validation**:
- Fix prevents storage of malicious joints with oversized skiplist_units
- No impact on legitimate joints (which have <10 skiplist units)
- Backward compatible with existing valid units
- Performance impact negligible (simple array length check)

## Notes

This vulnerability exploits the asymmetry in validation: `parent_units` has explicit `MAX_PARENTS_PER_UNIT` anti-spam protection, but `skiplist_units` lacks equivalent protection. The normal protocol generates only logarithmic numbers of skiplist units (~log₁₀(MCI)), making 100,000+ elements completely anomalous and indicative of a validation gap rather than intentional design.

The attack is sustainable because the 1-hour purge window allows attackers to maintain constant database pressure by continuously sending new malicious joints before old ones are purged.

### Citations

**File:** joint_storage.js (L70-88)
```javascript
function saveUnhandledJointAndDependencies(objJoint, arrMissingParentUnits, peer, onDone){
	var unit = objJoint.unit.unit;
	assocUnhandledUnits[unit] = true;
	db.takeConnectionFromPool(function(conn){
		var sql = "INSERT "+conn.getIgnore()+" INTO dependencies (unit, depends_on_unit) VALUES " + arrMissingParentUnits.map(function(missing_unit){
			return "("+conn.escape(unit)+", "+conn.escape(missing_unit)+")";
		}).join(", ");
		var arrQueries = [];
		conn.addQuery(arrQueries, "BEGIN");
		conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO unhandled_joints (unit, json, peer) VALUES (?, ?, ?)", [unit, JSON.stringify(objJoint), peer]);
		conn.addQuery(arrQueries, sql);
		conn.addQuery(arrQueries, "COMMIT");
		async.series(arrQueries, function(){
			conn.release();
			if (onDone)
				onDone();
		});
	});
}
```

**File:** joint_storage.js (L333-345)
```javascript
function purgeOldUnhandledJoints(){
	db.query("SELECT unit FROM unhandled_joints WHERE creation_date < "+db.addTime("-1 HOUR"), function(rows){
		if (rows.length === 0)
			return;
		var arrUnits = rows.map(function(row){ return row.unit; });
		arrUnits.forEach(function(unit){
			delete assocUnhandledUnits[unit];
		});
		var strUnitsList = arrUnits.map(db.escape).join(', ');
		db.query("DELETE FROM dependencies WHERE unit IN("+strUnitsList+")");
		db.query("DELETE FROM unhandled_joints WHERE unit IN("+strUnitsList+")");
	});
}
```

**File:** network.js (L926-937)
```javascript
	var objJoint = response.joint;
	if (!objJoint.unit || !objJoint.unit.unit)
		return sendError(ws, 'no unit');
	var unit = objJoint.unit.unit;
	if (request.params !== unit)
		return sendError(ws, "I didn't request this unit from you: "+unit);
	if (conf.bLight && objJoint.ball && !objJoint.unit.content_hash){
		// accept it as unfinished (otherwise we would have to require a proof)
		delete objJoint.ball;
		delete objJoint.skiplist_units;
	}
	conf.bLight ? handleLightOnlineJoint(ws, objJoint) : handleOnlineJoint(ws, objJoint);
```

**File:** network.js (L1225-1227)
```javascript
				joint_storage.saveUnhandledJointAndDependencies(objJoint, arrMissingUnits, ws.peer, function(){
					delete assocUnitsInWork[unit];
				});
```

**File:** validation.js (L51-104)
```javascript
function validate(objJoint, callbacks, external_conn) {
	
	var objUnit = objJoint.unit;
	if (typeof objUnit !== "object" || objUnit === null)
		throw Error("no unit object");
	if (!objUnit.unit)
		throw Error("no unit");
	
	console.log("\nvalidating joint identified by unit "+objJoint.unit.unit);
	
	if (!isStringOfLength(objUnit.unit, constants.HASH_LENGTH))
		return callbacks.ifJointError("wrong unit length");
	
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}

	const bGenesis = storage.isGenesisUnit(objUnit.unit);

	var bAA = false;
	if (objJoint.aa) {
		bAA = true;
		delete objJoint.aa;
	}
	else {
		if (ValidationUtils.isArrayOfLength(objUnit.authors, 1) && !ValidationUtils.isNonemptyObject(objUnit.authors[0].authentifiers) && !objUnit.content_hash)
			return callbacks.ifTransientError("possible AA");
	}
	
	if (objJoint.unsigned){
		if (hasFieldsExcept(objJoint, ["unit", "unsigned"]))
			return callbacks.ifJointError("unknown fields in unsigned unit-joint");
	}
	else if ("ball" in objJoint){
		if (!isStringOfLength(objJoint.ball, constants.HASH_LENGTH))
			return callbacks.ifJointError("wrong ball length");
		if (hasFieldsExcept(objJoint, ["unit", "ball", "skiplist_units"]))
			return callbacks.ifJointError("unknown fields in ball-joint");
		if ("skiplist_units" in objJoint){
			if (!isNonemptyArray(objJoint.skiplist_units))
				return callbacks.ifJointError("missing or empty skiplist array");
			//if (objUnit.unit.charAt(0) !== "0")
			//    return callbacks.ifJointError("found skiplist while unit doesn't start with 0");
		}
	}
	else{
		if (hasFieldsExcept(objJoint, ["unit"]))
			return callbacks.ifJointError("unknown fields in unit-joint");
	}
```

**File:** validation.js (L140-141)
```javascript
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis)
			return callbacks.ifUnitError("unit too large");
```

**File:** validation.js (L325-326)
```javascript
							if (err.error_code === "unresolved_dependency")
								callbacks.ifNeedParentUnits(err.arrMissingUnits, err.dontsave);
```

**File:** validation.js (L396-434)
```javascript
function validateHashTreeParentsAndSkiplist(conn, objJoint, callback){
	if (!objJoint.ball)
		return callback();
	var objUnit = objJoint.unit;
	
	function validateBallHash(arrParentBalls, arrSkiplistBalls){
		var hash = objectHash.getBallHash(objUnit.unit, arrParentBalls, arrSkiplistBalls, !!objUnit.content_hash);
		if (hash !== objJoint.ball)
			return callback(createJointError("ball hash is wrong"));
		callback();
	}
	
	function readBallsByUnits(arrUnits, handleList){
		conn.query("SELECT ball FROM balls WHERE unit IN(?) ORDER BY ball", [arrUnits], function(rows){
			var arrBalls = rows.map(function(row){ return row.ball; });
			if (arrBalls.length === arrUnits.length)
				return handleList(arrBalls);
			// we have to check in hash_tree_balls too because if we were synced, went offline, and now starting to catch up, our parents will have no ball yet
			for (var ball in storage.assocHashTreeUnitsByBall){
				var unit = storage.assocHashTreeUnitsByBall[ball];
				if (arrUnits.indexOf(unit) >= 0 && arrBalls.indexOf(ball) === -1)
					arrBalls.push(ball);
			}
			arrBalls.sort();
			handleList(arrBalls);
		});
	}
	
	readBallsByUnits(objUnit.parent_units, function(arrParentBalls){
		if (arrParentBalls.length !== objUnit.parent_units.length)
			return callback(createJointError("some parents not found in balls nor in hash tree")); // while the child is found in hash tree
		if (!objJoint.skiplist_units)
			return validateBallHash(arrParentBalls, []);
		readBallsByUnits(objJoint.skiplist_units, function(arrSkiplistBalls){
			if (arrSkiplistBalls.length !== objJoint.skiplist_units.length)
				return callback(createJointError("some skiplist balls not found"));
			validateBallHash(arrParentBalls, arrSkiplistBalls);
		});
	});
```

**File:** validation.js (L472-473)
```javascript
	if (objUnit.parent_units.length > constants.MAX_PARENTS_PER_UNIT) // anti-spam
		return callback("too many parents: "+objUnit.parent_units.length);
```

**File:** validation.js (L491-495)
```javascript
			if (arrMissingParentUnits.length > 0){
				conn.query("SELECT error FROM known_bad_joints WHERE unit IN(?)", [arrMissingParentUnits], function(rows){
					(rows.length > 0)
						? callback("some of the unit's parents are known bad: "+rows[0].error)
						: callback({error_code: "unresolved_dependency", arrMissingUnits: arrMissingParentUnits});
```

**File:** initial-db/byteball-sqlite.sql (L391-396)
```sql
CREATE TABLE unhandled_joints (
	unit CHAR(44) NOT NULL PRIMARY KEY,
	peer VARCHAR(100) NOT NULL,
	json TEXT NOT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

**File:** main_chain.js (L1838-1851)
```javascript
function getSimilarMcis(mci){
	if (mci === 0)
		return [];
	var arrSimilarMcis = [];
	var divisor = 10;
	while (true){
		if (mci % divisor === 0){
			arrSimilarMcis.push(mci - divisor);
			divisor *= 10;
		}
		else
			return arrSimilarMcis;
	}
}
```
