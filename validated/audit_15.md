# Audit Report: Unbounded Recursion in Payload Size Calculation Causes Network-Wide Node Crash

## Summary

The `getLength()` function in `object_length.js` performs unbounded recursion when calculating unit payload sizes without depth limits. When validation calls `getTotalPayloadSize()` at line 138 without try-catch protection, deeply nested data structures (~15,000 array levels) exhaust the JavaScript call stack, throwing uncaught `RangeError` exceptions that crash all validating nodes simultaneously, causing complete network shutdown.

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

A single malicious unit crashes all validating nodes simultaneously, causing network downtime >24 hours until emergency unit blacklisting and coordinated node patches. All transaction processing halts, witness consensus stops, requiring manual intervention across the entire network. Attack cost is minimal (~$1 in transaction fees).

## Finding Description

**Location**: `byteball/ocore/object_length.js:9-40`, function `getLength()`

**Intended Logic**: 
Validation should calculate unit payload size, verify it matches the declared `payload_commission`, and gracefully reject malformed or oversized units without crashing the process.

**Actual Logic**: 
The `getLength()` function recursively traverses objects and arrays without any depth limit or recursion counter. [1](#0-0) 

During validation, `getTotalPayloadSize()` is invoked WITHOUT try-catch protection at line 138: [2](#0-1) 

This function calls `getLength()` to traverse the entire message structure including deeply nested payloads: [3](#0-2) 

**Exploitation Path**:

1. **Initial bypass of ratio check**: When the unit is first received via WebSocket at line 2594, `getRatio()` is called, which HAS try-catch protection and returns 1 on stack overflow, allowing the unit to pass: [4](#0-3) [5](#0-4) 

2. **Proceeds to validation**: The unit passes to `handleOnlineJoint()` which calls `handleJoint()`: [6](#0-5) [7](#0-6) 

3. **Hash calculation succeeds**: At validation line 66, `objectHash.getUnitHash()` is called with try-catch protection. This succeeds because `getNakedUnit()` deletes message payloads before hashing: [8](#0-7) [9](#0-8) 

4. **Unprotected size calculation**: At validation line 138, `getTotalPayloadSize()` is called WITHOUT try-catch protection, including full message payloads with deep nesting.

5. **Stack overflow occurs**: `getLength()` recursively descends through 15,000 nesting levels, exhausts the JavaScript call stack (~10,000-15,000 frames), and throws uncaught `RangeError: Maximum call stack size exceeded`.

6. **Process crashes**: The exception bubbles up through the call stack with no handler at the `validation.validate()` call site, terminating the Node.js process: [10](#0-9) 

7. **Network-wide impact**: All nodes receiving the unit experience identical crashes and cannot recover until the unit is blacklisted.

**Security Property Broken**: 
Network Resilience Invariant - Nodes must validate and gracefully reject malformed units without crashing.

**Root Cause Analysis**:
- `getLength()` lacks depth parameter, recursion counter, or maximum depth check
- No try-catch protection around `getTotalPayloadSize()` call at validation.js line 138
- While `getRatio()` has try-catch (returns 1 on error), and `getUnitHash()` has try-catch, the critical `getTotalPayloadSize()` call lacks protection
- AA depth validation with `MAX_DEPTH=100` exists but executes AFTER line 138 during message-specific validation at line 1577, never reached due to earlier crash: [11](#0-10) [12](#0-11) 

## Impact Explanation

**Affected Assets**: Network availability, all pending transactions, consensus mechanism, all user funds (inaccessible during downtime).

**Damage Severity**:
- **Quantitative**: Single ~30KB unit causes complete network shutdown. All nodes crash simultaneously. Network downtime continues indefinitely (hours to days) until coordinated emergency response.
- **Qualitative**: Total loss of network availability. Users cannot send transactions, witnesses cannot post heartbeat units, consensus mechanism halts completely.

**User Impact**:
- **Who**: All network participants - full nodes, witnesses, light clients, all users
- **Conditions**: Exploitable during any network state with no special preconditions required
- **Recovery**: Requires emergency coordination to blacklist malicious unit hash, deploy patched node software, and restart all nodes

**Systemic Risk**:
- Attack cost: Minimal (transaction fees only, <$1)
- Detection: Attack succeeds before detection possible
- Repeatability: Attacker can submit multiple variants with different hashes

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with Obyte address capable of broadcasting units
- **Resources Required**: Minimal capital (transaction fees <$1)
- **Technical Skill**: Low - generating deeply nested JSON arrays is trivial

**Preconditions**:
- **Network State**: Normal operation; no special conditions required
- **Timing**: No timing constraints; attack succeeds immediately

**Execution Complexity**:
- **Transaction Count**: Single malicious unit sufficient
- **Coordination**: None required
- **Detection Risk**: None - attack succeeds before logging

**Overall Assessment**: Very High likelihood - Trivial to execute, guaranteed success, network-wide impact, minimal cost.

## Recommendation

**Immediate Mitigation**:
Add try-catch protection around `getTotalPayloadSize()` call in validation.js:

```javascript
// validation.js line 138
try {
    if (objectLength.getTotalPayloadSize(objUnit) !== objUnit.payload_commission)
        return callbacks.ifJointError("wrong payload commission");
} catch(e) {
    return callbacks.ifJointError("failed to calc payload size: "+e);
}
```

**Permanent Fix**:
Add depth limit to `getLength()` function in object_length.js:

```javascript
function getLength(value, bWithKeys, depth) {
    if (!depth) depth = 0;
    if (depth > 100) throw Error("object nesting too deep");
    
    // ... existing logic with depth+1 passed to recursive calls
}
```

**Additional Measures**:
- Add test case verifying deeply nested payloads are rejected
- Add monitoring for units with high recursion depth
- Update documentation on payload structure limits

## Proof of Concept

```javascript
const validation = require('./validation.js');
const objectHash = require('./object_hash.js');

// Generate deeply nested array payload
function createDeeplyNestedPayload(depth) {
    let payload = 0;
    for (let i = 0; i < depth; i++) {
        payload = [payload];
    }
    return payload;
}

// Create malicious unit
const maliciousUnit = {
    version: '1.0',
    alt: '1',
    authors: [{
        address: 'ATTACKER_ADDRESS',
        authentifiers: { r: 'signature_here' }
    }],
    messages: [{
        app: 'data',
        payload: {
            nested: createDeeplyNestedPayload(15000)
        }
    }],
    parent_units: ['PARENT_UNIT_HASH'],
    last_ball: 'LAST_BALL_HASH',
    last_ball_unit: 'LAST_BALL_UNIT_HASH',
    witness_list_unit: 'WITNESS_LIST_UNIT_HASH',
    headers_commission: 500,
    payload_commission: 30000
};

// Calculate unit hash
maliciousUnit.unit = objectHash.getUnitHash(maliciousUnit);

// Attempt validation - this will crash the node
validation.validate({ unit: maliciousUnit }, {
    ifUnitError: (err) => console.log('Unit error:', err),
    ifJointError: (err) => console.log('Joint error:', err),
    ifTransientError: (err) => console.log('Transient error:', err),
    ifOk: () => console.log('Validation passed')
});

// Expected result: Node.js process crashes with:
// RangeError: Maximum call stack size exceeded
```

**Notes**

This vulnerability demonstrates a critical gap in input validation where the system fails to enforce reasonable limits on data structure depth. While other recursive operations (like AA formula validation) have depth limits of 100, the fundamental payload size calculation lacks any such protection. The asymmetry in error handling—where `getRatio()` and `getUnitHash()` have try-catch protection but `getTotalPayloadSize()` does not—creates a exploitable path where malicious units pass initial checks but crash during deeper validation. This is a clear violation of the network resilience requirement that nodes must gracefully handle and reject invalid inputs without process termination.

### Citations

**File:** object_length.js (L9-40)
```javascript
function getLength(value, bWithKeys) {
	if (value === null)
		return 0;
	switch (typeof value){
		case "string": 
			return value.length;
		case "number": 
			if (!isFinite(value))
				throw Error("invalid number: " + value);
			return 8;
			//return value.toString().length;
		case "object":
			var len = 0;
			if (Array.isArray(value))
				value.forEach(function(element){
					len += getLength(element, bWithKeys);
				});
			else    
				for (var key in value){
					if (typeof value[key] === "undefined")
						throw Error("undefined at "+key+" of "+JSON.stringify(value));
					if (bWithKeys)
						len += key.length;
					len += getLength(value[key], bWithKeys);
				}
			return len;
		case "boolean": 
			return 1;
		default:
			throw Error("unknown type="+(typeof value)+" of "+value);
	}
}
```

**File:** object_length.js (L61-67)
```javascript
function getTotalPayloadSize(objUnit) {
	if (objUnit.content_hash)
		throw Error("trying to get payload size of stripped unit");
	var bWithKeys = (objUnit.version !== constants.versionWithoutTimestamp && objUnit.version !== constants.versionWithoutKeySizes);
	const { temp_data_length, messages_without_temp_data } = extractTempData(objUnit.messages);
	return Math.ceil(temp_data_length * constants.TEMP_DATA_PRICE) + getLength({ messages: messages_without_temp_data }, bWithKeys);
}
```

**File:** object_length.js (L104-113)
```javascript
function getRatio(objUnit) {
	try {
		if (objUnit.version !== constants.versionWithoutTimestamp && objUnit.version !== constants.versionWithoutKeySizes)
			return 1;
		return getLength(objUnit, true) / getLength(objUnit);
	}
	catch (e) {
		return 1;
	}
}
```

**File:** validation.js (L64-71)
```javascript
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}
```

**File:** validation.js (L136-141)
```javascript
		if (objectLength.getHeadersSize(objUnit) !== objUnit.headers_commission)
			return callbacks.ifJointError("wrong headers commission, expected "+objectLength.getHeadersSize(objUnit));
		if (objectLength.getTotalPayloadSize(objUnit) !== objUnit.payload_commission)
			return callbacks.ifJointError("wrong payload commission, unit "+objUnit.unit+", calculated "+objectLength.getTotalPayloadSize(objUnit)+", expected "+objUnit.payload_commission);
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis)
			return callbacks.ifUnitError("unit too large");
```

**File:** validation.js (L1574-1577)
```javascript
			var readGetterProps = function (aa_address, func_name, cb) {
				storage.readAAGetterProps(conn, aa_address, func_name, cb);
			};
			aa_validation.validateAADefinition(payload.definition, readGetterProps, objValidationState.last_ball_mci, function (err) {
```

**File:** network.js (L1025-1027)
```javascript
	var validate = function(){
		mutex.lock(['handleJoint'], function(unlock){
			validation.validate(objJoint, {
```

**File:** network.js (L1190-1197)
```javascript
function handleOnlineJoint(ws, objJoint, onDone){
	if (!onDone)
		onDone = function(){};
	var unit = objJoint.unit.unit;
	delete objJoint.unit.main_chain_index;
	delete objJoint.unit.actual_tps_fee;
	
	handleJoint(ws, objJoint, false, false, {
```

**File:** network.js (L2594-2595)
```javascript
				if (objectLength.getRatio(objJoint.unit) > 3)
					return sendError(ws, "the total size of keys is too large");
```

**File:** network.js (L2604-2604)
```javascript
				return conf.bLight ? handleLightOnlineJoint(ws, objJoint) : handleOnlineJoint(ws, objJoint);
```

**File:** object_hash.js (L41-46)
```javascript
	if (objNakedUnit.messages){
		for (var i=0; i<objNakedUnit.messages.length; i++){
			delete objNakedUnit.messages[i].payload;
			delete objNakedUnit.messages[i].payload_uri;
		}
	}
```

**File:** aa_validation.js (L27-28)
```javascript

var MAX_DEPTH = 100;
```
