# Audit Report: Unbounded Recursion in Payload Size Calculation Causes Network-Wide Node Crash

## Summary

The `getLength()` function in `object_length.js` performs unbounded recursion when calculating unit payload sizes, lacking any depth limit or recursion counter. During validation at line 138, deeply nested data structures (~15,000 array nesting levels in a ~30KB payload) exhaust the JavaScript call stack, throwing uncaught `RangeError` exceptions that crash all nodes network-wide. [1](#0-0) 

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

A single malicious unit with deeply nested arrays crashes all validating nodes simultaneously, causing indefinite network downtime until emergency patching and unit blacklisting. All transaction processing halts, witness consensus stops, requiring coordinated manual intervention for recovery. The attack requires only minimal transaction fees (~$1) and affects all network participants.

## Finding Description

**Location**: [1](#0-0) 

Called from: [2](#0-1) 

**Intended Logic**: 
Validation should calculate unit payload size, verify it matches declared `payload_commission`, and gracefully reject malformed or oversized units without crashing the process.

**Actual Logic**: 

The `getLength()` function recursively traverses objects and arrays without any depth limit. For arrays, line 24 calls `getLength(element, bWithKeys)` recursively for each element. For objects, line 32 calls `getLength(value[key], bWithKeys)` recursively for each property. [3](#0-2) 

During validation, `getTotalPayloadSize()` is invoked WITHOUT try-catch protection to verify payload commission: [4](#0-3) 

This function calls `getLength()` to traverse the entire message structure including deeply nested payloads: [5](#0-4) 

**Exploitation Path**:

1. **Initial bypass of ratio check**: When the unit is first received via WebSocket, `getRatio()` is called at line 2594, which HAS try-catch protection and returns 1 on stack overflow, allowing the unit to pass this initial check. [6](#0-5) [7](#0-6) 

2. **Proceeds to validation**: The unit passes to `handleOnlineJoint()` which calls `handleJoint()`: [8](#0-7) 

3. **Hash calculation succeeds**: At validation line 66, `objectHash.getUnitHash()` is called with try-catch protection. This succeeds because `getNakedUnit()` deletes message payloads before hashing: [9](#0-8) [10](#0-9) 

4. **Unprotected size calculation**: At validation line 138, `getTotalPayloadSize()` is called WITHOUT try-catch protection. This call includes the full message payloads with deep nesting.

5. **Stack overflow occurs**: `getLength()` recursively descends through 15,000 nesting levels, exhausts the JavaScript call stack (~10,000-15,000 frames), and throws uncaught `RangeError: Maximum call stack size exceeded`.

6. **Process crashes**: The exception bubbles up through the call stack with no handler, terminating the Node.js process.

7. **Network-wide impact**: All nodes receiving the unit experience identical crashes and cannot recover until the unit is blacklisted.

**Security Property Broken**: 
Network Resilience Invariant - Nodes must validate and gracefully reject malformed units without crashing.

**Root Cause Analysis**:
- `getLength()` lacks depth parameter, recursion counter, or maximum depth check in its implementation
- No try-catch protection around `getTotalPayloadSize()` call at validation.js line 138
- While `getRatio()` has try-catch (returns 1 on error), and `getUnitHash()` has try-catch, the critical `getTotalPayloadSize()` call lacks protection
- AA depth validation with `MAX_DEPTH=100` exists at line 1577 but executes AFTER line 138 during message-specific validation, never reached due to earlier crash [11](#0-10) [12](#0-11) 

## Impact Explanation

**Affected Assets**: Network availability, all pending transactions, consensus mechanism, all user funds (inaccessible during downtime).

**Damage Severity**:
- **Quantitative**: Single ~30KB unit causes complete network shutdown. All nodes crash simultaneously. Network downtime continues indefinitely (hours to days) until coordinated emergency response. No transactions can be processed during outage.
- **Qualitative**: Total loss of network availability. Users cannot send transactions, witnesses cannot post heartbeat units, consensus mechanism halts completely.

**User Impact**:
- **Who**: All network participants - full nodes, witnesses, light clients attempting to validate, all users
- **Conditions**: Exploitable during any network state with no special preconditions required
- **Recovery**: Requires emergency coordination to blacklist malicious unit hash, deploy patched node software with depth limits, and restart all nodes

**Systemic Risk**:
- **Attack Cost**: Minimal (only transaction fees for single unit, estimated <$1)
- **Detection**: Attack succeeds before detection possible; nodes crash before logging malicious unit details
- **Repeatability**: Attacker can submit multiple such units with different hashes/content until network implements comprehensive blacklist

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with Obyte address capable of broadcasting units to network peers
- **Resources Required**: Minimal capital (transaction fees only, under $1 equivalent)
- **Technical Skill**: Low - generating deeply nested JSON arrays is trivial with any programming language (e.g., `Array(15000).fill(0).reduce((acc) => [acc], 0)`)

**Preconditions**:
- **Network State**: Normal operation; no special conditions required
- **Attacker State**: Only needs ability to broadcast units to any network peer
- **Timing**: No timing constraints; attack succeeds immediately upon validation by any node

**Execution Complexity**:
- **Transaction Count**: Single malicious unit sufficient for network-wide impact
- **Coordination**: No coordination required
- **Detection Risk**: None - attack succeeds before detection mechanisms can log or alert

**Frequency**:
- **Repeatability**: Unlimited - attacker can craft multiple variants with different nesting structures
- **Scale**: Single unit affects entire network simultaneously

**Overall Assessment**: Very High likelihood - Trivial to execute, guaranteed success, network-wide impact, minimal cost, no technical barriers.

## Recommendation

**Immediate Mitigation**:

Add depth limit parameter to `getLength()` function with maximum recursion depth check:

```javascript
// File: byteball/ocore/object_length.js
// Lines 9-40

function getLength(value, bWithKeys, depth = 0) {
    const MAX_RECURSION_DEPTH = 1000;
    if (depth > MAX_RECURSION_DEPTH)
        throw Error("maximum recursion depth exceeded");
    
    if (value === null)
        return 0;
    switch (typeof value){
        case "string": 
            return value.length;
        case "number": 
            if (!isFinite(value))
                throw Error("invalid number: " + value);
            return 8;
        case "object":
            var len = 0;
            if (Array.isArray(value))
                value.forEach(function(element){
                    len += getLength(element, bWithKeys, depth + 1);
                });
            else    
                for (var key in value){
                    if (typeof value[key] === "undefined")
                        throw Error("undefined at "+key+" of "+JSON.stringify(value));
                    if (bWithKeys)
                        len += key.length;
                    len += getLength(value[key], bWithKeys, depth + 1);
                }
            return len;
        case "boolean": 
            return 1;
        default:
            throw Error("unknown type="+(typeof value)+" of "+value);
    }
}
```

**Permanent Fix**:

Wrap size calculation calls in try-catch blocks to gracefully handle depth limit errors:

```javascript
// File: byteball/ocore/validation.js
// Lines 136-141

try {
    if (objectLength.getHeadersSize(objUnit) !== objUnit.headers_commission)
        return callbacks.ifJointError("wrong headers commission, expected "+objectLength.getHeadersSize(objUnit));
    if (objectLength.getTotalPayloadSize(objUnit) !== objUnit.payload_commission)
        return callbacks.ifJointError("wrong payload commission, unit "+objUnit.unit+", calculated "+objectLength.getTotalPayloadSize(objUnit)+", expected "+objUnit.payload_commission);
} catch(e) {
    return callbacks.ifJointError("payload size calculation failed: " + e);
}
```

**Additional Measures**:
- Add test case verifying deeply nested structures are rejected with clear error messages
- Add monitoring to track units with unusual nesting depths before they reach critical limits
- Document maximum nesting depth in protocol specification
- Consider applying same depth limits to `string_utils.js:getSourceString()` which has similar recursive pattern [13](#0-12) 

**Validation Checklist**:
- [ ] Fix prevents stack overflow with depth limit check
- [ ] Error messages clearly indicate nesting depth violations
- [ ] No performance regression for normal units with reasonable nesting
- [ ] Backward compatible (existing valid units still process correctly)
- [ ] Test coverage includes edge cases at and beyond depth limit

## Proof of Concept

```javascript
const test = require('ava');
const objectLength = require('../object_length.js');

test('deeply nested array causes stack overflow in getLength', t => {
    // Create deeply nested array: [[[[...]]]] with 15,000 levels
    let deeplyNested = 0;
    for (let i = 0; i < 15000; i++) {
        deeplyNested = [deeplyNested];
    }
    
    const testUnit = {
        messages: [{
            app: 'data',
            payload: {
                data: deeplyNested
            }
        }]
    };
    
    // This should throw RangeError: Maximum call stack size exceeded
    const error = t.throws(() => {
        objectLength.getTotalPayloadSize({
            version: '1.0',
            messages: testUnit.messages
        });
    });
    
    t.true(error instanceof RangeError);
    t.true(error.message.includes('Maximum call stack size exceeded'));
});

test('getRatio with deeply nested array returns 1 due to try-catch', t => {
    // Create deeply nested array
    let deeplyNested = 0;
    for (let i = 0; i < 15000; i++) {
        deeplyNested = [deeplyNested];
    }
    
    const testUnit = {
        version: '1.0',
        messages: [{
            app: 'data',
            payload: { data: deeplyNested }
        }]
    };
    
    // getRatio has try-catch, so it returns 1 instead of crashing
    const ratio = objectLength.getRatio(testUnit);
    t.is(ratio, 1); // Returns 1 on error, allowing unit to pass initial check
});
```

**Notes**:
- The vulnerability exists because while `getRatio()` (called early in network.js) has exception handling, `getTotalPayloadSize()` (called later in validation.js) does not
- The unit hash calculation at validation.js:66 also has try-catch and succeeds because `getNakedUnit()` strips message payloads before hashing
- This creates a scenario where the malicious unit passes early checks but crashes during deeper validation
- The 15,000 depth level is calculated to exceed typical JavaScript V8 stack limits of ~10,000-15,000 frames while keeping payload size under the 5MB MAX_UNIT_LENGTH limit
- Similar recursive pattern exists in `string_utils.js:getSourceString()` but is protected by try-catch in hash calculation context

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

**File:** validation.js (L138-139)
```javascript
		if (objectLength.getTotalPayloadSize(objUnit) !== objUnit.payload_commission)
			return callbacks.ifJointError("wrong payload commission, unit "+objUnit.unit+", calculated "+objectLength.getTotalPayloadSize(objUnit)+", expected "+objUnit.payload_commission);
```

**File:** validation.js (L1577-1577)
```javascript
			aa_validation.validateAADefinition(payload.definition, readGetterProps, objValidationState.last_ball_mci, function (err) {
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

**File:** object_hash.js (L41-45)
```javascript
	if (objNakedUnit.messages){
		for (var i=0; i<objNakedUnit.messages.length; i++){
			delete objNakedUnit.messages[i].payload;
			delete objNakedUnit.messages[i].payload_uri;
		}
```

**File:** aa_validation.js (L28-30)
```javascript
var MAX_DEPTH = 100;

function validateAADefinition(arrDefinition, readGetterProps, mci, callback) {
```

**File:** string_utils.js (L11-56)
```javascript
function getSourceString(obj) {
	var arrComponents = [];
	function extractComponents(variable){
		if (variable === null)
			throw Error("null value in "+JSON.stringify(obj));
		switch (typeof variable){
			case "string":
				arrComponents.push("s", variable);
				break;
			case "number":
				if (!isFinite(variable))
					throw Error("invalid number: " + variable);
				arrComponents.push("n", variable.toString());
				break;
			case "boolean":
				arrComponents.push("b", variable.toString());
				break;
			case "object":
				if (Array.isArray(variable)){
					if (variable.length === 0)
						throw Error("empty array in "+JSON.stringify(obj));
					arrComponents.push('[');
					for (var i=0; i<variable.length; i++)
						extractComponents(variable[i]);
					arrComponents.push(']');
				}
				else{
					var keys = Object.keys(variable).sort();
					if (keys.length === 0)
						throw Error("empty object in "+JSON.stringify(obj));
					keys.forEach(function(key){
						if (typeof variable[key] === "undefined")
							throw Error("undefined at "+key+" of "+JSON.stringify(obj));
						arrComponents.push(key);
						extractComponents(variable[key]);
					});
				}
				break;
			default:
				throw Error("getSourceString: unknown type="+(typeof variable)+" of "+variable+", object: "+JSON.stringify(obj));
		}
	}

	extractComponents(obj);
	return arrComponents.join(STRING_JOIN_CHAR);
}
```
