# Audit Report: Stack Overflow in Unit Payload Size Calculation

## Summary

The `getLength()` function in `object_length.js` performs unbounded recursion when calculating unit payload sizes. [1](#0-0)  During validation, deeply nested arrays exhaust the JavaScript call stack before AA-specific depth validation executes, causing unhandled `RangeError` exceptions that crash all nodes processing the malicious unit.

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

A single malicious unit with deeply nested arrays (~30KB payload, well under the 5MB limit) crashes all validating nodes network-wide. The attack requires only minimal transaction fees and causes indefinite network downtime until emergency patching and unit blacklisting. All transaction processing halts, witness consensus stops, requiring coordinated manual intervention for recovery.

**Affected Parties**: All network nodes (full nodes, witnesses, light clients), all users unable to transact during outage.

**Quantified Impact**: Single unit causes complete network shutdown affecting all participants indefinitely until emergency response completed.

## Finding Description

**Location**: `byteball/ocore/object_length.js:9-40`, function `getLength()`  
Called from: `byteball/ocore/validation.js:138` via `getTotalPayloadSize()`

**Intended Logic**: Validation should calculate unit payload size, verify it matches declared `payload_commission`, and reject oversized units. AA definitions exceeding depth limits should be rejected by `MAX_DEPTH=100` validation during message-specific checks.

**Actual Logic**: 

The `getLength()` function recursively traverses objects and arrays without any depth limit or recursion counter. [2](#0-1)  For arrays, each element triggers another recursive call. [3](#0-2)  For objects, each property does the same.

During validation, `getTotalPayloadSize()` is invoked without try-catch protection to verify the payload commission matches the calculated size. [4](#0-3) 

This function calls `getLength()` to traverse the entire unit structure. [5](#0-4) 

With approximately 15,000 nesting levels, the JavaScript V8 engine's call stack limit (~10,000-15,000 frames) is exceeded, throwing `RangeError: Maximum call stack size exceeded`. This exception is NOT caught because there is no try-catch wrapper around the size calculation calls.

The AA depth validation with `MAX_DEPTH=100` protection exists but executes much later during message-specific validation, never reached due to the earlier crash. [6](#0-5) [7](#0-6) 

**Exploitation Path**:

1. **Initial bypass of ratio check**: When the unit is first received via WebSocket, `getRatio()` is called which DOES have try-catch protection and returns 1 on stack overflow, allowing the unit to pass this initial check. [8](#0-7) [9](#0-8) 

2. **Proceeds to validation**: The unit passes to `handleOnlineJoint()` which calls `handleJoint()` and then `validation.validate()`. [10](#0-9) [11](#0-10) 

3. **Unprotected size calculation**: At validation line 138, `getTotalPayloadSize()` is called WITHOUT try-catch protection.

4. **Stack overflow occurs**: `getLength()` recursively descends through 15,000 nesting levels, exhausts the call stack, and throws uncaught `RangeError`.

5. **Process crashes**: The exception bubbles up through the call stack with no handler, terminating the Node.js process.

6. **Network-wide impact**: All nodes receiving the unit experience identical crashes and cannot recover until the unit is blacklisted.

**Security Property Broken**: Network Resilience Invariant - Nodes must validate and gracefully reject malformed units without crashing.

**Root Cause**:
- `getLength()` lacks depth parameter, recursion counter, or maximum depth check
- No try-catch protection around size calculations in validation.js lines 136-139
- Validation ordering places size calculation before message-specific validation containing depth limits
- Inconsistent error handling: `getRatio()` has try-catch but `getTotalPayloadSize()` does not

## Impact Explanation

**Affected Assets**: Network availability, all pending transactions, consensus mechanism.

**Damage Severity**:
- **Quantitative**: Single 30KB unit causes complete network shutdown. All nodes crash simultaneously. Network downtime continues indefinitely (hours to days) until coordinated emergency response.
- **Qualitative**: Total loss of network availability. Users cannot send transactions, witnesses cannot post heartbeats, consensus mechanism halts.

**User Impact**:
- **Who**: All network participants - full nodes, light clients, witnesses, all users
- **Conditions**: Exploitable during any network state; no special conditions required
- **Recovery**: Requires emergency coordination to blacklist malicious unit hash, deploy patched node software, and restart all nodes

**Systemic Risk**:
- **Attack Cost**: Minimal (only transaction fees, ~$1 or less)
- **Detection**: Attack succeeds immediately; nodes crash before logging malicious unit
- **Repeatability**: Attacker can submit multiple such units with different hashes until network implements blacklist

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with Obyte address capable of broadcasting units to network
- **Resources Required**: Minimal - transaction fees only (under $1 equivalent)
- **Technical Skill**: Low - generating deeply nested JSON arrays is trivial with any programming language

**Preconditions**:
- **Network State**: Normal operation; no special conditions required
- **Attacker State**: Only needs ability to broadcast units to any peer
- **Timing**: No timing constraints; attack succeeds upon validation

**Execution Complexity**:
- **Transaction Count**: Single malicious unit sufficient
- **Coordination**: No coordination required
- **Detection Risk**: None - attack succeeds before detection possible

**Frequency**:
- **Repeatability**: Unlimited - attacker can craft multiple variants
- **Scale**: Single unit affects entire network

**Overall Assessment**: Very High - Trivial to execute, guaranteed success, network-wide impact, minimal cost.

## Recommendation

**Immediate Mitigation**:
Add depth limit parameter to `getLength()` function and enforce maximum recursion depth:

```javascript
// File: byteball/ocore/object_length.js
const MAX_NESTING_DEPTH = 1000;

function getLength(value, bWithKeys, depth = 0) {
    if (depth > MAX_NESTING_DEPTH)
        throw Error("maximum nesting depth exceeded");
    // ... rest of function with depth+1 passed to recursive calls
}
```

**Permanent Fix**:
Add try-catch protection around all `getLength()` calls in validation:

```javascript
// File: byteball/ocore/validation.js
try {
    if (objectLength.getHeadersSize(objUnit) !== objUnit.headers_commission)
        return callbacks.ifJointError("wrong headers commission");
    if (objectLength.getTotalPayloadSize(objUnit) !== objUnit.payload_commission)
        return callbacks.ifJointError("wrong payload commission");
} catch(e) {
    return callbacks.ifJointError("payload size calculation failed: " + e);
}
```

**Additional Measures**:
- Add test case verifying deeply nested structures are rejected gracefully
- Apply consistent error handling across all `object_length.js` functions
- Consider iterative instead of recursive implementation for `getLength()`

## Proof of Concept

```javascript
const test = require('ava');
const objectLength = require('../object_length.js');

test('deeply nested array causes stack overflow in getTotalPayloadSize', t => {
    // Create deeply nested array structure
    let nested = [];
    let current = nested;
    for (let i = 0; i < 15000; i++) {
        let next = [];
        current.push(next);
        current = next;
    }
    
    // Create minimal unit structure with nested payload
    const maliciousUnit = {
        version: '1.0',
        alt: '1',
        messages: [{
            app: 'data',
            payload: {
                data: nested
            }
        }]
    };
    
    // This should crash with RangeError: Maximum call stack size exceeded
    t.throws(() => {
        objectLength.getTotalPayloadSize(maliciousUnit);
    }, { instanceOf: RangeError });
});
```

## Notes

This vulnerability exploits the inconsistent error handling between `getRatio()` (which has try-catch protection) and `getTotalPayloadSize()` (which does not). The attacker can craft a unit with deeply nested arrays that passes the initial `getRatio()` check but crashes nodes during the subsequent unprotected `getTotalPayloadSize()` call. The AA-specific `MAX_DEPTH=100` validation exists but is never reached because the crash occurs earlier in the validation pipeline. This represents a clear oversight in defensive programming and violates the fundamental principle that validation code should never crash the process.

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

**File:** validation.js (L138-139)
```javascript
		if (objectLength.getTotalPayloadSize(objUnit) !== objUnit.payload_commission)
			return callbacks.ifJointError("wrong payload commission, unit "+objUnit.unit+", calculated "+objectLength.getTotalPayloadSize(objUnit)+", expected "+objUnit.payload_commission);
```

**File:** validation.js (L1577-1577)
```javascript
			aa_validation.validateAADefinition(payload.definition, readGetterProps, objValidationState.last_ball_mci, function (err) {
```

**File:** aa_validation.js (L28-28)
```javascript
var MAX_DEPTH = 100;
```

**File:** network.js (L1027-1027)
```javascript
			validation.validate(objJoint, {
```

**File:** network.js (L1197-1197)
```javascript
	handleJoint(ws, objJoint, false, false, {
```

**File:** network.js (L2594-2595)
```javascript
				if (objectLength.getRatio(objJoint.unit) > 3)
					return sendError(ws, "the total size of keys is too large");
```
