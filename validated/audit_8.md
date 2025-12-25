# Audit Report: Stack Overflow in Unit Payload Size Calculation

## Summary

The `getLength()` function in `object_length.js` performs unbounded recursion when traversing nested data structures. During unit validation, `getTotalPayloadSize()` calls this function without depth limits or try-catch protection, allowing deeply nested AA definitions (~15,000 levels) to exhaust the JavaScript call stack and crash nodes before AA-specific depth validation executes. [1](#0-0) [2](#0-1) 

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

A single malicious unit with deeply nested arrays (~90KB, well under the 5MB limit) crashes all validating nodes network-wide. Attack cost is minimal (transaction fees only). Network remains offline until emergency patch deployment and unit blacklisting. All transaction processing halts, witness consensus stops, requiring manual intervention for recovery.

**Affected Parties**: All network nodes (full nodes, witnesses, light clients), all users unable to transact during outage.

**Quantified Impact**: Single unit causes indefinite network downtime affecting all participants. Recovery requires coordinated emergency response.

## Finding Description

**Location**: `byteball/ocore/object_length.js:9-40`, function `getLength()`  
Called from: `byteball/ocore/validation.js:138` via `getTotalPayloadSize()`

**Intended Logic**: 
Validation should calculate unit payload size, verify it matches `payload_commission`, and reject oversized units. AA definitions exceeding depth limits should be rejected by `MAX_DEPTH=100` validation during message-specific checks.

**Actual Logic**: 
At validation.js line 138, `getTotalPayloadSize()` is called without try-catch protection. [3](#0-2) 

This invokes `getLength()` which recursively traverses the entire unit structure including deeply nested AA definition payloads. [4](#0-3) 

The recursion has no depth limit - each array element triggers another recursive call, and each object property does the same. [5](#0-4) 

With ~15,000 nesting levels, the JavaScript V8 call stack limit is exceeded, throwing `RangeError: Maximum call stack size exceeded`. This exception is NOT caught because there's no try-catch around the size calculation.

The AA depth validation with `MAX_DEPTH=100` protection exists but executes much later at line 1577, never reached due to the earlier crash. [6](#0-5) [7](#0-6) [8](#0-7) 

**Exploitation Path**:

1. **Attacker creates deeply nested structure**: Programmatically generate `[[[[...15000 levels...]]]]]` and embed in AA definition: `['autonomous agent', {messages: [[[[...]]]]}]`

2. **Wrap in valid unit**: Create unit with `app: 'definition'` message, valid parents, witnesses, signatures, and correct hash

3. **Submit to network**: Broadcast via WebSocket to any peer [9](#0-8) 

4. **Node begins validation**: `handleOnlineJoint()` leads to `validation.validate()` [10](#0-9) 

5. **Size calculation triggers**: At validation.js line 138, `getTotalPayloadSize()` is called with no try-catch

6. **Unbounded recursion begins**: `getLength()` recursively descends through 15,000 nesting levels

7. **Stack exhausted**: After ~10,000-15,000 frames, V8 throws RangeError

8. **Uncaught exception**: No exception handler catches it - process terminates

9. **Network-wide crash**: All peers receiving the unit crash identically and cannot recover

**Security Property Broken**: 
Network Resilience Invariant - Nodes must validate and gracefully reject malformed units without crashing.

**Root Cause**:
- `getLength()` lacks depth parameter or recursion counter
- No try-catch protection around size calculations at validation.js:136-139
- Basic validation ordering places size calculation before message-specific validation
- AA depth protection exists but is bypassed by earlier crash

## Likelihood Explanation

**Attacker Profile**:
- Any user with Obyte address (no special permissions)
- Minimal resources: transaction fee only (~1,000 bytes)
- Low technical skill: generating nested JSON is trivial

**Preconditions**:
- Normal network operation
- No timing constraints
- Single malicious unit sufficient

**Execution Complexity**:
- Single unit submission
- No coordination required
- Trivial to script nested structure generation

**Overall Assessment**: Very High - Trivial to execute, causes network-wide impact, difficult to defend without code changes.

## Recommendation

**Immediate Mitigation**:
Add depth limit to `getLength()` function:

```javascript
// File: object_length.js
function getLength(value, bWithKeys, depth) {
    if (!depth) depth = 0;
    if (depth > 1000) // reasonable safety limit
        throw Error("structure too deeply nested");
    
    // existing logic, passing depth+1 to recursive calls
}
```

**Additional Measures**:
- Wrap size calculations in try-catch at validation.js:136-139 to convert exceptions to validation errors
- Add integration test verifying deeply nested structures are rejected gracefully
- Consider moving AA depth validation earlier in validation sequence

## Proof of Concept

```javascript
// test/stack_overflow.test.js
const composer = require('../composer.js');
const network = require('../network.js');

describe('Stack overflow protection', function() {
    it('should reject deeply nested AA definitions without crashing', async function() {
        // Generate 15,000 level nested array
        let nested = 0;
        for (let i = 0; i < 15000; i++) {
            nested = [nested];
        }
        
        // Create AA definition with deeply nested messages
        const definition = ['autonomous agent', {
            messages: nested
        }];
        
        // Create unit with this definition
        const unit = {
            version: '4.0',
            alt: '1',
            messages: [{
                app: 'definition',
                payload: {
                    address: 'MALICIOUS_ADDRESS',
                    definition: definition
                }
            }],
            authors: [/* valid author */],
            parent_units: [/* valid parents */],
            // ... other required fields
        };
        
        // Attempt validation - should reject gracefully, not crash
        try {
            await validation.validate({unit: unit}, {
                ifUnitError: (err) => {
                    assert(err.includes('too deeply nested') || err.includes('stack'));
                },
                ifJointError: (err) => {
                    assert(err.includes('too deeply nested') || err.includes('stack'));
                }
            });
        } catch (e) {
            // Process should NOT crash with RangeError
            assert.fail('Node crashed instead of rejecting unit gracefully');
        }
    });
});
```

## Notes

This vulnerability exists because:
1. Size calculation happens before message-specific validation
2. No depth limits in the recursive `getLength()` traversal
3. No exception handling around size calculations
4. JavaScript call stack limits (~10,000-15,000 frames) are lower than reasonable nesting depths for malicious payloads

The AA depth validation with `MAX_DEPTH=100` provides proper protection but is never reached due to the earlier crash during basic validation.

The fix requires either adding depth limits to `getLength()`, wrapping size calculations in try-catch, or both for defense in depth.

### Citations

**File:** object_length.js (L22-25)
```javascript
			if (Array.isArray(value))
				value.forEach(function(element){
					len += getLength(element, bWithKeys);
				});
```

**File:** object_length.js (L32-32)
```javascript
					len += getLength(value[key], bWithKeys);
```

**File:** object_length.js (L61-66)
```javascript
function getTotalPayloadSize(objUnit) {
	if (objUnit.content_hash)
		throw Error("trying to get payload size of stripped unit");
	var bWithKeys = (objUnit.version !== constants.versionWithoutTimestamp && objUnit.version !== constants.versionWithoutKeySizes);
	const { temp_data_length, messages_without_temp_data } = extractTempData(objUnit.messages);
	return Math.ceil(temp_data_length * constants.TEMP_DATA_PRICE) + getLength({ messages: messages_without_temp_data }, bWithKeys);
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

**File:** aa_validation.js (L471-473)
```javascript
			depth = 0;
		if (depth > MAX_DEPTH)
			return cb("cases for " + field + " go too deep");
```

**File:** network.js (L1026-1027)
```javascript
		mutex.lock(['handleJoint'], function(unlock){
			validation.validate(objJoint, {
```

**File:** network.js (L2583-2584)
```javascript
		case 'joint':
			var objJoint = body;
```
