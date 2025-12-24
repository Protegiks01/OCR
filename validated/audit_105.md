## Audit Report: Type Validation Bypass in AA Definition Cases Array Causes Network-Wide Node Crash

### Summary

The `hasCases()` function in `formula/common.js` validates only that `value.cases` is a non-empty array without checking element types. When an attacker submits an AA definition with non-object case elements (e.g., `null`), the synchronous validation loop in `validateFieldWrappedInCases()` attempts property access operations that throw uncaught TypeErrors, crashing all nodes that process the malicious unit.

### Impact

**Severity**: Critical  
**Category**: Network Shutdown / DoS

**Affected Assets**: All network nodes receiving and validating the malicious unit

**Damage Severity**:
- **Quantitative**: Single malicious unit crashes every node that processes it within seconds of network propagation
- **Qualitative**: Complete network outage requiring manual node restart; persistent crash loops if malicious unit remains in processing queue

**User Impact**:
- **Who**: All network participants (validators, wallets, users)
- **Conditions**: Attack succeeds whenever the malicious unit reaches validation stage
- **Recovery**: Manual node restart required; may need database cleanup for persistent crash loops

**Systemic Risk**: Network-wide DoS from single attacker-controlled unit; no rate limiting or validation caching prevents repeated exploitation

### Finding Description

**Location**: 
- `byteball/ocore/formula/common.js:90-92`, function `hasCases()`
- `byteball/ocore/aa_validation.js:469-514`, function `validateFieldWrappedInCases()`

**Intended Logic**: Validation should reject AA definitions with malformed case structures before runtime errors occur. Each case element must be validated as an object with proper structure before property access operations.

**Actual Logic**: The `hasCases()` function performs only shallow array validation without element type checking. [1](#0-0) 

Subsequently, `validateFieldWrappedInCases()` enters a synchronous for loop that directly accesses properties on case elements without type guards. [2](#0-1) 

When a case element is `null`, line 483 executes `hasOwnProperty(acase, field)` which internally calls `Object.prototype.hasOwnProperty.call(null, field)`, throwing `TypeError: Cannot convert undefined or null to object`. [3](#0-2) 

The `hasOwnProperty` implementation confirms this behavior: [4](#0-3) 

**Exploitation Path**:

1. **Preconditions**: Attacker can submit units to the Obyte network (any user capability)

2. **Step 1**: Attacker crafts unit with AA definition containing `messages: { cases: [null, {...}] }`

3. **Step 2**: Unit is broadcast via network propagation. When received, `network.handleJoint()` acquires mutex and calls `validation.validate()` [5](#0-4) 

4. **Step 3**: For AA definition validation, `aa_validation.validateAADefinition()` is invoked [6](#0-5) 

5. **Step 4**: The validation flow reaches `validateFieldWrappedInCases(template, 'messages', validateMessages, ...)` [7](#0-6) 

6. **Step 5**: `hasCases()` returns `true` because it only verifies array structure, not element types [1](#0-0) 

7. **Step 6**: Synchronous for loop executes at line 479-491. When `acase = null`, line 483 throws TypeError [3](#0-2) 

8. **Step 7**: No try-catch blocks exist in the call chain. The callback-based error handling pattern cannot catch synchronous exceptions. The TypeError propagates uncaught.

9. **Step 8**: No global `uncaughtException` handler exists in the codebase (verified via grep search showing zero matches)

10. **Step 9**: Node.js process crashes. All nodes receiving the unit experience identical crash.

**Security Property Broken**: 
- Validation errors should be handled gracefully through error callbacks, not via uncaught exceptions
- Network resilience requires validation to reject malformed inputs without process termination

**Root Cause Analysis**: 
Incomplete validation at two levels:
1. `hasCases()` delegates to `ValidationUtils.isNonemptyArray()` which only checks `Array.isArray()` and length [8](#0-7) 
2. `validateFieldWrappedInCases()` assumes all case elements are objects and performs direct property access without defensive type checking

### Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with ability to create and broadcast units
- **Resources Required**: Minimal (~1000 bytes for unit fees)
- **Technical Skill**: Low (craft JSON with `null` in cases array)

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Possession of bytes for unit fees
- **Timing**: No specific timing required

**Execution Complexity**:
- **Transaction Count**: Single malicious unit
- **Coordination**: None required
- **Detection Risk**: Low until crash occurs

**Frequency**:
- **Repeatability**: Unlimited
- **Scale**: Network-wide from single unit

**Overall Assessment**: High likelihood - trivial execution, minimal cost, immediate network-wide impact

### Recommendation

**Immediate Mitigation**:
Add type validation in `hasCases()` or at the start of the for loop in `validateFieldWrappedInCases()`:

```javascript
// Option 1: Enhance hasCases() in formula/common.js
function hasCases(value) {
    if (typeof value !== 'object' || Object.keys(value).length !== 1 || !ValidationUtils.isNonemptyArray(value.cases))
        return false;
    // Validate each case element is an object
    for (var i = 0; i < value.cases.length; i++) {
        if (typeof value.cases[i] !== 'object' || value.cases[i] === null || Array.isArray(value.cases[i]))
            return false;
    }
    return true;
}

// Option 2: Add validation in validateFieldWrappedInCases() before line 481
for (var i = 0; i < cases.length; i++){
    var acase = cases[i];
    if (typeof acase !== 'object' || acase === null || Array.isArray(acase))
        return cb('case ' + i + ' must be an object');
    // ... existing validation
}
```

**Permanent Fix**:
Add comprehensive type validation for case array elements before property access operations. Wrap synchronous validation in try-catch as defense-in-depth.

**Additional Measures**:
- Add test case verifying rejection of `null`, primitives, and arrays as case elements
- Add monitoring for validation crashes
- Consider wrapping all synchronous validation loops in try-catch to convert unexpected errors to error callbacks

**Validation**:
- [ ] Fix rejects all non-object case elements before property access
- [ ] No performance regression from additional type checks
- [ ] Backward compatible (existing valid AA definitions unaffected)
- [ ] Test coverage includes edge cases (null, undefined, primitives, arrays)

### Proof of Concept

```javascript
// Test case demonstrating the vulnerability
const validation = require('./validation.js');
const aa_validation = require('./aa_validation.js');

describe('AA Definition Case Type Validation', function() {
    it('should reject null case elements without crashing', function(done) {
        const maliciousDefinition = ['autonomous agent', {
            messages: {
                cases: [
                    null, // This will cause crash
                    {
                        messages: [{
                            app: 'payment',
                            payload: {
                                outputs: [{
                                    address: 'VALIDADDRESS000000000000000000',
                                    amount: 1000
                                }]
                            }
                        }],
                        if: '{trigger.data.test}'
                    }
                ]
            }
        }];

        aa_validation.validateAADefinition(maliciousDefinition, function(err) {
            // Should receive validation error, not crash
            expect(err).to.exist;
            expect(err).to.match(/case.*must be.*object/i);
            done();
        });
    });
});
```

### Notes

This vulnerability represents a critical gap in input validation where type assumptions are not enforced before property access operations. The synchronous nature of the validation loop combined with callback-based error handling creates a crash vector that affects all network nodes simultaneously.

The fix is straightforward: add explicit type validation for case array elements before accessing their properties. This aligns with the defensive programming pattern used elsewhere in the validation codebase where type checks precede property access.

### Citations

**File:** formula/common.js (L90-92)
```javascript
function hasCases(value) {
	return (typeof value === 'object' && Object.keys(value).length === 1 && ValidationUtils.isNonemptyArray(value.cases));
}
```

**File:** aa_validation.js (L479-491)
```javascript
		for (var i = 0; i < cases.length; i++){
			var acase = cases[i];
			if (hasFieldsExcept(acase, [field, 'if', 'init']))
				return cb('foreign fields in case ' + i + ' of ' + field);
			if (!hasOwnProperty(acase, field))
				return cb('case ' + i + ' has no field ' + field);
			if ('if' in acase && !isNonemptyString(acase.if))
				return cb('bad if in case: ' + acase.if);
			if (!('if' in acase) && i < cases.length - 1)
				return cb('if required in all but the last cases');
			if ('init' in acase && !isNonemptyString(acase.init))
				return cb('bad init in case: ' + acase.init);
		}
```

**File:** aa_validation.js (L740-740)
```javascript
	validateFieldWrappedInCases(template, 'messages', validateMessages, function (err) {
```

**File:** validation_utils.js (L68-70)
```javascript
function isNonemptyArray(arr){
	return (Array.isArray(arr) && arr.length > 0);
}
```

**File:** validation_utils.js (L103-105)
```javascript
function hasOwnProperty(obj, prop) {
	return Object.prototype.hasOwnProperty.call(obj, prop);
}
```

**File:** network.js (L1026-1027)
```javascript
		mutex.lock(['handleJoint'], function(unlock){
			validation.validate(objJoint, {
```

**File:** validation.js (L1577-1577)
```javascript
			aa_validation.validateAADefinition(payload.definition, readGetterProps, objValidationState.last_ball_mci, function (err) {
```
