# Validation Complete: VALID Vulnerability

After systematic validation against the Obyte security framework, I confirm this is a **VALID Medium severity vulnerability**.

## Title
AA State Variable Size Limit Bypass via `||=` Operator Enabling DoS Attacks

## Summary
The `||=` concatenation assignment operator in Autonomous Agents allows storing strings up to 4096 bytes in state variables by delegating validation to the `concat()` function, which checks against `MAX_AA_STRING_LENGTH` instead of the intended `MAX_STATE_VAR_VALUE_LENGTH` (1024 bytes). [1](#0-0)  This inconsistency enables attackers to poison AA state with oversized strings that cause subsequent `=` operator assignments to fail with fatal errors, creating denial-of-service conditions.

## Impact

**Severity**: Medium  
**Category**: Unintended AA Behavior

**Affected Assets**: AA state variables, user funds in vulnerable AAs

**Concrete Impact**:
- Autonomous Agents using both `||=` and `=` operators on the same state variables become vulnerable to permanent DoS
- Attackers can inject 1025-4096 byte strings that later cause fatal validation errors
- State poisoning persists permanently in kvstore with no recovery mechanism
- If poisoned variables are in critical paths (withdrawal logic, user registries), funds may become permanently inaccessible
- 4x storage cost inflation (4096 vs 1024 bytes) per poisoned variable

**Affected Parties**: Users of AAs that accept external input into state variables via `||=` operator, particularly registries, logging systems, and data aggregators

## Finding Description

**Location**: `byteball/ocore/formula/evaluation.js`, lines 1260-1273 and 2575-2604

**Intended Logic**: All state variable assignments should uniformly enforce `MAX_STATE_VAR_VALUE_LENGTH` (1024 bytes) to control storage costs and ensure consistent behavior across assignment operators.

**Actual Logic**: The `||=` operator bypasses this limit by using `concat()` which validates against `MAX_AA_STRING_LENGTH` (4096 bytes), creating a validation gap.

**Code Evidence**:

The `=` operator correctly enforces the 1024-byte limit: [2](#0-1) 

The `||=` operator uses `concat()` without additional validation: [3](#0-2) 

The `concat()` function validates against the wrong constant (4096 bytes): [4](#0-3) 

The result is stored directly without checking `MAX_STATE_VAR_VALUE_LENGTH`: [5](#0-4) 

Storage to database occurs without validation: [6](#0-5) 

**Exploitation Path**:

1. **Preconditions**: Target AA uses both `||=` (for accumulation) and `=` (for reassignment) on same state variables

2. **Step 1 - Poison State**:
   - Attacker sends trigger with large payload: `{ data: { payload: "A".repeat(3000) } }`
   - AA executes: `var['log'] ||= trigger.data.payload`
   - Validation: 3000 ≤ MAX_AA_STRING_LENGTH (4096) ✓ passes
   - Result: 3000-byte string stored in stateVars

3. **Step 2 - State Persisted**:
   - State persisted to kvstore without validation [7](#0-6) 
   - Database now contains oversized state variable (3000 bytes)

4. **Step 3 - Trigger Bounce**:
   - Legitimate user triggers: `var['processed'] = var['log']`
   - Validation: 3000 > MAX_STATE_VAR_VALUE_LENGTH (1024) ✗ fails [8](#0-7) 
   - Fatal error: "state var value too long"
   - **Entire AA execution bounces**

5. **Step 4 - Permanent Dysfunction**:
   - Any code path reading and reassigning poisoned variable will bounce
   - No recovery mechanism - poisoned state persists permanently

**Security Property Broken**: AA State Consistency - state variables should uniformly enforce 1024-byte limit across all assignment operators, but `||=` allows 4x larger values.

**Root Cause**: The `concat()` function was designed for temporary string operations during formula evaluation (where 4096-byte limit applies), but is incorrectly reused for state variable concatenation without enforcing the stricter persistent storage limit.

## Impact Explanation

**Affected Assets**: AA state variables, user funds in AAs with poisoned critical variables

**Damage Severity**:
- **Quantitative**: State variables can be 4x oversized (4096 vs 1024 bytes). Each poisoned variable causes permanent DoS on code paths using `=` operator.
- **Qualitative**: Cascading bounces prevent legitimate operations. Permanent AA dysfunction if critical variables are poisoned.

**User Impact**:
- **Who**: Users of AAs accepting external input into state via `||=` (registries, logging systems, escrow contracts)
- **Conditions**: AA must use both `||=` for updates and `=` for reassignment on same variables
- **Recovery**: No recovery mechanism - poisoned state persists permanently. Requires deploying new AA and migrating users/funds.

**Systemic Risk**: Common AA patterns are vulnerable (logging, data accumulation). Attack is trivially automatable and can target multiple AAs simultaneously.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with ability to trigger AA (no privileges required)
- **Resources Required**: Minimal transaction fees (~10,000 bytes)
- **Technical Skill**: Low (craft large payload in trigger data)

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Minimal byte balance for transaction fees
- **Timing**: No timing requirements

**Execution Complexity**:
- **Transaction Count**: 1-2 transactions (poison, verify bounce)
- **Coordination**: Single-actor attack
- **Detection Risk**: Low (appears as normal AA trigger)

**Overall Assessment**: High likelihood - trivial execution, minimal resources, affects plausible AA patterns.

## Recommendation

**Immediate Mitigation**:
Add validation check after concat() to enforce MAX_STATE_VAR_VALUE_LENGTH for `||=` operator assignments.

**Permanent Fix**:
Modify the `||=` operator handling to validate concatenation result against MAX_STATE_VAR_VALUE_LENGTH before storing:

```javascript
// File: byteball/ocore/formula/evaluation.js
// Around line 1270-1274

if (assignment_op === '||=') {
    var ret = concat(value, res);
    if (ret.error)
        return setFatalError("state var assignment: " + ret.error, cb, false);
    value = ret.result;
    // Add validation for state variable storage limit
    if (typeof value === 'string' && value.length > constants.MAX_STATE_VAR_VALUE_LENGTH)
        return setFatalError("state var value too long: " + value, cb, false);
}
```

**Additional Measures**:
- Add test case verifying both operators enforce same limit
- Review all state variable assignment operators for consistency
- Document intended size limits for state variables

## Proof of Concept

```javascript
// File: test/state_var_limit_bypass.test.js

var test = require('ava');
var constants = require("../constants.js");
var formulaParser = require('../formula/index');

constants.aa2UpgradeMci = 0;
constants.aa3UpgradeMci = 0;
constants.v4UpgradeMci = 0;

var objValidationState = {
    last_ball_mci: 1000,
    last_ball_timestamp: 1.5e9,
    mc_unit: "oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=",
    storage_size: 200,
    assocBalances: {},
    number_of_responses: 0,
    arrPreviousAAResponses: [],
    arrAugmentedMessages: []
};

function evalFormulaWithVars(opts, callback) {
    var val_opts = {
        formula: opts.formula,
        complexity: 1,
        count_ops: 0,
        bAA: true,
        bStateVarAssignmentAllowed: opts.bStateVarAssignmentAllowed,
        bStatementsOnly: opts.bStatementsOnly,
        mci: opts.objValidationState.last_ball_mci,
        readGetterProps: () => {},
        locals: {}
    };
    formulaParser.validate(val_opts, function(validation_res){
        if (validation_res.error) {
            return callback(null);
        }
        formulaParser.evaluate(opts, function (err, eval_res) {
            if (err)
                console.log("evaluation error: ", err);
            callback(eval_res, validation_res.complexity, validation_res.count_ops);
        });
    });
}

test.cb('state var size limit bypass via ||= operator - DoS attack', t => {
    var stateVars = {};
    
    // Step 1: Use ||= to store oversized string (3000 bytes, exceeds 1024 but within 4096)
    var largePayload = 'A'.repeat(3000);
    var trigger1 = { data: { payload: largePayload } };
    
    evalFormulaWithVars({ 
        conn: null,
        formula: "var['log'] ||= trigger.data.payload;", 
        trigger: trigger1, 
        stateVars: stateVars, 
        objValidationState: objValidationState, 
        address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU', 
        bStateVarAssignmentAllowed: true, 
        bStatementsOnly: true 
    }, (res1, complexity1) => {
        // First assignment should succeed (uses 4096 byte limit)
        t.deepEqual(res1, true);
        t.truthy(stateVars.MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU);
        t.truthy(stateVars.MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU.log);
        t.deepEqual(stateVars.MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU.log.value.length, 3000);
        
        // Step 2: Try to use = operator on same variable (should fail with 1024 byte limit)
        var trigger2 = {};
        evalFormulaWithVars({ 
            conn: null,
            formula: "var['processed'] = var['log'];", 
            trigger: trigger2, 
            stateVars: stateVars, 
            objValidationState: objValidationState, 
            address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU', 
            bStateVarAssignmentAllowed: true, 
            bStatementsOnly: true 
        }, (res2, complexity2) => {
            // Second assignment should FAIL because var['log'] is 3000 bytes (exceeds 1024)
            // This proves the vulnerability: ||= allows oversized storage, = rejects it
            t.deepEqual(res2, null); // null indicates fatal error occurred
            t.end();
        });
    });
});

test.cb('normal state var with = operator enforces 1024 limit correctly', t => {
    var stateVars = {};
    var largePayload = 'B'.repeat(1500); // Exceeds 1024 limit
    var trigger = { data: { payload: largePayload } };
    
    evalFormulaWithVars({ 
        conn: null,
        formula: "var['test'] = trigger.data.payload;", 
        trigger: trigger, 
        stateVars: stateVars, 
        objValidationState: objValidationState, 
        address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU', 
        bStateVarAssignmentAllowed: true, 
        bStatementsOnly: true 
    }, (res, complexity) => {
        // Should fail with = operator (correct behavior)
        t.deepEqual(res, null);
        t.end();
    });
});
```

## Notes

This vulnerability represents a **validation inconsistency** rather than a missing validation entirely. The `=` operator correctly enforces the 1024-byte limit, while the `||=` operator inadvertently bypasses it by delegating to `concat()` which uses a different constant intended for temporary formula evaluation strings, not persistent state storage.

The severity is Medium because:
1. It causes unintended AA behavior (permanent DoS of affected code paths)
2. It could escalate to High severity (permanent fund freeze) if the poisoned variable is in a critical withdrawal path
3. However, it requires specific AA design patterns (using both `||=` and `=` on same variables) and doesn't guarantee fund loss across all implementations

The fix is straightforward: add the same length validation after `concat()` returns that already exists for the `=` operator.

### Citations

**File:** constants.js (L63-65)
```javascript
exports.MAX_AA_STRING_LENGTH = 4096;
exports.MAX_STATE_VAR_NAME_LENGTH = 128;
exports.MAX_STATE_VAR_VALUE_LENGTH = 1024;
```

**File:** formula/evaluation.js (L1260-1265)
```javascript
							if (assignment_op === "=") {
								if (typeof res === 'string' && res.length > constants.MAX_STATE_VAR_VALUE_LENGTH)
									return setFatalError("state var value too long: " + res, cb, false);
								stateVars[address][var_name].value = res;
								stateVars[address][var_name].updated = true;
								return cb(true);
```

**File:** formula/evaluation.js (L1269-1274)
```javascript
							if (assignment_op === '||=') {
								var ret = concat(value, res);
								if (ret.error)
									return setFatalError("state var assignment: " + ret.error, cb, false);
								value = ret.result;
							}
```

**File:** formula/evaluation.js (L1302-1304)
```javascript
							stateVars[address][var_name].value = value;
							stateVars[address][var_name].updated = true;
							cb(true);
```

**File:** formula/evaluation.js (L2600-2602)
```javascript
			result = operand0.toString() + operand1.toString();
			if (result.length > constants.MAX_AA_STRING_LENGTH)
				return { error: "string too long after concat: " + result };
```

**File:** aa_composer.js (L1357-1361)
```javascript
				var key = "st\n" + address + "\n" + var_name;
				if (state.value === false) // false value signals that the var should be deleted
					batch.del(key);
				else
					batch.put(key, getTypeAndValue(state.value)); // Decimal converted to string, object to json
```
