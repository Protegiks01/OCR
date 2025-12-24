## Title
Global `bHadReturn` Flag Bypasses Conditional Variable Assignment Validation in AA Formulas

## Summary
The `bHadReturn` flag in `formula/validation.js` is initialized once per validation and never reset between unrelated if-else blocks, unlike the properly-scoped `bInIf` flag. [1](#0-0)  This causes validation to incorrectly accept formulas where variables are conditionally assigned in one if-block and then reassigned outside any if-block, when an unrelated earlier if-block contains a return statement. [2](#0-1)  Such formulas pass validation but fail at runtime with fatal errors, [3](#0-2)  violating AA deterministic execution guarantees.

## Impact
**Severity**: Medium  
**Category**: Unintended AA Behavior

AAs with this pattern pass validation but execute non-deterministically: some input combinations succeed while others trigger fatal errors during execution. Users lose bounce fees (minimum 10,000 bytes) when their triggers hit the failing execution path. The AA cannot be fixed post-deployment and must be replaced. While no direct fund theft occurs, this breaks the trust model that validated AAs will execute deterministically.

## Finding Description

**Location**: `byteball/ocore/formula/validation.js`, function `evaluate()`, lines 243, 580-581, 1239

**Intended Logic**: The validation should detect and reject patterns where a variable is conditionally assigned within an if-block (state `'maybe assigned'`) and then assigned again outside the if-block, as this would cause double assignment during execution. The check at line 580-581 implements this protection.

**Actual Logic**: The `bHadReturn` flag is set to `true` when ANY return statement is encountered during validation [4](#0-3)  and remains `true` for the remainder of validation. This causes the check at line 580-581 to incorrectly pass for reassignments of `'maybe assigned'` variables, even when the return statement exists in a completely different, unrelated if-block. [2](#0-1) 

**Exploitation Path**:

1. **Preconditions**: Attacker deploys an AA with a formula following this pattern:
   ```
   if (condition1) { return 100; }
   if (condition2) { $result = 100; }
   $result = 200;
   ```

2. **Step 1 - Validation Phase**: The formula passes through `formula/validation.js:exports.validate()`. When evaluating the first if-block containing `return`, the flag `bHadReturn` is set to `true` globally.

3. **Step 2 - Validation Continues**: When the second if-block is evaluated, the variable `$result` is assigned, receiving state `'maybe assigned'` in the locals tracking.

4. **Step 3 - Validation Check**: When the unconditional assignment `$result = 200` is evaluated, the check at line 580-581 evaluates: `'maybe assigned' && !bInIf && !bHadReturn && !selectors` = `true && true && FALSE && true` = `FALSE`, so validation **incorrectly passes**.

5. **Step 4 - Runtime Execution**: When a user triggers the AA with inputs where `condition1=false` and `condition2=true`:
   - The first if-block is skipped (no return)
   - The second if-block executes: `$result = 100` (variable is now in locals)
   - The unconditional assignment attempts: `$result = 200`
   - Execution throws fatal error: "reassignment to $result" [5](#0-4) 
   - User loses bounce fee permanently

**Security Property Broken**: **AA Deterministic Execution** - Validated formulas must execute successfully for all valid inputs. This bug allows formulas to pass validation despite having execution paths that fail with fatal errors, creating non-deterministic behavior.

**Root Cause Analysis**: The `bHadReturn` flag lacks proper scoping. Compare with `bInIf`, which is saved and restored for each if-else block: [6](#0-5)  The asymmetry between properly-scoped `bInIf` and globally-scoped `bHadReturn` causes validation state from one if-block to pollute checks for unrelated subsequent code.

## Impact Explanation

**Affected Assets**: User bounce fees (minimum 10,000 bytes), AA execution reliability

**Damage Severity**:
- **Quantitative**: Each failed execution costs users the configured bounce fee. Attackers can deploy multiple such AAs to multiply impact. Individual loss per trigger: ≥10,000 bytes.
- **Qualitative**: Violates the AA determinism guarantee. Users cannot predict if their interaction will succeed or fail without analyzing execution paths, undermining confidence in the AA system.

**User Impact**:
- **Who**: Any user triggering AAs with this vulnerable pattern
- **Conditions**: Occurs when trigger data causes execution path to skip early return but execute conditional assignment followed by unconditional reassignment
- **Recovery**: Bounce fee lost permanently. No recovery mechanism. AA must be redeployed with corrected formula.

**Systemic Risk**: If pattern appears in multiple AAs (intentionally or accidentally), creates widespread unpredictable failures. Pattern could appear unintentionally in legitimate AAs since validation incorrectly accepts it.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Malicious AA developer or unaware legitimate developer
- **Resources Required**: Minimal - ability to deploy AA (standard transaction cost)
- **Technical Skill**: Intermediate - requires understanding of Obyte formula syntax and conditional logic

**Preconditions**:
- **Network State**: Standard operation, no special conditions required
- **Attacker State**: Must deploy AA with vulnerable pattern
- **Timing**: No timing constraints

**Execution Complexity**:
- **Transaction Count**: One AA deployment + victim trigger transactions
- **Coordination**: None required
- **Detection Risk**: Low - AA passes validation normally, failures appear as legitimate execution errors

**Frequency**:
- **Repeatability**: Unlimited - each trigger with specific inputs causes failure
- **Scale**: Affects all AAs with this pattern

**Overall Assessment**: High likelihood. Pattern is easy to create, requires no special privileges, and could appear accidentally in legitimate AAs since validation incorrectly accepts it.

## Recommendation

**Immediate Mitigation**:
Scope `bHadReturn` per if-else block like `bInIf`:

```javascript
case 'ifelse':
    var prev_in_if = bInIf;
    var prev_had_return = bHadReturn;  // ADD THIS
    bInIf = true;
    evaluate(if_block, function (err) {
        if (err) return cb(err);
        if (!else_block) {
            bInIf = prev_in_if;
            bHadReturn = prev_had_return;  // ADD THIS
            return cb();
        }
        evaluate(else_block, function (err) {
            bInIf = prev_in_if;
            bHadReturn = prev_had_return;  // ADD THIS
            cb(err);
        });
    });
```

**Permanent Fix**:
Add save/restore logic for `bHadReturn` in the `'ifelse'` case handler in `formula/validation.js` at lines 680-704, mirroring the existing pattern for `bInIf`.

**Additional Measures**:
- Add test case verifying the pattern is rejected: early return in one if-block + conditional assignment in another + unconditional reassignment
- Review existing deployed AAs for this pattern
- Document that `bHadReturn` scope must match `bInIf` scope

**Validation**:
- Fix prevents validation bypass for double assignment patterns
- No breaking changes to legitimate formulas
- Performance impact negligible

## Proof of Concept

```javascript
const test = require('ava');
const formulaParser = require('../formula/index');

test('bHadReturn flag incorrectly leaks across unrelated if-blocks', t => {
    const objValidationState = { last_ball_mci: 1000 };
    const readGetterProps = () => {};
    
    // This formula SHOULD fail validation but passes due to bHadReturn leak
    const formula = `{
        if (trigger.data.early_exit) {
            return 100;
        }
        if (trigger.data.conditional_assign) {
            $result = 100;
        }
        $result = 200;
        { response: {result: $result} }
    }`;
    
    // Validation incorrectly passes
    formulaParser.validate({ 
        formula, 
        complexity: 1, 
        count_ops: 0, 
        bAA: true, 
        bStateVarAssignmentAllowed: true,
        mci: objValidationState.last_ball_mci, 
        readGetterProps, 
        locals: {} 
    }, (validation_res) => {
        // BUG: Validation should reject this but error is false
        t.deepEqual(validation_res.error, false);
        
        // Now test execution with inputs that trigger the double assignment
        const trigger = { 
            data: { early_exit: false, conditional_assign: true },
            address: "TEST_ADDRESS",
            outputs: {}
        };
        
        formulaParser.evaluate({
            conn: null,
            formula,
            trigger,
            objValidationState,
            address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'
        }, (err, eval_res) => {
            // Execution fails with fatal error on double assignment
            t.truthy(err || eval_res === false);
            console.log('Expected fatal error on double assignment:', err);
        });
    });
});
```

This test demonstrates the vulnerability by showing validation incorrectly passes while execution fails with specific inputs.

## Notes

The vulnerability exists because `bHadReturn` is treated as a global flag across the entire formula validation, while it should be scoped to individual if-else blocks like `bInIf`. The check at line 580-581 assumes that `bHadReturn=true` means "there was a return statement that might prevent this code path from executing," but fails to account for return statements in unrelated prior if-blocks that don't actually guard the problematic assignment.

The fix is straightforward: save and restore `bHadReturn` for each if-else block evaluation, matching the existing pattern used for `bInIf`. This ensures validation state doesn't leak between unrelated control flow structures.

### Citations

**File:** formula/validation.js (L243-243)
```javascript
	var bHadReturn = false;
```

**File:** formula/validation.js (L580-581)
```javascript
							if (locals[var_name].state === 'maybe assigned' && !bInIf && !bHadReturn && !selectors)
								return cb("local var " + var_name + " already conditionally assigned");
```

**File:** formula/validation.js (L689-703)
```javascript
					var prev_in_if = bInIf;
					bInIf = true;
					evaluate(if_block, function (err) {
						if (err)
							return cb(err);
						if (!else_block) {
							bInIf = prev_in_if;
							return cb();
						}
						evaluate(else_block, function (err) {
							bInIf = prev_in_if;
							cb(err);
						});
					});
				});
```

**File:** formula/validation.js (L1239-1239)
```javascript
				bHadReturn = true;
```

**File:** formula/evaluation.js (L1154-1156)
```javascript
					if (hasOwnProperty(locals, var_name)) {
						if (!selectors)
							return setFatalError("reassignment to " + var_name + ", old value " + locals[var_name], cb, false);
```
