# Audit Report

## Title
Context Leakage in Function Declaration Validation: `bInIf` Flag Not Saved/Restored

## Summary
The `bInIf` context flag in `formula/validation.js` is not saved and restored when parsing function declarations inside conditional blocks. This causes the `freeze` statement validation to incorrectly skip marking variables as frozen, allowing code that passes validation to fail during execution with "variable is frozen" errors, violating the AA deterministic validation principle.

## Impact
**Severity**: Medium  
**Category**: Unintended AA Behavior Without Direct Fund Risk

**Affected Parties**: AA developers who unknowingly deploy buggy code; users triggering affected AAs who lose bounce fees (typically 10,000 bytes per transaction)

**Quantified Loss**: Per-transaction bounce fee loss (~10,000 bytes); no direct theft of user funds or AA balances

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: Function bodies should be validated in an independent scope where `bInIf` reflects conditional context *within the function*, not whether the function declaration itself is inside a conditional. The freeze statement should mark variables as frozen during validation if the freeze is unconditional within its validation scope.

**Actual Logic**: When `parseFunctionDeclaration` is called, it saves and restores `bInFunction`, `complexity`, `count_ops`, `bStateVarAssignmentAllowed`, and `locals` [2](#0-1) , but does NOT save or restore `bInIf`. If a function is declared inside an if-else block, the `bInIf = true` flag set by the outer conditional [3](#0-2)  leaks into function body validation.

**Code Evidence**:

The freeze statement only marks variables as frozen when `!bInIf`: [4](#0-3) 

During runtime evaluation, freeze ALWAYS executes: [5](#0-4) 

Variable mutation checks frozen state during evaluation: [6](#0-5) 

**Exploitation Path**:

1. **Preconditions**: Attacker can deploy AA with arbitrary code; AA2 upgrade activated (functions enabled)

2. **Step 1**: Attacker deploys AA with function declared inside if-else:
   ```javascript
   if (trigger.data.mode == 'A') {
       $compute = () => {
           $data = {value: 100};
           freeze $data;
           $data.value = 200;
           return $data;
       };
   }
   ```
   Code path: AA deployment → `formula/validation.js:validate()` → `evaluate()` at line 266

3. **Step 2**: Validation evaluates if-else block
   - `ifelse` case sets `bInIf = true` [7](#0-6) 
   - Evaluates if_block containing function assignment

4. **Step 3**: Function declaration parsed with inherited `bInIf = true`
   - `parseFunctionDeclaration` called at line 603
   - Does NOT save/restore `bInIf` [2](#0-1) 
   - Function body validated with `bInIf = true` from outer scope

5. **Step 4**: Freeze statement validation skips marking frozen
   - Freeze statement evaluated in function body
   - Check `if (!bInIf)` evaluates to false (since `bInIf = true`)
   - Variable `$data` NOT marked as `frozen` [4](#0-3) 
   - Subsequent mutation `$data.value = 200` passes validation (line 576-577 doesn't trigger)

6. **Step 5**: AA passes validation and is deployed

7. **Step 6**: Runtime execution fails unexpectedly
   - User triggers AA; function executes
   - Freeze statement executes unconditionally, sets `locals['$data'].frozen = true` [5](#0-4) 
   - Mutation attempt checks frozen state [6](#0-5) 
   - Error: "variable $data is frozen"
   - Transaction bounces; user loses bounce fee

**Security Property Broken**: AA Deterministic Validation - The validation layer should deterministically catch all execution errors before deployment, but code that will fail at runtime passes validation.

**Root Cause**: When `bInIf` was introduced to track conditional context, it was not added to the save/restore logic in `parseFunctionDeclaration`. The function was designed to create isolated validation contexts by saving state variables, but this new context variable was overlooked.

## Impact Explanation

**Affected Assets**: User bounce fees, AA developer reputation

**Damage Severity**:
- **Quantitative**: Users lose bounce fees (~10,000 bytes per failed trigger); cumulative loss limited by number of users interacting with affected AA
- **Qualitative**: Validation layer incompleteness; user experience degradation; developer confusion

**User Impact**:
- **Who**: Users triggering affected AAs; AA developers who deploy code with this pattern
- **Conditions**: AA contains function declared inside if-else with freeze + subsequent mutation pattern
- **Recovery**: No recovery of lost bounce fees; AA must be redeployed with corrected code

**Systemic Risk**: Validation gap undermines trust in validation layer; could be exploited for griefing by intentionally deploying AAs that appear functional but fail in specific conditions

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: AA developer (malicious for griefing, or careless)
- **Resources**: Minimal - just AA deployment cost
- **Technical Skill**: Intermediate - requires understanding of AA functions, conditionals, and freeze semantics

**Preconditions**:
- **Network State**: Normal operation; AA2 upgrade activated
- **Attacker State**: Ability to deploy AA
- **Timing**: None

**Execution Complexity**:
- **Transaction Count**: 1 (deployment) + N (victim triggers)
- **Coordination**: None
- **Detection Risk**: Low during deployment (passes validation); medium during exploitation (visible bounce errors)

**Frequency**:
- **Repeatability**: Per-AA (each malformed AA can affect unlimited users)
- **Scale**: Limited to users of specific AAs

**Overall Assessment**: Medium likelihood - specific pattern unlikely to occur accidentally; could be used intentionally for griefing with minimal cost

## Recommendation

**Immediate Mitigation**:
Add `bInIf` to the save/restore logic in `parseFunctionDeclaration`:

```javascript
// In formula/validation.js, function parseFunctionDeclaration
var saved_complexity = complexity;
var saved_count_ops = count_ops;
var saved_sva = bStateVarAssignmentAllowed;
var saved_infunction = bInFunction;
var saved_in_if = bInIf;  // ADD THIS LINE
var saved_locals = _.cloneDeep(locals);
```

And restore it:

```javascript
// After function body evaluation
complexity = saved_complexity;
count_ops = saved_count_ops;
bStateVarAssignmentAllowed = saved_sva;
bInFunction = saved_infunction;
bInIf = saved_in_if;  // ADD THIS LINE
assignObject(locals, saved_locals);
```

**Additional Measures**:
- Add test case verifying freeze statements in functions declared inside conditionals behave correctly
- Review other context flags to ensure complete isolation in function scope

## Proof of Concept

```javascript
// test/freeze_in_conditional_function.test.js
var test = require('ava');
var formulaParser = require('../formula/index');

function validateFormula(formula, cb) {
    var opts = {
        formula,
        complexity: 0,
        count_ops: 0,
        mci: Number.MAX_SAFE_INTEGER,
        bAA: true,
        bStateVarAssignmentAllowed: true,
        bStatementsOnly: true,
        readGetterProps: () => {},
        locals: {}
    };
    formulaParser.validate(opts, cb);
}

test('freeze in function inside conditional should fail validation on subsequent mutation', t => {
    const formula = `
        if (trigger.data.mode == 'A') {
            $compute = () => {
                $data = {value: 100};
                freeze $data;
                $data.value = 200;
                return $data;
            };
        }
    `;
    
    validateFormula(formula, res => {
        // Currently passes validation due to bug (bInIf leakage)
        // Should fail with "local var $data is frozen"
        t.is(res.error, false); // Bug: validation incorrectly passes
        
        // After fix, this should change to:
        // t.truthy(res.error);
        // t.regex(res.error, /frozen/);
    });
});

test('freeze in function outside conditional should properly fail validation', t => {
    const formula = `
        $compute = () => {
            $data = {value: 100};
            freeze $data;
            $data.value = 200;
            return $data;
        };
    `;
    
    validateFormula(formula, res => {
        // This correctly fails validation
        t.truthy(res.error);
        t.regex(res.error, /frozen/);
    });
});
```

**Expected Test Result**: First test currently passes (demonstrating bug); should fail after fix. Second test correctly fails validation in both cases.

## Notes

This is a validation completeness issue rather than a fund theft vulnerability. While the financial impact is limited to bounce fees, it violates the principle that validation should deterministically catch all runtime errors. The bug affects a specific code pattern (function declarations inside conditionals with freeze statements) that is unlikely to occur accidentally but could be exploited for griefing.

The fix is straightforward: add `bInIf` to the list of saved/restored variables in `parseFunctionDeclaration` [2](#0-1) , ensuring function bodies are validated with independent conditional context.

### Citations

**File:** formula/validation.js (L689-690)
```javascript
					var prev_in_if = bInIf;
					bInIf = true;
```

**File:** formula/validation.js (L915-916)
```javascript
						if (!bInIf)
							locals[var_name_expr].state = 'frozen';
```

**File:** formula/validation.js (L1281-1321)
```javascript
	function parseFunctionDeclaration(args, body, cb) {
		var scopeVarNames = Object.keys(locals);
		if (_.intersection(args, scopeVarNames).length > 0)
			return cb("some args would shadow some local vars");
		var count_args = args.length;
		if (_.uniq(args).length !== count_args)
			return cb("duplicate arguments");
		var saved_complexity = complexity;
		var saved_count_ops = count_ops;
		var saved_sva = bStateVarAssignmentAllowed;
		var saved_infunction = bInFunction;
		var saved_locals = _.cloneDeep(locals);
		complexity = 0;
		count_ops = 0;
		//	bStatementsOnly is ignored in functions
		bStateVarAssignmentAllowed = true;
		bInFunction = true;
		// if a var was conditinally assigned, treat it as assigned when parsing the function body
		finalizeLocals(locals);
		// arguments become locals within function body
		args.forEach(name => {
			assignField(locals, name, { state: 'assigned', type: 'data' });
		});
		evaluate(body, function (err) {
			if (err)
				return cb(err);
			var funcProps = { complexity, count_args, count_ops };
			// restore the saved values
			complexity = saved_complexity;
			count_ops = saved_count_ops;
			bStateVarAssignmentAllowed = saved_sva;
			bInFunction = saved_infunction;
			assignObject(locals, saved_locals);

			if (funcProps.complexity > constants.MAX_COMPLEXITY)
				return cb("function exceeds complexity: " + funcProps.complexity);
			if (funcProps.count_ops > constants.MAX_OPS)
				return cb("function exceeds max ops: " + funcProps.count_ops);
			cb(null, funcProps);
		});
	}
```

**File:** formula/evaluation.js (L1159-1160)
```javascript
						if (locals[var_name].frozen)
							return setFatalError("variable " + var_name + " is frozen", cb, false);
```

**File:** formula/evaluation.js (L2138-2138)
```javascript
						locals[var_name].frozen = true;
```
