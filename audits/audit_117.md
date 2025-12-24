## Title
Stack Overflow DoS via Unbounded Recursion in Shared Address Template Validation

## Summary
The `getMemberDeviceAddressesBySigningPaths()` function in `wallet_defined_by_addresses.js` recursively processes address definition templates without depth limits, allowing an attacker to crash a victim node by sending a deeply nested template (10,000+ levels) via the "create_new_shared_address" P2P message. This causes stack overflow before complexity checks in `Definition.validateDefinition()` are applied.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay (single node DoS)

**Affected Assets**: Node availability and network participation  

**Damage Severity**:
- **Quantitative**: Single node crash requiring manual restart. Attack repeatable indefinitely to prevent node operation.
- **Qualitative**: Denial of service affecting individual nodes, not network-wide. Node cannot process messages while crashed.

**User Impact**:
- **Who**: Node operators who have paired with attacker as correspondent device
- **Conditions**: Attacker must be paired correspondent OR compromise existing correspondent's keys
- **Recovery**: Manual node restart required; attack can repeat immediately

**Systemic Risk**: Limited to single nodes - does not affect consensus, main chain integrity, fund security, or network-wide operation

## Finding Description

**Location**: `byteball/ocore/wallet_defined_by_addresses.js:384-424`, function `getMemberDeviceAddressesBySigningPaths()`

**Intended Logic**: Extract device addresses from address definition template by recursively walking the structure to find 'address' operations with '$address@' prefixes.

**Actual Logic**: The inner `evaluate()` function recursively processes 'or', 'and', 'r of set', and 'weighted and' operations without any depth counter, complexity limit, or recursion guard, allowing unbounded recursion that exhausts the JavaScript call stack.

**Code Evidence**:

The vulnerable recursive function lacks depth checking: [1](#0-0) 

This function is called BEFORE the complexity-checked validation: [2](#0-1) 

The proper complexity checks exist in `Definition.validateDefinition()` but are only applied AFTER: [3](#0-2) 

For comparison, the correct implementation with complexity checks in `Definition.validateDefinition()`: [4](#0-3) 

The complexity limits defined: [5](#0-4) 

**Exploitation Path**:

1. **Preconditions**: 
   - Attacker has paired with victim node as correspondent device
   - Victim node is listening for P2P device messages

2. **Step 1**: Attacker crafts deeply nested address definition template (10,000+ levels of nesting in 'and', 'or', 'r of set', or 'weighted and' operations)

3. **Step 2**: Attacker sends "create_new_shared_address" message to victim via hub: [6](#0-5) 

4. **Step 3**: Message handler performs minimal validation (only checks array length), then calls `validateAddressDefinitionTemplate()` which immediately invokes the vulnerable `getMemberDeviceAddressesBySigningPaths()` function

5. **Step 4**: The `evaluate()` function recurses 10,000+ times without checks, exhausting JavaScript call stack (typical limit: 10,000-15,000 frames). This throws `RangeError: Maximum call stack size exceeded`, crashing the Node.js process.

**Security Property Broken**: Single-node availability - a malicious peer can prevent a node from processing legitimate messages by crashing it, disrupting the victim's network participation.

**Root Cause Analysis**:
1. Wallet message handler processes untrusted input from paired correspondent devices
2. `getMemberDeviceAddressesBySigningPaths()` is called as preprocessing step before proper validation
3. The complexity/depth checks in `Definition.validateDefinition()` (MAX_COMPLEXITY=100, MAX_OPS=2000) are bypassed because crash occurs first
4. No try-catch handling for stack overflow exceptions
5. No defense-in-depth: outer function trusts inner recursive traversal to be safe

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Malicious peer with correspondent device pairing
- **Resources Required**: Ability to send P2P device messages (minimal cost), device pairing with target (requires social engineering or previous interaction)
- **Technical Skill**: Low - attack requires only crafting nested JSON structure

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Must be paired correspondent device
- **Timing**: No specific timing required

**Execution Complexity**:
- **Transaction Count**: Single P2P device message (not a blockchain transaction)
- **Coordination**: None required
- **Detection Risk**: High - stack overflow crash generates error logs and node restart is observable

**Frequency**:
- **Repeatability**: Unlimited - can repeat immediately after node restart
- **Scale**: One node per paired correspondent relationship

**Overall Assessment**: Medium likelihood - requires correspondent pairing (social barrier) but execution is trivial once paired

## Recommendation

**Immediate Mitigation**:
Add depth checking to `getMemberDeviceAddressesBySigningPaths()` similar to `Definition.validateDefinition()`:

```javascript
function getMemberDeviceAddressesBySigningPaths(arrAddressDefinitionTemplate){
    var depth = 0;
    var MAX_DEPTH = 100; // Match MAX_COMPLEXITY
    
    function evaluate(arr, path){
        depth++;
        if (depth > MAX_DEPTH)
            throw Error("recursion depth exceeded at " + path);
        // ... existing logic ...
        depth--;
    }
    // ... rest of function
}
```

**Permanent Fix**:
Wrap the call in try-catch to handle exceptions gracefully: [7](#0-6) 

**Additional Measures**:
- Add test case verifying deeply nested templates are rejected
- Consider reusing `Definition.validateDefinition()` for template validation instead of custom traversal
- Add monitoring for repeated message handling failures from same correspondent

## Proof of Concept

```javascript
// test/stack_overflow_shared_address.test.js
const device = require('../device.js');
const walletDefinedByAddresses = require('../wallet_defined_by_addresses.js');

describe('Stack overflow protection in shared address template validation', function(){
    it('should reject deeply nested address definition template', function(done){
        // Craft deeply nested template
        let template = ['address', '$address@DEVICE0'];
        for (let i = 0; i < 15000; i++) {
            template = ['and', [template, ['address', '$address@DEVICE' + i]]];
        }
        
        // Attempt validation - should throw error or handle gracefully
        try {
            walletDefinedByAddresses.validateAddressDefinitionTemplate(
                template, 
                device.getMyDeviceAddress(),
                function(err, result){
                    if (err) {
                        // Expected: validation rejects overly complex template
                        console.log('Validation correctly rejected template:', err);
                        done();
                    } else {
                        // Unexpected: validation accepted dangerous template
                        done(new Error('Validation should have rejected deeply nested template'));
                    }
                }
            );
        } catch(e) {
            // Stack overflow occurred before callback
            if (e.message.includes('Maximum call stack size exceeded')) {
                done(new Error('Stack overflow occurred - vulnerability confirmed'));
            } else {
                throw e;
            }
        }
    });
});
```

## Notes

This vulnerability requires the attacker to be a paired correspondent device, which limits the attack surface compared to network-wide attacks. However, this is still a valid security issue because:

1. **Pairing is common**: Users regularly pair with multiple correspondents (wallets, exchanges, services)
2. **Social engineering**: Attackers can trick users into pairing using phishing or impersonation
3. **Persistent access**: Once paired, attacker has unlimited ability to send messages
4. **Trivial exploitation**: No complex timing, cryptography, or protocol manipulation required
5. **Repeatable attack**: Victim cannot prevent re-attack after restart without manually deleting the pairing

The vulnerability is particularly concerning because it bypasses the proper complexity checks that exist in `Definition.validateDefinition()` by crashing the process before those checks are reached. This represents a defensive gap where untrusted input is processed without the same rigor applied to similar data structures elsewhere in the codebase.

### Citations

**File:** wallet_defined_by_addresses.js (L385-420)
```javascript
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
```

**File:** wallet_defined_by_addresses.js (L426-427)
```javascript
function validateAddressDefinitionTemplate(arrDefinitionTemplate, from_address, handleResult){
	var assocMemberDeviceAddressesBySigningPaths = getMemberDeviceAddressesBySigningPaths(arrDefinitionTemplate);
```

**File:** wallet_defined_by_addresses.js (L451-451)
```javascript
	Definition.validateDefinition(db, arrFakeDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
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

**File:** wallet.js (L173-188)
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
				break;
```
