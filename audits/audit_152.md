# Audit Report: Signed Message Author Duplication Process Crash Vulnerability

## Summary

The `validateSignedMessage()` function in `signed_message.js` allows duplicate author addresses in the authors array, unlike regular unit validation which enforces strict address uniqueness. When a signed message with duplicate authors is processed and contains nested address references in definitions, the evaluation logic throws an uncaught exception that crashes the Node.js process, enabling a Denial-of-Service attack against validator nodes.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay / Network Disruption

**Affected Assets**: All validator nodes, AA execution nodes, light clients, and any software processing signed messages.

**Damage Severity**:
- **Quantitative**: Any node validating a malicious signed message crashes immediately. Repeated attacks can cause sustained network disruption affecting transaction processing capacity.
- **Qualitative**: Process termination requires manual restart. During downtime, affected nodes cannot validate transactions, execute AAs, or participate in consensus.

**User Impact**:
- **Who**: All users whose transactions are processed by crashed nodes; AA users whose triggers depend on crashed validators
- **Conditions**: Exploitable whenever signed messages with nested address definitions are validated, particularly in AA contexts using `is_valid_signed_package`
- **Recovery**: Manual node restart required; automated restart mechanisms may re-crash if malicious message persists in queue

## Finding Description

**Location**: [1](#0-0)  and [2](#0-1)  and [3](#0-2) 

**Intended Logic**: Signed message validation should enforce unique author addresses, matching the invariant enforced in regular unit validation where authors must be strictly sorted (preventing duplicates).

**Actual Logic**: The signed message validation loop iterates through all authors and overwrites `the_author` for each address match, allowing duplicates. When definition evaluation encounters nested address references, it filters ALL authors for matching definitions and throws an uncaught `Error` if duplicates exist, crashing the process.

**Code Evidence**:

The signed message validation allows duplicate addresses: [1](#0-0) 

In contrast, regular unit validation enforces strict sorting (preventing duplicates): [4](#0-3) 

During validation phase, duplicate authors trigger an uncaught exception: [2](#0-1) 

During authentication phase, the same issue occurs: [3](#0-2) 

**Exploitation Path**:

1. **Preconditions**: 
   - Target address uses nested address reference in definition: `['address', 'NESTED_ADDR']`
   - Attacker can submit signed messages (any network participant)

2. **Step 1**: Attacker crafts malicious signed message
   - Author array contains: `[{address: 'NESTED_ADDR', definition: D}, {address: 'NESTED_ADDR', definition: D}, {address: 'TARGET_ADDR', authentifiers: {...}}]`
   - Message properly signed by TARGET_ADDR

3. **Step 2**: Message submitted to validation
   - Execution flow: `validateSignedMessage()` → `validateAuthentifiers()` → nested address evaluation
   - Code path: [5](#0-4) 

4. **Step 3**: Definition evaluation encounters duplicate
   - Filter operation at [6](#0-5)  returns array length > 1
   - Condition check at [7](#0-6)  evaluates to true

5. **Step 4**: Uncaught exception crashes process
   - `throw Error("more than 1 address definition")` executes inside async callback
   - Exception propagates to Node.js runtime without being caught
   - Process terminates immediately

**Security Property Broken**: 
- **Definition Evaluation Integrity**: The assumption that only one author can provide a given address definition is violated
- **Process Stability**: Validation logic should never throw uncaught exceptions that crash the process

**Root Cause Analysis**: 
The inconsistency exists because regular unit validation enforces unique addresses through sorting checks, but signed message validation does not. The definition evaluation code was written assuming duplicates are impossible (safe for regular units), using `throw Error()` instead of callback-based error handling. This becomes a crash vector when the precondition (no duplicate authors) is violated by signed messages.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any network participant who can submit signed messages
- **Resources Required**: Minimal - ability to construct JSON and submit to network
- **Technical Skill**: Medium - requires understanding of address definition syntax and nested address references

**Preconditions**:
- **Network State**: Addresses using nested address references exist on network (valid feature)
- **Attacker State**: No special privileges or positions required
- **Timing**: No timing constraints - attack executable anytime

**Execution Complexity**:
- **Transaction Count**: Single malicious signed message
- **Coordination**: None - single-actor attack
- **Detection Risk**: High detectability after first crash (logged), but may affect multiple nodes

**Frequency**:
- **Repeatability**: Unlimited - attacker can craft variants with different target addresses
- **Scale**: Can broadcast to multiple nodes simultaneously

**Overall Assessment**: High likelihood. Simple to execute, no privileges required, immediate impact. Primary barrier is identifying addresses with nested definitions, discoverable through blockchain analysis.

## Recommendation

**Immediate Mitigation**:
Add duplicate address check to signed message validation:

```javascript
// File: signed_message.js, function validateSignedMessage
// After line 135, before the loop at line 136:

var seen_addresses = {};
for (var i = 0; i < authors.length; i++){
    var author = authors[i];
    if (seen_addresses[author.address])
        return handleResult("duplicate author address");
    seen_addresses[author.address] = true;
    // ... rest of existing validation
}
```

**Permanent Fix**:
1. Enforce address uniqueness in signed messages (matching regular unit validation)
2. Replace `throw Error()` with callback-based error handling in definition.js:
   - Line 270: `return cb("more than 1 address definition");`
   - Line 722: `return cb2(false);` or `fatal_error = "more than 1 address definition"; return cb2(false);`

**Additional Measures**:
- Add test case verifying duplicate authors are rejected in signed messages
- Add test case for nested address evaluation with duplicate authors (should fail gracefully)
- Code review all other async code paths for uncaught `throw` statements

## Proof of Concept

```javascript
const test = require('ava');
const signedMessage = require('../signed_message.js');
const objectHash = require('../object_hash.js');

test('duplicate authors with nested address causes crash', t => {
    // Create address definitions
    const nestedAddr = 'NESTED_ADDRESS_HERE'; // Base32 address
    const targetAddr = 'TARGET_ADDRESS_HERE'; // Base32 address
    const nestedDef = ['sig', {pubkey: 'BASE64_PUBKEY'}];
    
    // Craft malicious signed message with duplicate authors
    const maliciousMessage = {
        signed_message: "test message",
        authors: [
            {
                address: nestedAddr,
                definition: nestedDef,
                authentifiers: {'r': '-'.repeat(88)}
            },
            {
                address: nestedAddr,  // DUPLICATE
                definition: nestedDef,
                authentifiers: {'r': '-'.repeat(88)}
            },
            {
                address: targetAddr,
                definition: ['address', nestedAddr], // Nested reference
                authentifiers: {'r': '-'.repeat(88)}
            }
        ]
    };
    
    // Attempt validation - should crash process if vulnerability exists
    signedMessage.validateSignedMessage(maliciousMessage, targetAddr, function(err) {
        // Should return error gracefully, not crash
        t.truthy(err);
        t.regex(err, /duplicate|more than 1/i);
    });
});
```

## Notes

This vulnerability exists due to an architectural inconsistency where two validation code paths (regular units vs. signed messages) enforce different invariants. The fix should align signed message validation with unit validation by enforcing the same address uniqueness requirement. Additionally, all async error conditions in definition evaluation should use callback-based error propagation rather than throwing exceptions.

### Citations

**File:** signed_message.js (L136-146)
```javascript
	for (var i = 0; i < authors.length; i++){
		var author = authors[i];
		if (ValidationUtils.hasFieldsExcept(author, ['address', 'definition', 'authentifiers']))
			return handleResult("foreign fields in author");
		if (author.address === address)
			the_author = author;
		else if (!ValidationUtils.isValidAddress(author.address))
			return handleResult("not valid address");
		if (!ValidationUtils.isNonemptyObject(author.authentifiers))
			return handleResult("no authentifiers");
	}
```

**File:** signed_message.js (L229-238)
```javascript
		Definition.validateAuthentifiers(
			conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers,
			function (err, res) {
				if (err) // error in address definition
					return handleResult(err);
				if (!res) // wrong signature or the like
					return handleResult("authentifier verification failed");
				handleResult(null, last_ball_mci);
			}
		);
```

**File:** definition.js (L264-270)
```javascript
						var arrDefiningAuthors = objUnit.authors.filter(function(author){
							return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
						});
						if (arrDefiningAuthors.length === 0) // no address definition in the current unit
							return bAllowUnresolvedInnerDefinitions ? cb(null, true) : cb("definition of inner address "+other_address+" not found");
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
```

**File:** definition.js (L716-722)
```javascript
						var arrDefiningAuthors = objUnit.authors.filter(function(author){
							return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
						});
						if (arrDefiningAuthors.length === 0) // no definition in the current unit
							return cb2(false);
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
```

**File:** validation.js (L962-967)
```javascript
	var prev_address = "";
	for (var i=0; i<arrAuthors.length; i++){
		var objAuthor = arrAuthors[i];
		if (objAuthor.address <= prev_address)
			return callback("author addresses not sorted");
		prev_address = objAuthor.address;
```
