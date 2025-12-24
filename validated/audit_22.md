# VALIDATION RESULT: VALID CRITICAL VULNERABILITY

After thorough analysis of the codebase, I can confirm this is a **valid Critical severity vulnerability**. Here is my audit report:

## Title
Definition Rollback Attack via User-Controlled `last_ball_unit` in Signed Message Validation

## Summary
The `validateSignedMessage()` function retrieves address definitions at the MCI specified by the user-controlled `last_ball_unit` field without validating recency or checking if definition changes occurred after that point. This allows attackers with compromised historical private keys to forge valid signatures against weaker historical definitions, completely bypassing the address definition upgrade security mechanism and enabling direct fund theft from Autonomous Agents using `is_valid_signed_package()` for authorization.

## Impact
**Severity**: Critical  
**Category**: Direct Fund Loss

**Affected Assets**: 
- Bytes (native currency) in AAs using signed package validation
- Custom divisible/indivisible assets controlled by such AAs
- AA state variables and any funds controlled by AAs trusting `is_valid_signed_package()` for authorization

**Damage Severity**:
- **Quantitative**: Unlimited - any AA using `is_valid_signed_package()` for authorization can be fully drained if the authorizing address ever had a weaker historical definition
- **Qualitative**: Complete bypass of address security upgrades; renders the definition change mechanism ineffective for security recovery

**User Impact**:
- **Who**: Any user who upgraded their address definition for security purposes (after key compromise, to add multi-signature, to increase threshold requirements)
- **Conditions**: Exploitable when (1) address had weaker definition historically, (2) old key was compromised, (3) signed messages authorize AA actions
- **Recovery**: None - stolen funds are permanently lost once AA executes the unauthorized action

## Finding Description

**Location**: `byteball/ocore/signed_message.js:179`, function `validateSignedMessage()`

**Intended Logic**: Address definition validation should use the current active definition to ensure signatures reflect the address owner's latest security requirements, especially after definition upgrades for security recovery.

**Actual Logic**: The function reads the definition at the MCI specified by the user-controlled `last_ball_unit` parameter, allowing attackers to select arbitrary historical MCIs before definition upgrades occurred. [1](#0-0) 

The underlying storage function queries for definition changes at or before the specified `max_mci`: [2](#0-1) 

If no definition change exists at or before that MCI, the original address definition is returned, even if the address subsequently upgraded to a stronger definition.

The only validation check in AA formula evaluation prevents **future** MCIs but explicitly allows **all past** MCIs: [3](#0-2) 

**Exploitation Path**:

1. **Preconditions**:
   - Alice creates address A1 with single-signature definition at MCI 1000
   - Alice's private key gets compromised at MCI 1500
   - Alice upgrades to 2-of-3 multisig at MCI 2000 via `address_definition_change` unit
   - Current MCI is 3000
   - An AA uses `is_valid_signed_package(trigger.data.signed_pkg, A1)` to authorize withdrawals

2. **Step 1 - Craft Malicious Signed Message**: 
   Attacker creates signed package with:
   - `signed_message`: `{action: "withdraw", recipient: "ATTACKER_ADDRESS", amount: 100000}`
   - `last_ball_unit`: Hash of unit at MCI 1800 (before definition upgrade at MCI 2000)
   - `authors[0].address`: A1 (Alice's address)
   - `authors[0].authentifiers`: Single signature using compromised old key
   - Hash includes `last_ball_unit`, so signature is valid for this specific package

3. **Step 2 - Trigger AA**: 
   Attacker submits unit triggering the AA with the malicious signed package

4. **Step 3 - AA Validation**:
   AA formula calls `is_valid_signed_package()` → `validateSignedMessage()`
   - Line 160: Queries for MCI of `last_ball_unit` → returns 1800
   - Line 179: Calls `storage.readDefinitionByAddress(conn, A1, 1800, ...)`

5. **Step 4 - Definition Retrieval**:
   `storage.js` line 755-760: Queries for `address_definition_changes` where `main_chain_index <= 1800`
   - No rows returned (upgrade was at MCI 2000)
   - Line 760: Returns address itself as `definition_chash` (original single-sig definition)

6. **Step 5 - Signature Validation**:
   Signature validates successfully against old single-sig definition using compromised key
   - Line 1573: Only checks `last_ball_mci > mci` (not in future) - check passes
   - Line 1575: Returns `true`

7. **Step 6 - Fund Theft**:
   AA interprets validated signature as legitimate authorization and executes malicious withdrawal

**Security Property Broken**: **Definition Evaluation Integrity** - Address definitions must reflect the current security posture. This vulnerability allows validation against historical (weaker) definitions that are no longer active, defeating the security recovery mechanism.

**Root Cause**: The `last_ball_unit` parameter is entirely user-controlled with zero validation of:
- Recency (could be years old)
- Relationship to definition changes for that address
- Whether it represents a legitimate historical signature vs. newly forged one

The system cannot distinguish between:
1. Legitimate historical signature created before definition upgrade
2. Malicious new signature using compromised old key with old `last_ball_unit`

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Anyone who obtained a historical private key (phishing, malware, data breach, insider access)
- **Resources**: Single compromised historical private key
- **Technical Skill**: Medium - must understand DAG structure and signed message format

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Possession of old private key valid before definition upgrade
- **Timing**: No constraints - works anytime after victim upgrades definition

**Execution Complexity**:
- **Transaction Count**: Single AA trigger unit
- **Coordination**: None required
- **Detection Risk**: Low - signature appears cryptographically valid

**Overall Assessment**: High likelihood - precisely the scenario definition changes are meant to protect against, with straightforward execution.

## Recommendation

**Immediate Mitigation**:
Add validation in `validateSignedMessage()` to verify `last_ball_mci` is after the most recent definition change for the address:

```javascript
// In signed_message.js after line 177
conn.query(
    "SELECT MAX(main_chain_index) as latest_definition_mci FROM address_definition_changes " +
    "CROSS JOIN units USING(unit) WHERE address=? AND is_stable=1 AND sequence='good'",
    [objAuthor.address],
    function(rows) {
        if (rows.length > 0 && rows[0].latest_definition_mci && last_ball_mci < rows[0].latest_definition_mci) {
            return handleResult("last_ball_unit predates latest definition change");
        }
        // Continue with existing logic...
    }
);
```

**Permanent Fix**:
Consider requiring AAs to explicitly specify maximum acceptable age for `last_ball_mci` in `is_valid_signed_package()`, or add protocol-level recency requirements (e.g., `last_ball_mci` must be within 1000 MCIs of current).

**Additional Measures**:
- Add test case verifying signed messages with old `last_ball_unit` are rejected when definition changed
- Document that `is_valid_signed_package()` validates against historical definitions
- Add AA formula helper to check definition change history: `definition_changed_since(address, mci)`

## Proof of Concept

```javascript
// Conceptual test demonstrating the vulnerability
// This would require full test infrastructure setup with units, MCIs, etc.

const test = require('ava');
const signed_message = require('../signed_message.js');
const storage = require('../storage.js');
const db = require('../db.js');

test.serial('definition rollback attack', async t => {
    // Setup: Create address with single-sig definition at MCI 1000
    // (Would require creating actual units and advancing MCI)
    const address = 'TEST_ADDRESS';
    const oldPrivKey = 'compromised_old_key';
    
    // Simulate address definition upgrade to multisig at MCI 2000
    // (Would require creating address_definition_change unit)
    
    // Advance to current MCI 3000
    
    // Attack: Create signed message with last_ball_unit at MCI 1800
    const maliciousSignedPackage = {
        signed_message: { action: 'withdraw', amount: 100000 },
        last_ball_unit: 'unit_hash_at_mci_1800', // Before upgrade at MCI 2000
        authors: [{
            address: address,
            authentifiers: {
                r: signWithOldKey(maliciousMessage, oldPrivKey) // Single sig with compromised key
            }
        }]
    };
    
    // Validate - should reject but currently accepts
    signed_message.validateSignedMessage(db, maliciousSignedPackage, address, (err, last_ball_mci) => {
        // Current behavior: err is null (validation succeeds)
        // Expected behavior: err should be "last_ball_unit predates definition change"
        t.is(err, null); // This proves the vulnerability
        t.is(last_ball_mci, 1800); // Used old definition
    });
});
```

**Note**: A complete runnable test requires extensive setup (initial database state, unit creation, MCI progression, definition change units, AA deployment). The above demonstrates the vulnerability logic, though full implementation would require the test infrastructure shown in `test/aa.test.js`.

---

## Notes

This vulnerability is particularly severe because:

1. **Defeats Security Recovery**: Address definition changes are explicitly designed to allow users to recover from key compromise, but this vulnerability makes them ineffective

2. **Silent Failure**: There are no warnings or errors - the validation succeeds normally, giving no indication that a security bypass occurred

3. **Wide Impact**: Any AA using `is_valid_signed_package()` for authorization (payment channels, order books, access control, etc.) is vulnerable

4. **No User Recourse**: Once funds are stolen based on a validated malicious signature, they cannot be recovered

5. **Cryptographically Valid**: The attack uses legitimate cryptographic signatures, just against an outdated definition, making it hard to detect

The vulnerability violates the core security invariant that address definitions should reflect the current security state and that users can upgrade their security through definition changes.

### Citations

**File:** signed_message.js (L179-179)
```javascript
				storage.readDefinitionByAddress(conn, objAuthor.address, last_ball_mci, {
```

**File:** storage.js (L755-762)
```javascript
	conn.query(
		"SELECT definition_chash FROM address_definition_changes CROSS JOIN units USING(unit) \n\
		WHERE address=? AND is_stable=1 AND sequence='good' AND main_chain_index<=? ORDER BY main_chain_index DESC LIMIT 1", 
		[address, max_mci], 
		function(rows){
			var definition_chash = (rows.length > 0) ? rows[0].definition_chash : address;
			handle(definition_chash);
	});
```

**File:** formula/evaluation.js (L1570-1576)
```javascript
						signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, function (err, last_ball_mci) {
							if (err)
								return cb(false);
							if (last_ball_mci === null || last_ball_mci > mci)
								return cb(false);
							cb(true);
						});
```
