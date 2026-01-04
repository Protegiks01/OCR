# Audit Report: Case-Sensitivity Mismatch in AA Address Validation

## Title
Address Case Validation Inconsistency Bypasses Bounce Fee Protection Causing Permanent Fund Loss

## Summary
A critical architectural flaw exists where bounce fee validation uses strict uppercase-only address validation while general payment validation accepts any case. This inconsistency allows payments to AA addresses in lowercase/mixed-case format to bypass bounce fee checks entirely. When units stabilize, funds become permanently locked due to database JOIN failures (SQLite) or insufficient bounce fees (MySQL), with no recovery mechanism possible.

## Impact
**Severity**: Critical  
**Category**: Permanent Fund Freeze

**Affected Assets**: Bytes (native currency), all divisible assets, all indivisible assets

**Damage Severity**:
- **Quantitative**: Unlimited per transaction - any payment to lowercase AA address with <10,000 bytes bounce fees results in permanent fund loss
- **Qualitative**: Permanent and irreversible. Funds cannot be recovered as AA addresses are deterministically uppercase-only, making lowercase address definitions impossible to create

**User Impact**: All users sending payments to AA addresses, particularly those using UIs accepting case-insensitive input or copy-pasting addresses from external sources. Accidental triggering is highly probable.

## Finding Description

**Location**: Multiple files in `byteball/ocore`

**Intended Logic**: The bounce fee validation system should identify ALL AA addresses in payment outputs and verify sufficient bounce fees (minimum 10,000 bytes) are included to protect users from fund loss when AA execution fails.

**Actual Logic**: Two address validation functions exist with incompatible case requirements: [1](#0-0) [2](#0-1) 

The bounce fee check filters addresses using the strict uppercase validator: [3](#0-2) 

However, general payment validation uses the permissive validator: [4](#0-3) 

**Exploitation Path**:

1. **Preconditions**: User wants to send payment to AA address with insufficient bounce fees (<10,000 bytes)

2. **Step 1**: User provides AA address in lowercase format through wallet
   - Wallet calls `aa_addresses.checkAAOutputs(arrPayments)` before sending
   - Code path: `wallet.js` → `aa_addresses.js:checkAAOutputs()` [5](#0-4) 

3. **Step 2**: Bounce fee validation silently bypasses lowercase address
   - `checkAAOutputs` extracts addresses and calls `readAADefinitions` [6](#0-5) 
   - `readAADefinitions` filters with `isValidAddress` (uppercase-only), lowercase address removed [7](#0-6) 
   - Empty array returned, validation passes with no error

4. **Step 3**: Payment validation accepts unit
   - Uses `isValidAddressAnyCase` which accepts lowercase [4](#0-3) 
   - Unit enters DAG, addresses stored without normalization [8](#0-7) 

5. **Step 4**: Permanent fund loss when unit stabilizes
   - AA trigger detection uses database JOIN [9](#0-8) 
   
   **SQLite Case** (case-sensitive by default): [10](#0-9) 
   - JOIN fails: lowercase "outputs.address" ≠ uppercase "aa_addresses.address"
   - No trigger created → Funds locked at non-existent address
   
   **MySQL Case** (case-insensitive collation): [11](#0-10) 
   - JOIN succeeds but AA bounce logic detects insufficient fees [12](#0-11) 
   - Returns `finish(null)` → No bounce response, no refund [13](#0-12) 

**Security Property Broken**: Balance Conservation Invariant - All funds must reach their destination or return to sender. This vulnerability violates the protocol guarantee that failed AA executions refund inputs minus bounce fees.

**Root Cause Analysis**: 
- Two validation functions with different case requirements exist without normalization layer
- Bounce fee checker uses stricter function, payment validation uses permissive function  
- Addresses preserved in original case throughout system (no normalization before storage/JOINs)
- `getChash160` always returns uppercase [14](#0-13) 
- This makes lowercase address definitions impossible to create, blocking fund recovery [15](#0-14) 

## Impact Explanation

**Affected Assets**: Bytes (native currency), all divisible assets, all indivisible assets

**Damage Severity**:
- **Quantitative**: Any payment to lowercase AA address with insufficient bounce fees (<10,000 bytes) results in 100% permanent loss. No upper limit per transaction.
- **Qualitative**: Permanent and irreversible. Cannot be recovered through any transaction or AA definition due to deterministic uppercase-only address generation.

**User Impact**:
- **Who**: All users sending payments to AA addresses
- **Conditions**: Exploitable during normal operation whenever user provides lowercase or mixed-case AA address
- **Recovery**: No recovery mechanism exists. Requires protocol change and hard fork to redistribute locked funds

**Systemic Risk**:
- Silent failure mode: No error message during validation bypass
- Affects all database backends (SQLite and MySQL have different failure modes but same outcome)
- Can be triggered accidentally through copy-paste errors or UI case conversion
- Undermines user trust in AA bounce fee protection mechanism

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with wallet access
- **Resources Required**: Minimal transaction fees (<1,000 bytes)
- **Technical Skill**: None - simply provide lowercase address (can occur accidentally)

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Any wallet with funds
- **Timing**: No constraints

**Execution Complexity**:
- **Transaction Count**: Single transaction
- **Coordination**: None required
- **Detection Risk**: Low - appears as normal payment, silent validation bypass

**Frequency**:
- **Repeatability**: Can be repeated for any amount of funds
- **Accidental Triggering**: High probability through UI input normalization or copy-paste errors

**Overall Assessment**: High likelihood - extremely low barrier, accidental triggering highly probable, no error warnings during critical validation bypass

## Recommendation

**Immediate Mitigation**:
Add address normalization to uppercase before all validation and storage operations:

1. In `aa_addresses.js`, normalize addresses before filtering:
   - Modify `readAADefinitions` to call `arrAddresses.map(addr => addr.toUpperCase()).filter(isValidAddress)`

2. In `writer.js`, normalize addresses before storage:
   - Modify output insertion to normalize: `output.address.toUpperCase()`

3. Add validation gate in `validation.js`:
   - Reject payments with lowercase addresses to AA addresses, or auto-normalize with warning

**Permanent Fix**:
Implement comprehensive address normalization layer:

1. Create `normalizeAddress(address)` utility function in `validation_utils.js`
2. Apply normalization at all entry points: `composer.js`, `wallet.js`, `validation.js`
3. Add migration script to normalize existing addresses in database
4. Add validation to reject or warn on case mismatches

**Additional Measures**:
- Add test case verifying lowercase AA addresses are properly handled
- Add UI warning when AA address case doesn't match standard format
- Document case-sensitivity requirements in API and wallet integration guides

**Validation**:
- Fix prevents fund loss through lowercase addresses
- Backward compatible (uppercase addresses unaffected)
- No performance impact (string normalization is O(1))
- Recovers existing locked funds through database migration

## Proof of Concept

```javascript
// File: test/aa_case_sensitivity_vuln.test.js
const composer = require('../composer.js');
const aa_addresses = require('../aa_addresses.js');
const validation = require('../validation.js');

describe('AA Case Sensitivity Vulnerability', function() {
    it('should detect that lowercase AA addresses bypass bounce fee checks', async function() {
        // Setup: Create AA definition with uppercase address
        const aa_definition = ["autonomous agent", {
            bounce_fees: { base: 10000 }
        }];
        const aa_address_uppercase = objectHash.getChash160(aa_definition); // Returns uppercase
        
        // Deploy AA (address is uppercase)
        await deployAA(aa_definition, aa_address_uppercase);
        
        // Step 1: User provides lowercase AA address with insufficient bounce fees
        const aa_address_lowercase = aa_address_uppercase.toLowerCase();
        const payment = {
            outputs: [{
                address: aa_address_lowercase,  // Lowercase
                amount: 5000  // Less than 10,000 required bounce fee
            }]
        };
        
        // Step 2: Bounce fee check silently bypasses lowercase address
        const bounceCheckResult = await aa_addresses.checkAAOutputs([{
            asset: 'base',
            outputs: payment.outputs
        }]);
        
        // VULNERABILITY: Should return error about missing bounce fees
        // But returns undefined (no error) because lowercase filtered out
        assert.strictEqual(bounceCheckResult, undefined, 'Bounce fee check bypassed!');
        
        // Step 3: Payment validation accepts the unit
        const unit = await composer.composeJoint({
            paying_addresses: [sender_address],
            outputs: payment.outputs,
            signer: signer
        });
        
        const validationResult = await validation.validate(unit);
        assert.strictEqual(validationResult, null, 'Payment validation accepted lowercase address');
        
        // Step 4: After stabilization, funds are locked
        await waitForStabilization(unit.unit);
        
        // Verify: No AA trigger created (SQLite case)
        const triggers = await db.query("SELECT * FROM aa_triggers WHERE address=?", [aa_address_lowercase]);
        assert.strictEqual(triggers.length, 0, 'No trigger created for lowercase address');
        
        // Verify: Funds locked in outputs table
        const outputs = await db.query("SELECT * FROM outputs WHERE address=?", [aa_address_lowercase]);
        assert.strictEqual(outputs[0].amount, 5000, 'Funds locked at lowercase address');
        assert.strictEqual(outputs[0].is_spent, 0, 'Output unspent and unspendable');
        
        // Verify: Cannot create AA at lowercase address (recovery impossible)
        try {
            const lowercase_aa_definition = ["autonomous agent", {...}];
            const computed_address = objectHash.getChash160(lowercase_aa_definition);
            assert.notStrictEqual(computed_address, aa_address_lowercase, 
                'getChash160 only returns uppercase - cannot create lowercase AA');
        } catch (e) {
            // Expected: Cannot create AA at lowercase address
        }
        
        // RESULT: 5000 bytes permanently locked, no recovery possible
    });
});
```

## Notes

This vulnerability represents a critical architectural flaw where inconsistent validation functions create a silent bypass of critical safety mechanisms. The bounce fee system exists specifically to protect users from fund loss when AA executions fail, but the case-sensitivity mismatch makes this protection completely ineffective for lowercase/mixed-case addresses.

The vulnerability is particularly severe because:
1. **Silent Failure**: No error message alerts users to the bypassed validation
2. **Two Failure Modes**: Both SQLite (JOIN fails) and MySQL (insufficient fees) lead to permanent fund loss
3. **No Recovery**: Deterministic uppercase-only address generation prevents creating recovery AAs
4. **High Probability**: Can occur accidentally through normal UI interactions
5. **Unlimited Impact**: Any amount can be lost per transaction

The fix requires coordinated changes across multiple modules to implement consistent address normalization, plus a database migration to recover existing locked funds.

### Citations

**File:** validation_utils.js (L56-58)
```javascript
function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}
```

**File:** validation_utils.js (L60-62)
```javascript
function isValidAddress(address){
	return (typeof address === "string" && address === address.toUpperCase() && isValidChash(address, 32));
}
```

**File:** aa_addresses.js (L37-39)
```javascript
	arrAddresses = arrAddresses.filter(isValidAddress);
	if (arrAddresses.length === 0)
		return handleRows([]);
```

**File:** aa_addresses.js (L84-86)
```javascript
							if (objectHash.getChash160(arrDefinition) !== address) {
								console.log("definition doesn't match address: " + address);
								return cb();
```

**File:** aa_addresses.js (L111-145)
```javascript
function checkAAOutputs(arrPayments, handleResult) {
	var assocAmounts = {};
	arrPayments.forEach(function (payment) {
		var asset = payment.asset || 'base';
		payment.outputs.forEach(function (output) {
			if (!assocAmounts[output.address])
				assocAmounts[output.address] = {};
			if (!assocAmounts[output.address][asset])
				assocAmounts[output.address][asset] = 0;
			assocAmounts[output.address][asset] += output.amount;
		});
	});
	var arrAddresses = Object.keys(assocAmounts);
	readAADefinitions(arrAddresses, function (rows) {
		if (rows.length === 0)
			return handleResult();
		var arrMissingBounceFees = [];
		rows.forEach(function (row) {
			var arrDefinition = JSON.parse(row.definition);
			var bounce_fees = arrDefinition[1].bounce_fees;
			if (!bounce_fees)
				bounce_fees = { base: constants.MIN_BYTES_BOUNCE_FEE };
			if (!bounce_fees.base)
				bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
			for (var asset in bounce_fees) {
				var amount = assocAmounts[row.address][asset] || 0;
				if (amount < bounce_fees[asset])
					arrMissingBounceFees.push({ address: row.address, asset: asset, missing_amount: bounce_fees[asset] - amount, recommended_amount: bounce_fees[asset] });
			}
		});
		if (arrMissingBounceFees.length === 0)
			return handleResult();
		handleResult(new MissingBounceFeesErrorMessage({ error: "The amounts are less than bounce fees", missing_bounce_fees: arrMissingBounceFees }));
	});
}
```

**File:** validation.js (L1955-1956)
```javascript
			if (!ValidationUtils.isValidAddressAnyCase(output.address))
				return callback("output address "+output.address+" invalid");
```

**File:** writer.js (L394-397)
```javascript
								conn.addQuery(arrQueries, 
									"INSERT INTO outputs \n\
									(unit, message_index, output_index, address, amount, asset, denomination, is_serial) VALUES(?,?,?,?,?,?,?,1)",
									[objUnit.unit, i, j, output.address, parseInt(output.amount), payload.asset, denomination]
```

**File:** main_chain.js (L1603-1614)
```javascript
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND aa_definition_units.main_chain_index<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
```

**File:** initial-db/byteball-sqlite.sql (L318-334)
```sql
CREATE TABLE outputs (
	output_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	unit CHAR(44) NOT NULL,
	message_index TINYINT NOT NULL,
	output_index TINYINT NOT NULL,
	asset CHAR(44) NULL,
	denomination INT NOT NULL DEFAULT 1,
	address CHAR(32) NULL,  -- NULL if hidden by output_hash
	amount BIGINT NOT NULL,
	blinding CHAR(16) NULL,
	output_hash CHAR(44) NULL,
	is_serial TINYINT NULL, -- NULL if not stable yet
	is_spent TINYINT NOT NULL DEFAULT 0,
	UNIQUE (unit, message_index, output_index),
	FOREIGN KEY (unit) REFERENCES units(unit),
	CONSTRAINT outputsByAsset FOREIGN KEY (asset) REFERENCES assets(unit)
);
```

**File:** db.js (L14-14)
```javascript
		charset  : 'UTF8MB4_UNICODE_520_CI', // https://github.com/mysqljs/mysql/blob/master/lib/protocol/constants/charsets.js
```

**File:** aa_composer.js (L880-881)
```javascript
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
```

**File:** aa_composer.js (L886-887)
```javascript
			if (fee > amount)
				return finish(null);
```

**File:** chash.js (L139-139)
```javascript
	var encoded = (chash_length === 160) ? base32.encode(chash).toString() : chash.toString('base64');
```
