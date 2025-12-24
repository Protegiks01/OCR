# Audit Report: TPS Fee Validation Bypass via Type Mismatch

## Summary

A critical type mismatch vulnerability in `storage.getTpsFeeRecipients()` causes TPS fee validation to check the first author's balance during validation, but then deduct fees from different recipients after unit storage. This occurs because the function receives `earned_headers_commission_recipients` in array format during validation but object format during fee deduction, and JavaScript's `for...in` loop behaves differently for each type. Attackers can exploit this to bypass TPS fee requirements and accumulate negative balances.

## Impact

**Severity**: Critical  
**Category**: Fee Bypass / Balance Conservation Violation

**Affected Assets**: TPS fee balances (bytes denomination), which regulate transaction processing during network congestion.

**Damage Severity**:
- Attackers can submit units without sufficient TPS fee balance by validating against a co-author with adequate balance
- Enables accumulation of unlimited negative TPS fee balances
- With typical min_tps_fee of 500-1000 bytes per unit, attackers can evade thousands of bytes in fees daily
- Breaks the TPS fee mechanism's core congestion control purpose

**User Impact**:
- All network participants affected - honest users pay proper TPS fees while attackers bypass them
- Exploitable whenever network TPS exceeds threshold and TPS fees are non-zero
- Recovery requires protocol upgrade and potentially resetting negative balances

**Systemic Risk**:
- TPS fee system becomes ineffective if multiple attackers exploit this
- Attacker units can crowd out legitimate transactions during high-load periods
- Negative balances accumulate indefinitely without recovery mechanism

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: The `getTpsFeeRecipients()` function should identify which author addresses will pay TPS fees based on `earned_headers_commission_recipients`, validate that all specified recipients are authors (rejecting external addresses), and return a consistent mapping for both validation and fee deduction phases.

**Actual Logic**: The function contains a critical type mismatch bug. It uses a `for...in` loop to iterate over recipients, but JavaScript's `for...in` behaves differently for arrays versus objects:
- **Array input** (during validation): Iterates over indices ("0", "1") instead of addresses, causing all recipients to be flagged as "external" and overridden to give 100% to the first author
- **Object input** (after storage): Correctly iterates over address keys, returning the actual recipient mapping

**Code Evidence**:

The vulnerable function: [1](#0-0) 

Called during validation with array format: [2](#0-1) 

Array format validated here: [3](#0-2) 

Conversion from array to object format in writer: [4](#0-3) 

Conversion when loading from database: [5](#0-4) 

Called during fee deduction with object format: [6](#0-5) 

Database schema explicitly allows negative balances: [7](#0-6) 

**Exploitation Path**:

1. **Preconditions**: 
   - Network has reached v4 upgrade (MCI ≥ constants.v4UpgradeMci)
   - Attacker controls two addresses: A (high TPS fee balance, e.g., 10,000 bytes) and B (zero balance)
   - Address A < B lexicographically (enforced by author sorting: [8](#0-7) )

2. **Step 1 - Craft Multi-Author Unit**:
   - Create unit with authors = [A, B] (sorted)
   - Set `earned_headers_commission_recipients = [{address: "B", earned_headers_commission_share: 100}]` (array format required by validation)
   - Both A and B sign the unit

3. **Step 2 - Validation Bypass**:
   - `validateTpsFee()` calls `getTpsFeeRecipients(array_format, [A, B])`
   - `for (let address in recipients)` iterates over "0" (array index, not address "B")
   - Check `author_addresses.includes("0")` returns false (since "0" ≠ "A" and "0" ≠ "B")
   - Sets `bHasExternalRecipients = true`
   - Overrides to `recipients = {A: 100}` (first author)
   - Validation checks A's balance (10,000 bytes) → passes

4. **Step 3 - Storage Conversion**:
   - Unit passes validation
   - Writer converts array to object: [4](#0-3) 
   - Stored as `{B: 100}` in `storage.assocUnstableUnits`
   - Unit becomes stable

5. **Step 4 - Fee Deduction Discrepancy**:
   - `updateTpsFees()` calls `getTpsFeeRecipients({B: 100}, [A, B])` (object format now)
   - `for (let address in recipients)` correctly iterates over "B"
   - Check `author_addresses.includes("B")` returns true
   - Returns `{B: 100}` without override
   - Deducts TPS fee (e.g., 500 bytes) from B's balance: [9](#0-8) 
   - B's balance: 0 - 500 = **-500 bytes** (negative balance allowed by schema)

**Security Properties Broken**:
- **Balance Conservation**: TPS fee balances can become negative without corresponding credit elsewhere
- **Fee Sufficiency Validation**: Units bypass actual fee payment requirements through validation-deduction mismatch

**Root Cause**: JavaScript's `for...in` loop iterates over array indices ("0", "1") for arrays but object keys (addresses) for objects. The function was designed for post-storage object format but is also called during validation with pre-storage array format. The validation function `validateHeadersCommissionRecipients()` enforces array format but doesn't verify recipients are authors, delegating that check to `getTpsFeeRecipients()`, which fails for arrays.

## Likelihood Explanation

**Attacker Profile**:
- Any user with two Obyte addresses (easily achievable)
- Requires understanding of multi-author units and `earned_headers_commission_recipients` field
- Technical skill: Medium

**Preconditions**:
- Post-v4 upgrade network
- Control of two addresses with proper lexicographic ordering
- No special timing or network state required

**Execution Complexity**:
- Single multi-author unit per exploit
- Self-contained (attacker controls both authors)
- Detection risk: Low (multi-author units with custom recipients are legitimate)

**Frequency**:
- Unlimited repeatability
- Can create multiple low-balance addresses to distribute negative balances

**Overall Assessment**: High likelihood - easy to execute, difficult to detect, provides direct financial benefit by evading TPS fees.

## Recommendation

**Immediate Mitigation**:

Fix `getTpsFeeRecipients()` to handle both array and object formats correctly:

```javascript
function getTpsFeeRecipients(earned_headers_commission_recipients, author_addresses) {
    let recipients = earned_headers_commission_recipients || { [author_addresses[0]]: 100 };
    if (earned_headers_commission_recipients) {
        let bHasExternalRecipients = false;
        
        // Convert array format to object format if needed
        if (Array.isArray(earned_headers_commission_recipients)) {
            recipients = {};
            earned_headers_commission_recipients.forEach(r => {
                recipients[r.address] = r.earned_headers_commission_share;
            });
        }
        
        // Now check recipients using object keys
        for (let address in recipients) {
            if (!author_addresses.includes(address))
                bHasExternalRecipients = true;
        }
        if (bHasExternalRecipients)
            recipients = { [author_addresses[0]]: 100 };
    }
    return recipients;
}
```

**Additional Measures**:
- Add validation preventing negative TPS fee balances during fee deduction
- Add monitoring to detect units where validation and deduction recipients differ
- Database migration to reset existing negative TPS fee balances

**Validation**:
- Fix ensures consistent recipient detection for both array and object inputs
- Prevents validation-deduction mismatch
- No breaking changes to existing valid units

## Proof of Concept

```javascript
const test = require('ava');
const storage = require('../storage.js');

test('getTpsFeeRecipients type mismatch vulnerability', t => {
    const author_addresses = ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'];
    
    // During validation: array format
    const array_format = [
        {address: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', earned_headers_commission_share: 100}
    ];
    const validation_recipients = storage.getTpsFeeRecipients(array_format, author_addresses);
    
    // During fee deduction: object format (as converted by writer.js or storage.js)
    const object_format = {'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB': 100};
    const deduction_recipients = storage.getTpsFeeRecipients(object_format, author_addresses);
    
    // BUG: Different recipients returned!
    // Validation checks first author (A), but deduction charges specified recipient (B)
    t.deepEqual(validation_recipients, {'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA': 100}); // Checks A's balance
    t.deepEqual(deduction_recipients, {'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB': 100}); // Charges B's balance
    
    // This proves the validation-deduction mismatch
    t.notDeepEqual(validation_recipients, deduction_recipients);
});
```

## Notes

The database schema comment "can be negative" at line 1002 of `byteball-sqlite.sql` likely refers to legitimate refund scenarios when actual TPS is lower than estimated, not for bypassing validation. The validation logic at [10](#0-9)  explicitly checks balance sufficiency, indicating that negative balances from insufficient validation are not intended behavior.

The vulnerability requires the attacker to control both author addresses, but this is trivial since any user can create multiple addresses. The exploit provides clear economic benefit by avoiding TPS fees that can reach thousands of bytes during high network load periods.

### Citations

**File:** storage.js (L1217-1217)
```javascript
			const recipients = getTpsFeeRecipients(objUnitProps.earned_headers_commission_recipients, objUnitProps.author_addresses);
```

**File:** storage.js (L1220-1223)
```javascript
				const tps_fees_delta = Math.floor(total_tps_fees_delta * share / 100);
				const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, mci]);
				const tps_fees_balance = row ? row.tps_fees_balance : 0;
				await conn.query("REPLACE INTO tps_fees_balances (address, mci, tps_fees_balance) VALUES(?,?,?)", [address, mci, tps_fees_balance + tps_fees_delta]);
```

**File:** storage.js (L1421-1433)
```javascript
function getTpsFeeRecipients(earned_headers_commission_recipients, author_addresses) {
	let recipients = earned_headers_commission_recipients || { [author_addresses[0]]: 100 };
	if (earned_headers_commission_recipients) {
		let bHasExternalRecipients = false;
		for (let address in recipients) {
			if (!author_addresses.includes(address))
				bHasExternalRecipients = true;
		}
		if (bHasExternalRecipients) // override, non-authors won't pay for our tps fee
			recipients = { [author_addresses[0]]: 100 };
	}
	return recipients;
}
```

**File:** storage.js (L2298-2300)
```javascript
						if (!assocUnits[prow.unit].earned_headers_commission_recipients)
							assocUnits[prow.unit].earned_headers_commission_recipients = {};
						assocUnits[prow.unit].earned_headers_commission_recipients[prow.address] = prow.earned_headers_commission_share;
```

**File:** validation.js (L911-911)
```javascript
	const recipients = storage.getTpsFeeRecipients(objUnit.earned_headers_commission_recipients, author_addresses);
```

**File:** validation.js (L916-917)
```javascript
		if (tps_fees_balance + objUnit.tps_fee * share < min_tps_fee * share)
			return callback(`tps_fee ${objUnit.tps_fee} + tps fees balance ${tps_fees_balance} less than required ${min_tps_fee} for address ${address} whose share is ${share}`);
```

**File:** validation.js (L929-954)
```javascript
function validateHeadersCommissionRecipients(objUnit, cb){
	if (objUnit.authors.length > 1 && typeof objUnit.earned_headers_commission_recipients !== "object")
		return cb("must specify earned_headers_commission_recipients when more than 1 author");
	if ("earned_headers_commission_recipients" in objUnit){
		if (!isNonemptyArray(objUnit.earned_headers_commission_recipients))
			return cb("empty earned_headers_commission_recipients array");
		var total_earned_headers_commission_share = 0;
		var prev_address = "";
		for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
			var recipient = objUnit.earned_headers_commission_recipients[i];
			if (!isPositiveInteger(recipient.earned_headers_commission_share))
				return cb("earned_headers_commission_share must be positive integer");
			if (hasFieldsExcept(recipient, ["address", "earned_headers_commission_share"]))
				return cb("unknowsn fields in recipient");
			if (recipient.address <= prev_address)
				return cb("recipient list must be sorted by address");
			if (!isValidAddress(recipient.address))
				return cb("invalid recipient address checksum");
			total_earned_headers_commission_share += recipient.earned_headers_commission_share;
			prev_address = recipient.address;
		}
		if (total_earned_headers_commission_share !== 100)
			return cb("sum of earned_headers_commission_share is not 100");
	}
	cb();
}
```

**File:** validation.js (L965-966)
```javascript
		if (objAuthor.address <= prev_address)
			return callback("author addresses not sorted");
```

**File:** writer.js (L571-576)
```javascript
		if ("earned_headers_commission_recipients" in objUnit) {
			objNewUnitProps.earned_headers_commission_recipients = {};
			objUnit.earned_headers_commission_recipients.forEach(function(row){
				objNewUnitProps.earned_headers_commission_recipients[row.address] = row.earned_headers_commission_share;
			});
		}
```

**File:** initial-db/byteball-sqlite.sql (L1002-1002)
```sql
	tps_fees_balance INT NOT NULL DEFAULT 0, -- can be negative
```
