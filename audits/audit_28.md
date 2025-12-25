# Audit Report: TPS Fee Validation Bypass via Array/Object Type Mismatch

## Summary

A type mismatch vulnerability in `storage.getTpsFeeRecipients()` allows attackers to bypass TPS fee validation by exploiting JavaScript's `for...in` loop behavior difference between arrays and objects. During validation, the function receives `earned_headers_commission_recipients` in array format and incorrectly returns the first author for balance checks, but during fee deduction, it receives object format and correctly deducts from the specified recipient's balance. [1](#0-0) 

## Impact

**Severity**: Medium  
**Category**: Fee Bypass / Protocol Mechanism Violation

**Affected Assets**: TPS fee balances (congestion control mechanism), network transaction processing fairness during high-load periods.

**Damage Severity**: Attackers can submit unlimited units without paying TPS fees by validating against a co-author with sufficient balance while deducting from addresses with zero/negative balance. This breaks the TPS fee congestion control mechanism and could enable DoS-like behavior during network congestion by allowing free transactions.

**User Impact**: Honest users pay proper TPS fees while attackers bypass them entirely. Only exploitable post-v4 upgrade when network TPS exceeds threshold. Does not directly steal user funds but undermines fee fairness.

**Systemic Risk**: TPS fee system becomes ineffective if widely exploited, potentially causing temporary transaction delays for honest users during high TPS periods.

## Finding Description

**Location**: `getTpsFeeRecipients()` function [1](#0-0) 

**Intended Logic**: The function should consistently identify which author addresses will pay TPS fees based on `earned_headers_commission_recipients`, validate that all specified recipients are authors, and return the same address-to-share mapping for both validation and fee deduction phases.

**Actual Logic**: The function uses `for...in` loop to iterate over recipients. When passed an array (during validation), it iterates over numeric indices ("0", "1"). When passed an object (during fee deduction), it iterates over address keys. This causes validation to check against the wrong address.

**Exploitation Path**:

1. **Preconditions**: Network has reached v4 upgrade (TPS fees active), attacker controls two addresses A (high TPS fee balance) and B (zero balance).

2. **Step 1 - Craft Multi-Author Unit**: Create unit with `authors = [A, B]` and `earned_headers_commission_recipients = [{address: "B", earned_headers_commission_share: 100}]` (array format).

3. **Step 2 - Validation Phase**: [2](#0-1) 
   
   Validation calls `getTpsFeeRecipients(array_format, [A, B])`. The `for...in` loop iterates over "0" (array index), not the address. The check `author_addresses.includes("0")` returns false, setting `bHasExternalRecipients = true`. Returns `{A: 100}`. [3](#0-2) 
   
   Validation checks A's balance → passes if A has sufficient balance.

4. **Step 3 - Storage Conversion**: [4](#0-3) 
   
   Writer converts array to object format: `{B: 100}`.

5. **Step 4 - Fee Deduction Phase**: [5](#0-4) 
   
   Storage calls `getTpsFeeRecipients({B: 100}, [A, B])`. The `for...in` loop iterates over "B" (object key). The check `author_addresses.includes("B")` returns true, `bHasExternalRecipients` stays false. Returns `{B: 100}`. [6](#0-5) 
   
   Deducts fee from B's balance → B goes negative.

6. **Result**: [7](#0-6) 
   
   B's TPS fee balance becomes negative (explicitly allowed per database schema). Attacker can repeat unlimited times: validate against A, deduct from B.

**Security Property Broken**: Fee Validation Integrity - Validation checks one address while deduction targets another.

**Root Cause**: [8](#0-7) 

The function receives `earned_headers_commission_recipients` in two different formats but uses `for...in` which has format-dependent iteration behavior. Additionally, `validateHeadersCommissionRecipients()` does not enforce that recipient addresses must be authors.

## Likelihood Explanation

**Attacker Profile**: Any user with two Obyte addresses.

**Resources Required**: Minimal (one address needs sufficient TPS fee balance for validation).

**Technical Skill**: Medium (requires understanding multi-author units).

**Preconditions**: Post-v4 upgrade, normal operation. No special timing required.

**Execution Complexity**: Single multi-author unit per exploit, self-contained.

**Frequency**: Unlimited repeatability with same address pair.

**Overall Assessment**: High likelihood - technically simple, economically beneficial during congestion, difficult to detect.

## Proof of Concept

```javascript
const test = require('ava');
const storage = require('../storage.js');

test('getTpsFeeRecipients array vs object behavior mismatch', t => {
    const author_addresses = ['ADDRESS_A', 'ADDRESS_B'];
    
    // Array format (as received during validation from objUnit)
    const array_format = [{address: 'ADDRESS_B', earned_headers_commission_share: 100}];
    const result_array = storage.getTpsFeeRecipients(array_format, author_addresses);
    
    // Object format (as stored in objUnitProps after writer.js conversion)
    const object_format = {'ADDRESS_B': 100};
    const result_object = storage.getTpsFeeRecipients(object_format, author_addresses);
    
    // BUG: Different results for semantically identical input
    // Array returns first author (ADDRESS_A), object returns actual recipient (ADDRESS_B)
    t.deepEqual(result_array, {'ADDRESS_A': 100}); // Validates against ADDRESS_A
    t.deepEqual(result_object, {'ADDRESS_B': 100}); // Deducts from ADDRESS_B
    
    // This mismatch allows fee bypass
    t.notDeepEqual(result_array, result_object);
});
```

## Recommendation

**Immediate Mitigation**: Normalize the input format in `getTpsFeeRecipients()` to always process objects, or validate that all recipients are authors in `validateHeadersCommissionRecipients()`.

**Permanent Fix**: Modify `getTpsFeeRecipients()` to handle array input correctly by accessing the `address` field:

```javascript
function getTpsFeeRecipients(earned_headers_commission_recipients, author_addresses) {
    let recipients = earned_headers_commission_recipients || { [author_addresses[0]]: 100 };
    
    // Normalize array format to object format
    if (Array.isArray(earned_headers_commission_recipients)) {
        recipients = {};
        earned_headers_commission_recipients.forEach(r => {
            recipients[r.address] = r.earned_headers_commission_share;
        });
    }
    
    if (earned_headers_commission_recipients) {
        let bHasExternalRecipients = false;
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

**Additional Measures**: Add validation in `validateHeadersCommissionRecipients()` to enforce that all recipient addresses must be authors, and add test case verifying consistent behavior across formats.

## Notes

This vulnerability is valid because:
1. It exploits a genuine type mismatch in JavaScript's `for...in` behavior
2. All affected files are in-scope core protocol files
3. The exploit requires no special privileges and is deterministic
4. It breaks the intended TPS fee validation mechanism
5. Negative balances are explicitly allowed by the database schema
6. The validation layer does not check that recipients must be authors

The severity is Medium rather than Critical/High because it does not directly steal user funds or freeze assets, but it does undermine a protocol mechanism and could enable DoS during congestion periods.

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

**File:** validation.js (L911-911)
```javascript
	const recipients = storage.getTpsFeeRecipients(objUnit.earned_headers_commission_recipients, author_addresses);
```

**File:** validation.js (L914-917)
```javascript
		const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, objValidationState.last_ball_mci]);
		const tps_fees_balance = row ? row.tps_fees_balance : 0;
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

**File:** writer.js (L571-575)
```javascript
		if ("earned_headers_commission_recipients" in objUnit) {
			objNewUnitProps.earned_headers_commission_recipients = {};
			objUnit.earned_headers_commission_recipients.forEach(function(row){
				objNewUnitProps.earned_headers_commission_recipients[row.address] = row.earned_headers_commission_share;
			});
```

**File:** initial-db/byteball-sqlite.sql (L1002-1002)
```sql
	tps_fees_balance INT NOT NULL DEFAULT 0, -- can be negative
```
