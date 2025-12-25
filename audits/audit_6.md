# Audit Report: TPS Fee Validation Bypass via Array/Object Type Mismatch

## Summary

A type mismatch vulnerability in `storage.getTpsFeeRecipients()` allows attackers to bypass TPS fee validation by exploiting JavaScript's `for...in` loop behavior difference between arrays and objects. During validation, the function receives `earned_headers_commission_recipients` in array format and incorrectly returns the first author for balance checks, but during fee deduction after storage, it receives the data in object format and correctly deducts from the specified recipient's balance, enabling unlimited negative balance accumulation.

## Impact

**Severity**: Medium  
**Category**: Fee Bypass / Protocol Mechanism Violation

**Affected Assets**: 
- TPS fee balances (congestion control mechanism)
- Network transaction processing fairness during high-load periods

**Damage Severity**:
- Attackers can submit unlimited units without paying TPS fees by validating against a co-author with sufficient balance while deducting from addresses with zero/negative balance
- Breaks the TPS fee congestion control mechanism intended to rate-limit transactions during network overload
- If exploited at scale during high TPS periods (>15 TPS), could potentially cause temporary transaction delays for honest users

**User Impact**:
- Honest users pay proper TPS fees while attackers bypass them entirely
- Only exploitable post-v4 upgrade when network TPS exceeds threshold
- Does not directly steal user funds but undermines fee fairness

**Systemic Risk**:
- TPS fee system becomes ineffective if widely exploited
- Could enable DoS-like behavior during congestion by allowing free transactions

## Finding Description

**Location**: `byteball/ocore/storage.js:1421-1433`, function `getTpsFeeRecipients()` [1](#0-0) 

**Intended Logic**: The function should consistently identify which author addresses will pay TPS fees based on `earned_headers_commission_recipients`, validate that all specified recipients are authors, and return the same address-to-share mapping for both validation and fee deduction phases.

**Actual Logic**: The function uses `for...in` loop to iterate over recipients. When passed an array (during validation), it iterates over numeric indices ("0", "1"). When passed an object (during fee deduction), it iterates over address keys. This causes validation to check against the wrong address.

**Exploitation Path**:

1. **Preconditions**:
   - Network has reached v4 upgrade (TPS fees active)
   - Attacker controls two addresses A (high TPS fee balance) and B (zero balance)
   - Addresses sorted lexicographically per protocol requirements

2. **Step 1 - Craft Multi-Author Unit**:
   - Create unit with `authors = [A, B]` 
   - Set `earned_headers_commission_recipients = [{address: "B", earned_headers_commission_share: 100}]` (array format)
   - Code path: `composer.js` → `validation.js:validate()` → `validation.js:validateTpsFee()`

3. **Step 2 - Validation Phase (Array Format)**:
   - `validation.js:911` calls `getTpsFeeRecipients(array_format, [A, B])` [2](#0-1) 
   - In `getTpsFeeRecipients()`, line 1425: `for (let address in recipients)` iterates over "0" (array index)
   - Line 1426: `author_addresses.includes("0")` returns false
   - Sets `bHasExternalRecipients = true`
   - Line 1430: Returns `{[author_addresses[0]]: 100}` = `{A: 100}`
   - Validation checks A's balance at line 914-917 → passes (A has sufficient balance) [3](#0-2) 

4. **Step 3 - Storage Conversion (Array → Object)**:
   - `writer.js:571-575` converts array to object format when storing unit properties [4](#0-3) 
   - Stores `objNewUnitProps.earned_headers_commission_recipients = {B: 100}` in `assocUnstableUnits` [5](#0-4) 

5. **Step 4 - Fee Deduction Phase (Object Format)**:
   - `storage.js:1217` calls `getTpsFeeRecipients({B: 100}, [A, B])` during `updateTpsFees()` [6](#0-5) 
   - In `getTpsFeeRecipients()`, line 1425: `for (let address in recipients)` iterates over "B" (object key)
   - Line 1426: `author_addresses.includes("B")` returns true
   - `bHasExternalRecipients` stays false
   - Returns `{B: 100}`
   - Line 1220-1223: Deducts fee from B's balance → B goes negative [7](#0-6) 

6. **Result - Negative Balance Accumulation**:
   - B's TPS fee balance becomes negative (explicitly allowed per database schema) [8](#0-7) 
   - Attacker can repeat unlimited times: validate against A, deduct from B

**Security Property Broken**:
- **Balance Conservation**: TPS fee balances become negative without corresponding credit from any source
- **Fee Validation Integrity**: Validation checks one address while deduction targets another

**Root Cause**: 
The function receives `earned_headers_commission_recipients` in two different formats (array during validation, object after storage) but uses `for...in` which has format-dependent iteration behavior. Additionally, `validateHeadersCommissionRecipients()` does not enforce that recipient addresses must be authors, delegating this check to `getTpsFeeRecipients()` which fails for arrays. [9](#0-8) 

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with two Obyte addresses
- **Resources**: Minimal (one address needs sufficient TPS fee balance for validation)
- **Technical Skill**: Medium (requires understanding multi-author units and protocol behavior)

**Preconditions**:
- **Network State**: Post-v4 upgrade, normal operation
- **Attacker State**: Control of two addresses with lexicographic ordering
- **Timing**: No special timing required, exploit is deterministic

**Execution Complexity**:
- **Transaction Count**: Single multi-author unit per exploit
- **Coordination**: Self-contained (attacker signs both authors)
- **Detection Risk**: Low (appears as legitimate multi-author unit usage)

**Frequency**:
- **Repeatability**: Unlimited (can repeat with same address pair indefinitely)
- **Scale**: Per-transaction basis

**Overall Assessment**: High likelihood of exploitation - technically simple, economically beneficial during congestion, difficult to detect.

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

**Immediate Mitigation**:

Enforce that `earned_headers_commission_recipients` addresses must be authors in `validation.js`:

```javascript
// In validation.js:validateHeadersCommissionRecipients()
// Add after line 948:
for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
    var recipient = objUnit.earned_headers_commission_recipients[i];
    // ... existing validation ...
    
    // NEW: Enforce recipients must be authors
    if (!objUnit.authors.some(a => a.address === recipient.address))
        return cb("earned_headers_commission_recipient address must be one of the authors");
}
```

**Permanent Fix**:

Normalize input format in `getTpsFeeRecipients()` to handle both array and object consistently:

```javascript
function getTpsFeeRecipients(earned_headers_commission_recipients, author_addresses) {
    // Normalize to object format
    let recipients;
    if (Array.isArray(earned_headers_commission_recipients)) {
        recipients = {};
        earned_headers_commission_recipients.forEach(r => {
            recipients[r.address] = r.earned_headers_commission_share;
        });
    } else {
        recipients = earned_headers_commission_recipients || { [author_addresses[0]]: 100 };
    }
    
    // Rest of existing logic...
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

**Additional Measures**:
- Add integration test verifying multi-author TPS fee validation and deduction consistency
- Add monitoring for addresses with deeply negative TPS fee balances (potential exploit indicator)
- Consider database check constraint limiting negative balance depth

## Notes

This vulnerability violates the "balance conservation" core protocol invariant by allowing TPS fee balances to become arbitrarily negative without corresponding positive balances elsewhere. While it doesn't directly steal user funds, it undermines the fundamental congestion control mechanism and could enable unfair advantages during high-load periods. The severity is assessed as Medium rather than High because it requires specific network conditions (high TPS) to have significant impact and does not cause permanent fund loss or network shutdown.

### Citations

**File:** storage.js (L1217-1217)
```javascript
			const recipients = getTpsFeeRecipients(objUnitProps.earned_headers_commission_recipients, objUnitProps.author_addresses);
```

**File:** storage.js (L1218-1223)
```javascript
			for (let address in recipients) {
				const share = recipients[address];
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

**File:** validation.js (L910-911)
```javascript
	const bFromOP = isFromOP(author_addresses, objValidationState.last_ball_mci);
	const recipients = storage.getTpsFeeRecipients(objUnit.earned_headers_commission_recipients, author_addresses);
```

**File:** validation.js (L912-917)
```javascript
	for (let address in recipients) {
		const share = recipients[address] / 100;
		const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, objValidationState.last_ball_mci]);
		const tps_fees_balance = row ? row.tps_fees_balance : 0;
		if (tps_fees_balance + objUnit.tps_fee * share < min_tps_fee * share)
			return callback(`tps_fee ${objUnit.tps_fee} + tps fees balance ${tps_fees_balance} less than required ${min_tps_fee} for address ${address} whose share is ${share}`);
```

**File:** validation.js (L929-953)
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

**File:** writer.js (L589-589)
```javascript
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
```

**File:** sqlite_migrations.js (L563-563)
```javascript
							tps_fees_balance INT NOT NULL DEFAULT 0, -- can be negative
```
