# Audit Report: TPS Fee Validation Bypass via Type Mismatch

## Summary

A critical type mismatch vulnerability in `storage.getTpsFeeRecipients()` allows attackers to bypass TPS fee validation by exploiting JavaScript's `for...in` loop behavior difference between arrays and objects. During validation, the function receives `earned_headers_commission_recipients` in array format and incorrectly validates against the first author's balance, but during fee deduction after storage, it receives the data in object format and deducts from the actual specified recipient's balance, enabling negative balance accumulation. [1](#0-0) 

## Impact

**Severity**: High  
**Category**: Fee Bypass / Balance Conservation Violation

**Affected Assets**: TPS fee balances regulate transaction processing during network congestion. The vulnerability allows unlimited fee evasion.

**Damage Severity**:
- Attackers submit units without sufficient TPS fee balance by validating against a co-author with adequate balance while deducting fees from addresses with zero balance
- Unlimited negative TPS fee balance accumulation breaks the congestion control mechanism
- Multiple attackers exploiting this could overwhelm the network during high-load periods

**User Impact**:
- Honest users pay proper TPS fees while attackers bypass them entirely
- Exploitable whenever network TPS exceeds threshold (post-v4 upgrade)
- Recovery requires protocol upgrade to fix validation logic and potentially reset negative balances

**Systemic Risk**:
- TPS fee system becomes ineffective if exploited at scale
- Breaks fundamental fee mechanism designed for congestion control

## Finding Description

**Location**: `byteball/ocore/storage.js:1421-1433`, function `getTpsFeeRecipients()`

**Intended Logic**: The function should consistently identify which author addresses will pay TPS fees based on `earned_headers_commission_recipients`, validate that all specified recipients are authors, and return the same mapping for both validation and fee deduction phases.

**Actual Logic**: JavaScript's `for...in` loop behaves differently for arrays (iterates over numeric indices "0", "1") versus objects (iterates over address keys). During validation, array format causes recipient addresses to be treated as "external" and overridden to the first author. After storage, object format correctly processes actual recipients. [1](#0-0) 

**Exploitation Path**:

1. **Preconditions**:
   - Network has reached v4 upgrade [2](#0-1) 
   - Attacker controls addresses A (high TPS fee balance) and B (zero balance)
   - Addresses sorted lexicographically (enforced) [3](#0-2) 

2. **Step 1 - Craft Multi-Author Unit**:
   - Create unit with `authors = [A, B]` and `earned_headers_commission_recipients = [{address: "B", earned_headers_commission_share: 100}]` (array format validated) [4](#0-3) 

3. **Step 2 - Validation Bypass**:
   - `validateTpsFee()` calls `getTpsFeeRecipients(array_format, [A, B])` [5](#0-4) 
   - `for (let address in recipients)` iterates over "0" (array index)
   - Check `author_addresses.includes("0")` returns false → sets `bHasExternalRecipients = true`
   - Returns `{A: 100}`, validates A's balance → passes

4. **Step 3 - Storage Conversion**:
   - Writer converts array to object format and stores in `assocUnstableUnits` [6](#0-5) 

5. **Step 4 - Fee Deduction Discrepancy**:
   - `updateTpsFees()` calls `getTpsFeeRecipients({B: 100}, [A, B])` (object format) [7](#0-6) 
   - `for (let address in recipients)` correctly iterates over "B"
   - Returns `{B: 100}`, deducts fee from B's balance [8](#0-7) 
   - B's balance becomes negative (explicitly allowed) [9](#0-8) 

**Security Properties Broken**:
- **Balance Conservation**: TPS fee balances become negative without corresponding credit
- **Fee Sufficiency Validation**: Units bypass fee payment requirements through validation-deduction mismatch

**Root Cause**: The function receives `earned_headers_commission_recipients` in two different formats (array during validation, object after storage) but uses `for...in` loop which behaves differently for each type. The validation function enforces array format [10](#0-9)  but delegates author checking to `getTpsFeeRecipients()`, which fails for arrays.

## Likelihood Explanation

**Attacker Profile**:
- Any user with two Obyte addresses
- Technical skill: Medium (requires understanding multi-author units)

**Preconditions**:
- Post-v4 upgrade network
- Control of two addresses with proper ordering
- No special timing required

**Execution Complexity**:
- Single multi-author unit per exploit
- Self-contained (attacker controls both authors)
- Detection risk: Low (legitimate use case)

**Frequency**: Unlimited repeatability

**Overall Assessment**: High likelihood - easy to execute, difficult to detect, provides direct benefit by evading TPS fees.

## Recommendation

**Immediate Mitigation**:
Normalize input format in `getTpsFeeRecipients()` before processing:

```javascript
function getTpsFeeRecipients(earned_headers_commission_recipients, author_addresses) {
    // Convert array format to object format consistently
    let recipients = earned_headers_commission_recipients || { [author_addresses[0]]: 100 };
    if (Array.isArray(earned_headers_commission_recipients)) {
        recipients = {};
        earned_headers_commission_recipients.forEach(r => {
            recipients[r.address] = r.earned_headers_commission_share;
        });
    }
    // Rest of validation logic...
}
```

**Additional Measures**:
- Add validation in `validateHeadersCommissionRecipients()` to verify all recipients are authors
- Add test cases for multi-author units with custom recipients
- Monitor for addresses with large negative TPS fee balances

## Proof of Concept

```javascript
// Test: TPS Fee Validation Bypass via Type Mismatch
const { expect } = require('chai');
const composer = require('../composer.js');
const validation = require('../validation.js');
const storage = require('../storage.js');

describe('TPS Fee Type Mismatch Vulnerability', function() {
    it('should expose validation-deduction discrepancy', async function() {
        // Setup: Two addresses, A with 10000 bytes TPS balance, B with 0
        const addressA = 'A_ADDRESS_WITH_HIGH_BALANCE_LEXICOGRAPHICALLY_FIRST';
        const addressB = 'B_ADDRESS_WITH_ZERO_BALANCE_LEXICOGRAPHICALLY_SECOND';
        
        // Step 1: Craft multi-author unit
        const unit = {
            authors: [
                { address: addressA, authentifiers: {...} },
                { address: addressB, authentifiers: {...} }
            ],
            earned_headers_commission_recipients: [
                { address: addressB, earned_headers_commission_share: 100 }
            ],
            messages: [...],
            parent_units: [...],
            timestamp: Date.now()
        };
        
        // Step 2: During validation, getTpsFeeRecipients receives array format
        const validationRecipients = storage.getTpsFeeRecipients(
            unit.earned_headers_commission_recipients,  // Array format
            [addressA, addressB]
        );
        // Bug: Returns {addressA: 100} due to for...in on array indices
        expect(validationRecipients).to.deep.equal({ [addressA]: 100 });
        
        // Validation checks addressA's balance (10000) and passes
        await validation.validateTpsFee(unit);  // Should pass
        
        // Step 3: After storage, writer converts to object format
        const objUnitProps = {
            earned_headers_commission_recipients: {
                [addressB]: 100  // Object format
            },
            author_addresses: [addressA, addressB]
        };
        
        // Step 4: During fee deduction, getTpsFeeRecipients receives object format
        const deductionRecipients = storage.getTpsFeeRecipients(
            objUnitProps.earned_headers_commission_recipients,  // Object format
            objUnitProps.author_addresses
        );
        // Returns {addressB: 100} correctly for objects
        expect(deductionRecipients).to.deep.equal({ [addressB]: 100 });
        
        // Fee is deducted from addressB (0 - 500 = -500)
        // addressA validated but addressB charged
        const balanceBefore = await getTpsFeeBalance(addressB);
        expect(balanceBefore).to.equal(0);
        
        await storage.updateTpsFees(conn, [mci]);
        
        const balanceAfter = await getTpsFeeBalance(addressB);
        expect(balanceAfter).to.be.lessThan(0);  // Negative balance!
    });
});
```

## Notes

This vulnerability arises from a subtle JavaScript behavior difference in `for...in` loops between arrays and objects, combined with the data format transformation between validation and storage phases. The validation function `validateHeadersCommissionRecipients()` enforces array format and checks structural validity but delegates author membership verification to `getTpsFeeRecipients()`, which fails silently for arrays by treating array indices as addresses. The database schema explicitly allows negative TPS fee balances, enabling unlimited exploitation.

### Citations

**File:** storage.js (L1204-1204)
```javascript
		if (mci < constants.v4UpgradeMci) // not last_ball_mci
```

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

**File:** validation.js (L911-911)
```javascript
	const recipients = storage.getTpsFeeRecipients(objUnit.earned_headers_commission_recipients, author_addresses);
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
