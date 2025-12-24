# Vulnerability Report

## Title
TPS Fee Validation Bypass via Type Mismatch in earned_headers_commission_recipients Processing

## Summary
A type mismatch bug in `storage.getTpsFeeRecipients()` causes JavaScript's `for...in` loop to iterate over array indices instead of addresses during validation, incorrectly flagging legitimate author recipients as "external" and overriding to check the wrong author's TPS fee balance. This allows attackers to bypass TPS fee requirements by validating against a high-balance co-author while actual fee deduction occurs against a different author's zero-balance address, enabling negative TPS fee balances and breaking the network's congestion control mechanism.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay / Economic Mechanism Bypass

This vulnerability enables attackers to bypass the TPS fee rate-limiting mechanism during network congestion by accumulating unlimited negative TPS fee balances. While this does not result in direct theft of bytes or assets from other users, it allows spam attacks that could cause temporary transaction delays (≥1 hour) during high-load periods by overwhelming the network with units that should have been rejected due to insufficient TPS fees.

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: The `getTpsFeeRecipients()` function should identify which addresses will pay TPS fees based on `earned_headers_commission_recipients`, validate that all recipients are authors (to prevent external addresses from being charged), and return the correct recipient mapping for both validation and fee deduction phases.

**Actual Logic**: The function contains a critical type mismatch bug. It uses JavaScript's `for...in` loop which behaves fundamentally differently for arrays versus objects:
- **Arrays**: `for...in` iterates over indices as strings ("0", "1", "2", ...)
- **Objects**: `for...in` iterates over property keys (addresses)

During validation, `earned_headers_commission_recipients` is in array format [2](#0-1) , but the function checks if array indices are in the authors array, always failing and incorrectly overriding to the first author. After database storage, the data is converted to object format [3](#0-2) , and the function works correctly, causing fee deduction against the actually specified recipients.

**Code Evidence**:

The vulnerable function: [1](#0-0) 

Validation call (array format): [4](#0-3) 

Fee deduction call (object format): [5](#0-4) 

Database schema explicitly allows negative balances: [6](#0-5) 

**Exploitation Path**:

1. **Preconditions**: 
   - Network post-v4 upgrade (TPS fees active)
   - Attacker controls addresses A (high TPS fee balance) and B (zero balance)
   - A < B lexicographically (A becomes first author)

2. **Step 1 - Craft Multi-Author Unit**:
   - Create unit with `authors = [A, B]` (sorted)
   - Set `earned_headers_commission_recipients = [{address: "B", earned_headers_commission_share: 100}]`
   - Both authors sign (attacker controls both)

3. **Step 2 - Validation Bypass**:
   - `validateTpsFee()` calls `getTpsFeeRecipients(array, [A, B])`
   - `for (let address in recipients)` iterates over "0" (array index)
   - `author_addresses.includes("0")` returns false
   - `bHasExternalRecipients = true`
   - Overrides to `{A: 100}`
   - Validation checks A's balance (10,000 bytes) → passes

4. **Step 3 - Storage Conversion**:
   - Unit stored to database as individual rows
   - When read via `initParenthoodAndHeadersComissionShareForUnits()`, converted to object `{B: 100}`

5. **Step 4 - Fee Deduction Discrepancy**:
   - `updateTpsFees()` calls `getTpsFeeRecipients({B: 100}, [A, B])`
   - `for (let address in recipients)` iterates over "B"
   - `author_addresses.includes("B")` returns true
   - Returns `{B: 100}`
   - Fee (500 bytes) deducted from B: 0 - 500 = -500 bytes
   - No validation prevents negative balance

**Security Property Broken**: Balance Conservation & Fee Sufficiency - TPS fee balances can go negative without any prevention mechanism, allowing unlimited exploitation of the rate-limiting system.

**Root Cause Analysis**: The function was designed for object format (as stored in database) but is also called during validation with array format. The validation function `validateHeadersCommissionRecipients()` [7](#0-6)  enforces array format but does NOT validate that recipients are authors, delegating that check to `getTpsFeeRecipients()` which fails when given an array due to `for...in` semantics.

## Impact Explanation

**Affected Assets**: TPS fee balances (rate-limiting mechanism for network congestion)

**Damage Severity**:
- **Quantitative**: With typical min_tps_fee of 500-1000 bytes, an attacker could submit hundreds of units daily, accumulating tens of thousands of negative bytes in TPS fee balance
- **Qualitative**: Breaks the TPS fee mechanism's purpose of rate-limiting during congestion, enabling spam attacks

**User Impact**:
- **Who**: All network participants during high-load periods
- **Conditions**: Exploitable whenever TPS fees are active (network under load)
- **Recovery**: Requires protocol upgrade and potentially resetting negative balances

**Systemic Risk**: If widely exploited, the TPS fee system becomes ineffective at managing congestion. Attacker units could crowd out legitimate transactions during high-load periods, causing temporary delays ≥1 hour for honest users.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with two addresses
- **Resources Required**: Minimal - one address with sufficient TPS fee balance (reusable), multiple zero-balance addresses
- **Technical Skill**: Medium - requires understanding multi-author units and `earned_headers_commission_recipients`

**Preconditions**:
- **Network State**: Post-v4 upgrade
- **Attacker State**: Control of 2+ addresses
- **Timing**: No specific timing requirements

**Execution Complexity**:
- **Transaction Count**: Single multi-author unit per exploit
- **Coordination**: Self-contained (attacker controls both authors)
- **Detection Risk**: Low - legitimate feature, distinguishing abuse requires balance analysis

**Frequency**:
- **Repeatability**: Unlimited
- **Scale**: Can create multiple addresses for distribution

**Overall Assessment**: High likelihood - easy to execute, difficult to detect, provides clear economic benefit.

## Recommendation

**Immediate Mitigation**:
Convert array to object format before processing or use proper iteration method:

```javascript
function getTpsFeeRecipients(earned_headers_commission_recipients, author_addresses) {
    // Convert array format to object format if needed
    let recipients = earned_headers_commission_recipients;
    if (Array.isArray(earned_headers_commission_recipients)) {
        recipients = {};
        for (let recipient of earned_headers_commission_recipients) {
            recipients[recipient.address] = recipient.earned_headers_commission_share;
        }
    }
    recipients = recipients || { [author_addresses[0]]: 100 };
    
    // Rest of function remains same
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
- Add explicit validation in `validateHeadersCommissionRecipients()` to ensure all recipients are authors
- Add monitoring for negative TPS fee balance accumulation
- Consider adding database constraint or validation to prevent excessive negative balances

## Proof of Concept

```javascript
const test = require('ava');
const composer = require('../composer.js');
const validation = require('../validation.js');
const db = require('../db.js');

test('TPS fee validation bypass via type mismatch', async t => {
    // Setup: Create two addresses A and B controlled by attacker
    const addressA = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; // High balance
    const addressB = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'; // Zero balance
    
    // Pre-populate A with high TPS fee balance
    await db.query("REPLACE INTO tps_fees_balances (address, mci, tps_fees_balance) VALUES(?,?,?)", 
        [addressA, 1000, 10000]);
    
    // Craft multi-author unit with earned_headers_commission_recipients
    const unit = {
        version: '4.0',
        authors: [
            {address: addressA, authentifiers: {r: 'sig_a'}},
            {address: addressB, authentifiers: {r: 'sig_b'}}
        ],
        earned_headers_commission_recipients: [
            {address: addressB, earned_headers_commission_share: 100}
        ],
        tps_fee: 500,
        // ... other required fields
    };
    
    // Step 1: Validation should pass (checking A's balance)
    const validationResult = await new Promise((resolve, reject) => {
        validation.validateTpsFee(db, {unit}, {last_ball_mci: 1000}, (err) => {
            if (err) reject(err);
            else resolve('passed');
        });
    });
    t.is(validationResult, 'passed', 'Validation incorrectly passes using address A balance');
    
    // Step 2: Store unit and process fees
    // (simulating storage and stability)
    await storeUnitAndMakeStable(unit);
    
    // Step 3: Fee deduction happens against address B
    const [rowB] = await db.query(
        "SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? ORDER BY mci DESC LIMIT 1",
        [addressB]
    );
    
    // Assert: Address B now has negative balance
    t.true(rowB.tps_fees_balance < 0, 'Address B has negative TPS fee balance');
    t.is(rowB.tps_fees_balance, -500, 'Exact negative amount matches fee');
    
    // Address A balance unchanged (should have been charged but wasn't)
    const [rowA] = await db.query(
        "SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? ORDER BY mci DESC LIMIT 1",
        [addressA]
    );
    t.is(rowA.tps_fees_balance, 10000, 'Address A balance unchanged despite validation');
});
```

## Notes

The bug exploits a fundamental JavaScript language behavior where `for...in` loops handle arrays differently than objects. The validation function enforces array format for `earned_headers_commission_recipients`, but `getTpsFeeRecipients()` was designed assuming object format, creating the mismatch.

While the database schema comment indicates negative TPS fee balances are "allowed" [8](#0-7) , the validation logic [9](#0-8)  clearly intends to prevent units with insufficient fees from being accepted. The bypass allows unlimited exploitation of this protection mechanism.

This vulnerability affects the network's economic security and congestion control but does not enable direct theft of bytes or assets from other users, qualifying it as Medium severity per Immunefi guidelines (Temporary Transaction Delay during high-load periods).

### Citations

**File:** storage.js (L1217-1223)
```javascript
			const recipients = getTpsFeeRecipients(objUnitProps.earned_headers_commission_recipients, objUnitProps.author_addresses);
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

**File:** storage.js (L2298-2300)
```javascript
						if (!assocUnits[prow.unit].earned_headers_commission_recipients)
							assocUnits[prow.unit].earned_headers_commission_recipients = {};
						assocUnits[prow.unit].earned_headers_commission_recipients[prow.address] = prow.earned_headers_commission_share;
```

**File:** validation.js (L911-917)
```javascript
	const recipients = storage.getTpsFeeRecipients(objUnit.earned_headers_commission_recipients, author_addresses);
	for (let address in recipients) {
		const share = recipients[address] / 100;
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

**File:** initial-db/byteball-sqlite.sql (L999-1005)
```sql
CREATE TABLE tps_fees_balances (
	address CHAR(32) NOT NULL,
	mci INT NOT NULL,
	tps_fees_balance INT NOT NULL DEFAULT 0, -- can be negative
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (address, mci DESC)
);
```
