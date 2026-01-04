# NoVulnerability found for this question.

## Validation Assessment

After applying the comprehensive Obyte Protocol Validation Framework, I **confirm the anti-vulnerability claim is correct**. The type inconsistency in `getTpsFeeRecipients()` is a code quality bug but NOT a security vulnerability meeting Immunefi criteria.

## Technical Verification

The claim accurately identifies a genuine type inconsistency:

**During Validation:** `earned_headers_commission_recipients` arrives as an **array** from network units. [1](#0-0) 

**During Storage:** The array is converted to an **object** for database persistence. [2](#0-1) 

**In getTpsFeeRecipients():** The function uses `for...in` iteration which behaves differently for arrays (iterating indices "0", "1") versus objects (iterating keys). [3](#0-2) 

When `getTpsFeeRecipients()` receives an array during validation [4](#0-3) , the `for...in` loop iterates over string indices ("0", "1") instead of addresses. Since `author_addresses.includes("0")` returns false, the function incorrectly determines there are external recipients and overrides to give 100% to the first author.

## Why This is NOT a Security Vulnerability

### 1. **Fails Immunefi Severity Thresholds**

**Medium Severity Requires:**
- Temporary transaction delay ≥1 hour, OR  
- Unintended AA behavior

**Reality:** No concrete evidence demonstrates this causes ≥1 hour delays. During validation, the wrong address's balance is checked, but during deduction (after stabilization), correct recipients are charged. [5](#0-4)  The TPS fee mechanism continues functioning - fees are validated and charged, rate limiting works, and exponential fee increases during congestion still apply.

### 2. **Voluntary Multi-Party Participation**

Multi-author units require **all authors to cryptographically sign**. Both addresses A and B must voluntarily sign the unit. If address B refuses to subsidize A's TPS fees, B simply doesn't sign the unit. There is no victim - only willing participants who choose to co-author and share TPS balance responsibility.

### 3. **Negative Balances Are Intentional Design**

The database schema explicitly allows negative TPS fee balances: [6](#0-5) 

The comment `-- can be negative` indicates this is intentional protocol design, not a security flaw. Addresses can accumulate "TPS debt" when actual fees exceed paid amounts, which is reconciled when units stabilize.

### 4. **No Unauthorized State Changes**

- Validation checks if first author can afford the fee [7](#0-6) 
- Deduction charges the correct author per `earned_headers_commission_recipients`
- Both operations are deterministic across all nodes (no consensus break)
- No funds are stolen (each author controls their own address)
- No outputs are frozen or made unspendable

### 5. **TPS Rate Limiting Remains Effective**

Even with the accounting inconsistency:
- Units must still declare sufficient `tps_fee` to pass validation
- Actual fees are still deducted from balances during deduction
- Addresses with negative balances face exponentially increasing fees
- The economic disincentive against spam/congestion remains intact

## Notes

This is a **code quality bug** warranting a fix (using `for...in` on arrays is incorrect JavaScript practice), but it:

- Affects only edge-case multi-author units with custom `earned_headers_commission_recipients`
- Impacts only voluntary co-authors who both signed the unit  
- Lacks concrete evidence of ≥1 hour delays (Medium threshold)
- Creates no unauthorized state changes or fund movements
- Allows intentional "TPS balance sharing" between willing co-authors

**Recommended Fix:** Modify `getTpsFeeRecipients()` to handle both array and object formats, or standardize the data type throughout the codebase. However, this is a code improvement, not a security vulnerability qualifying for Immunefi bounty.

The anti-vulnerability assessment correctly applies the validation framework by recognizing that behavioral inconsistency between voluntary participants, without demonstrable exploitability causing measurable harm per Immunefi thresholds, does not constitute a bounty-eligible security vulnerability.

### Citations

**File:** validation.js (L911-911)
```javascript
	const recipients = storage.getTpsFeeRecipients(objUnit.earned_headers_commission_recipients, author_addresses);
```

**File:** validation.js (L916-917)
```javascript
		if (tps_fees_balance + objUnit.tps_fee * share < min_tps_fee * share)
			return callback(`tps_fee ${objUnit.tps_fee} + tps fees balance ${tps_fees_balance} less than required ${min_tps_fee} for address ${address} whose share is ${share}`);
```

**File:** validation.js (L933-933)
```javascript
		if (!isNonemptyArray(objUnit.earned_headers_commission_recipients))
```

**File:** writer.js (L571-575)
```javascript
		if ("earned_headers_commission_recipients" in objUnit) {
			objNewUnitProps.earned_headers_commission_recipients = {};
			objUnit.earned_headers_commission_recipients.forEach(function(row){
				objNewUnitProps.earned_headers_commission_recipients[row.address] = row.earned_headers_commission_share;
			});
```

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

**File:** initial-db/byteball-sqlite.sql (L1002-1002)
```sql
	tps_fees_balance INT NOT NULL DEFAULT 0, -- can be negative
```
