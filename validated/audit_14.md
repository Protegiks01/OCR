# NoVulnerability found for this question.

## Validation Assessment

I have thoroughly analyzed the anti-vulnerability claim regarding the type inconsistency in `getTpsFeeRecipients()` and **confirm it is correct** - this is NOT a security vulnerability meeting Immunefi criteria.

## Technical Analysis Confirmation

The claim correctly identifies a genuine code bug:

**The Inconsistency:**
- During validation: `earned_headers_commission_recipients` is an **array** [1](#0-0) 
- During deduction: It's converted to an **object** [2](#0-1) 
- `getTpsFeeRecipients()` uses `for...in` which behaves differently for arrays vs objects [3](#0-2) 

When given an array, `for...in` iterates over indices ("0", "1") instead of addresses, causing the function to always override to the first author.

## Why This is NOT a Vulnerability

### 1. **Impact Fails to Meet Medium Severity Threshold**

Per Immunefi scope, Medium severity requires:
- Temporary transaction delay **≥1 hour**, OR
- Unintended AA behavior

**The claim provides NO concrete evidence** that this inconsistency causes ≥1 hour delays. Speculative "could bypass congestion control" statements without demonstrated network impact do not meet the threshold.

### 2. **Both Parties Are Voluntary Participants**

The scenario requires:
- Multi-author unit with addresses A and B
- Both A and B sign the unit [4](#0-3) 
- Custom `earned_headers_commission_recipients` specified

Both addresses are controlled by the unit creators who voluntarily structured their transaction this way. This is self-imposed behavior, not unauthorized access.

### 3. **Negative Balances Are By Design**

The database schema explicitly allows negative TPS fee balances: [5](#0-4) 

The comment `-- can be negative` indicates this is intentional design, not a security flaw.

### 4. **No Direct Harm or Fund Loss**

- No theft of bytes or assets
- No unauthorized spending
- No consensus break
- No fund freeze
- Only accounting inconsistency between the creator's own addresses

### 5. **TPS Fee Mechanism Still Functions**

Even with the inconsistency:
- Validation still requires sufficient `tps_fee` field in units [6](#0-5) 
- Deduction still charges fees [7](#0-6) 
- Rate limiting continues to increase fees exponentially during congestion
- No demonstrated bypass of economic disincentives

## Notes

This is a **code quality bug** that should be fixed (using `for...in` with arrays is incorrect), but it:
- Affects only edge case multi-author units with custom commission recipients
- Impacts only the unit creators themselves who control both addresses  
- Lacks concrete evidence of meeting Immunefi Medium severity thresholds
- Does not enable unauthorized state changes or fund movements

The anti-vulnerability claim correctly applies the validation framework by identifying that behavioral inconsistency alone, without demonstrated exploitability causing measurable harm (≥1 hour delay, fund loss, consensus break), does not constitute a security vulnerability for bounty purposes.

### Citations

**File:** validation.js (L909-911)
```javascript
	const author_addresses = objUnit.authors.map(a => a.address);
	const bFromOP = isFromOP(author_addresses, objValidationState.last_ball_mci);
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

**File:** storage.js (L1209-1223)
```javascript
			const tps_fee = getFinalTpsFee(objUnitProps) * (1 + (objUnitProps.count_aa_responses || 0));
			await conn.query("UPDATE units SET actual_tps_fee=? WHERE unit=?", [tps_fee, objUnitProps.unit]);
			const total_tps_fees_delta = (objUnitProps.tps_fee || 0) - tps_fee; // can be negative
			//	if (total_tps_fees_delta === 0)
			//		continue;
			/*	const recipients = (objUnitProps.earned_headers_commission_recipients && total_tps_fees_delta < 0)
					? storage.getTpsFeeRecipients(objUnitProps.earned_headers_commission_recipients, objUnitProps.author_addresses)
					: (objUnitProps.earned_headers_commission_recipients || { [objUnitProps.author_addresses[0]]: 100 });*/
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
