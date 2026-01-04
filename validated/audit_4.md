# NoVulnerability found for this question.

## Validation Assessment

After applying the comprehensive Obyte Protocol Validation Framework, I **confirm the anti-vulnerability claim is correct**. The type inconsistency in `getTpsFeeRecipients()` is a code quality bug but NOT a security vulnerability meeting Immunefi criteria.

## Technical Verification - Confirmed Accurate

I have verified all technical claims in the codebase:

1. **Array during validation**: The function `validateHeadersCommissionRecipients` explicitly checks that `earned_headers_commission_recipients` must be a non-empty array. [1](#0-0) 

2. **Object during storage**: When persisting units, the array is converted to an object mapping addresses to shares. [2](#0-1) 

3. **Type inconsistency in getTpsFeeRecipients**: The function uses `for...in` iteration which behaves differently for arrays (iterating string indices "0", "1", "2") versus objects (iterating address keys). [3](#0-2) 

4. **Called with both types**: During validation, it receives the array from network units [4](#0-3) , but during TPS fee deduction after stabilization, it receives the object from database. [5](#0-4) 

5. **Negative balances intentional**: The database schema explicitly documents that TPS fee balances can be negative. [6](#0-5) 

## Why This is NOT a Security Vulnerability

### Fails Immunefi Severity Thresholds

Applying the **FINAL DECISION MATRIX**:

- ❌ **State change is unauthorized**: NO unauthorized state changes occur. Validation checks if the first author can afford the fee, and deduction charges the correct recipients per `earned_headers_commission_recipients`. Both operations are deterministic across all nodes.

- ❌ **Impact meets severity thresholds**: Does NOT meet any Immunefi severity level:
  - **Critical** (Network shutdown >24h, chain split, direct fund loss, permanent freeze): None apply
  - **High** (Permanent fund freeze): Does not apply
  - **Medium** (Temporary delay ≥1 hour OR unintended AA behavior): No concrete evidence demonstrates ≥1 hour delays, and this does not involve AA behavior

- ❌ **Core invariant violated**: No Obyte protocol invariant is broken. Balance conservation holds, no double-spend occurs, consensus remains intact, and all state transitions are deterministic.

### Voluntary Multi-Party Participation

Multi-author units require **all authors to cryptographically sign**. [7](#0-6)  If address B refuses to share TPS fee liability with address A, B simply doesn't sign the unit. There is no victim—only willing participants who chose to co-author.

### Deterministic Behavior Across All Nodes

- During validation: All nodes check the first author's balance (consistently wrong but deterministic)
- During deduction: All nodes charge the correct recipients (consistent and correct)
- No consensus divergence occurs
- Both operations produce identical results across all validator nodes

### No Exploitability for Gain

An attacker cannot:
- Steal funds (each author controls their own address)
- Freeze funds (outputs remain spendable)
- Cause network delays (units are simply accepted or rejected normally)
- Break consensus (all nodes apply the same logic)

## Notes

This is a **code quality bug** that should be fixed by:
- Standardizing the data type (always use object or always use array)
- Or modifying `getTpsFeeRecipients()` to handle both formats correctly

However, it:
- Affects only edge-case multi-author units with custom `earned_headers_commission_recipients`
- Impacts only voluntary co-authors who both signed the unit
- Lacks concrete evidence of ≥1 hour delays (Medium severity threshold)
- Creates no unauthorized state changes or fund movements
- Does not violate any Obyte protocol invariant
- Maintains deterministic execution across all nodes

**The anti-vulnerability assessment correctly applies the validation framework** by recognizing that behavioral inconsistency between voluntary participants, without demonstrable exploitability causing measurable harm per Immunefi thresholds, does not constitute a bounty-eligible security vulnerability.

### Citations

**File:** validation.js (L911-911)
```javascript
	const recipients = storage.getTpsFeeRecipients(objUnit.earned_headers_commission_recipients, author_addresses);
```

**File:** validation.js (L933-933)
```javascript
		if (!isNonemptyArray(objUnit.earned_headers_commission_recipients))
```

**File:** validation.js (L956-968)
```javascript
function validateAuthors(conn, arrAuthors, objUnit, objValidationState, callback) {
	if (objValidationState.bAA && arrAuthors.length !== 1)
		throw Error("AA unit with multiple authors");
	if (arrAuthors.length > constants.MAX_AUTHORS_PER_UNIT) // this is anti-spam. Otherwise an attacker would send nonserial balls signed by zillions of authors.
		return callback("too many authors");
	objValidationState.arrAddressesWithForkedPath = [];
	var prev_address = "";
	for (var i=0; i<arrAuthors.length; i++){
		var objAuthor = arrAuthors[i];
		if (objAuthor.address <= prev_address)
			return callback("author addresses not sorted");
		prev_address = objAuthor.address;
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
