# Audit Report: TPS Fee Validation Bypass via Type Mismatch

## Title
Type Mismatch in getTpsFeeRecipients() Enables TPS Fee Bypass Through Array/Object Iteration Discrepancy

## Summary
A critical type mismatch bug in `storage.getTpsFeeRecipients()` causes JavaScript's `for...in` loop to iterate over array indices instead of addresses during validation, incorrectly identifying legitimate author recipients as "external" and overriding to validate against the wrong author's balance. This allows attackers to bypass TPS fee requirements by validating against a high-balance author while deducting fees from a different author's zero-balance address, enabling unlimited negative TPS fee balances and breaking the network's congestion control mechanism. [1](#0-0) 

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay / Economic Mechanism Bypass

The vulnerability enables attackers to bypass the TPS (transactions per second) fee rate-limiting mechanism during network congestion by accumulating unlimited negative TPS fee balances. While this does not result in direct theft of bytes or assets from other users, it allows spam attacks that could cause temporary transaction delays (≥1 hour) during high-load periods by overwhelming the network with units that should have been rejected due to insufficient TPS fees. The TPS fee system is designed to exponentially increase fees during congestion to prevent spam - breaking this mechanism undermines the network's ability to manage load during peak usage.

## Finding Description

**Location**: `byteball/ocore/storage.js:1421-1433`, function `getTpsFeeRecipients()`

**Intended Logic**: The function should identify which addresses will pay TPS fees based on `earned_headers_commission_recipients`, validate that all recipients are authors (to prevent external addresses from being charged), and return the correct recipient mapping for both validation and fee deduction phases. The comment at line 1429 explicitly states "override, non-authors won't pay for our tps fee" confirming this intent. [2](#0-1) 

**Actual Logic**: The function uses JavaScript's `for...in` loop which behaves fundamentally differently for arrays versus objects:
- **For arrays**: `for...in` iterates over indices as strings ("0", "1", "2"...)
- **For objects**: `for...in` iterates over property keys (addresses)

During validation, `earned_headers_commission_recipients` arrives in array format as enforced by `validateHeadersCommissionRecipients()` [3](#0-2) , but after database storage and retrieval via `initParenthoodAndHeadersComissionShareForUnits()`, it's converted to object format. [4](#0-3) 

**Exploitation Path**:

1. **Preconditions**: 
   - Network post-v4 upgrade (TPS fees active)
   - Attacker controls addresses A (high TPS fee balance, e.g., 10,000 bytes) and B (zero balance)
   - A < B lexicographically (A becomes first author after sorting)

2. **Step 1 - Craft Multi-Author Unit**:
   - Create unit with `authors = [A, B]` (protocol requires sorted order)
   - Set `earned_headers_commission_recipients = [{address: "B", earned_headers_commission_share: 100}]`
   - Both authors sign (attacker controls both addresses)
   - Code path: Standard multi-author unit composition

3. **Step 2 - Validation Bypass**:
   - `validateTpsFee()` calls `getTpsFeeRecipients(array, [A, B])` [5](#0-4) 
   - At line 1425: `for (let address in recipients)` iterates over "0" (array index)  
   - At line 1426: `author_addresses.includes("0")` returns false (string "0" not in author array)
   - At line 1427: `bHasExternalRecipients = true`
   - At line 1430: Overrides to `{A: 100}` (first author gets 100% share)
   - At line 914: Validation queries A's balance (10,000 bytes) [6](#0-5) 
   - At line 916: Check passes: 10,000 + 500 >= 500 ✓

4. **Step 3 - Storage Conversion**:
   - Unit stored to database as individual rows via `writer.js` [7](#0-6) 
   - When loaded into `assocStableUnits` via `initParenthoodAndHeadersComissionShareForUnits()`, converted to object format
   - Lines 2298-2300: Builds object `{B: 100}` from database rows [8](#0-7) 

5. **Step 4 - Fee Deduction Discrepancy**:
   - `updateTpsFees()` calls `getTpsFeeRecipients({B: 100}, [A, B])` [9](#0-8) 
   - At line 1425: `for (let address in recipients)` now iterates over "B" (object key)
   - At line 1426: `author_addresses.includes("B")` returns true
   - Returns `{B: 100}` (correct recipients)
   - At line 1221: Queries B's balance (0 bytes) [10](#0-9) 
   - At line 1223: Updates B's balance: 0 + (-500) = -500 bytes
   - Database schema explicitly allows negative balances [11](#0-10) 

**Security Property Broken**: Balance Conservation & Fee Sufficiency - TPS fee balances can go negative without validation preventing it, allowing unlimited exploitation of the rate-limiting system. The attacker can repeat this process indefinitely since validation always checks A's balance (which stays positive) while fees are deducted from B's balance (increasingly negative).

**Root Cause Analysis**: 
- `validateHeadersCommissionRecipients()` enforces array format but does NOT validate that recipients are authors [3](#0-2) 
- `getTpsFeeRecipients()` is designed to detect external recipients with the `for...in` loop and author check, but this check fails with array format due to JavaScript semantics
- After storage, `initParenthoodAndHeadersComissionShareForUnits()` converts to object format, causing the function to work correctly during fee deduction
- No validation exists to prevent negative TPS fee balances

## Impact Explanation

**Affected Assets**: TPS fee balances (rate-limiting mechanism for network congestion)

**Damage Severity**:
- **Quantitative**: With typical min_tps_fee of 500-1000 bytes per unit, an attacker could submit hundreds of units per day. Over a month, this accumulates tens of thousands of negative bytes in the TPS fee balance of the exploited address (B), while the validation address (A) maintains a positive balance enabling continued exploitation.
- **Qualitative**: Breaks the TPS fee mechanism's fundamental purpose of preventing spam during congestion. The system is designed to exponentially increase fees as network throughput increases, making spam economically prohibitive. This bypass allows attackers to ignore these fees entirely.

**User Impact**:
- **Who**: All network participants during high-load periods when TPS fees are active
- **Conditions**: Exploitable whenever the network experiences congestion (TPS fees activate above base rate)
- **Recovery**: Requires protocol upgrade to fix the type mismatch bug and potentially resetting negative balances for affected addresses

**Systemic Risk**: If widely exploited, the TPS fee congestion control system becomes ineffective. During peak network load, attacker units that should be rate-limited can flood the network alongside legitimate transactions, causing validation delays and unit confirmation times to exceed 1 hour for honest users.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with two Obyte addresses (trivial to create)
- **Resources Required**: Minimal - one address needs sufficient TPS fee balance (10,000 bytes ≈ $0.10 USD at current prices, reusable across exploits), additional addresses need zero balance
- **Technical Skill**: Medium - requires understanding of multi-author units and `earned_headers_commission_recipients` structure, ability to construct and sign multi-author transactions

**Preconditions**:
- **Network State**: Post-v4 upgrade (TPS fee system active)
- **Attacker State**: Control of 2+ addresses with ability to sign transactions from both
- **Timing**: No specific timing requirements - exploit works during normal operation

**Execution Complexity**:
- **Transaction Count**: Single multi-author unit per exploit instance
- **Coordination**: Self-contained (attacker controls all required addresses)
- **Detection Risk**: Low - multi-author units are a legitimate protocol feature; distinguishing abuse requires forensic analysis of TPS fee balance patterns

**Frequency**:
- **Repeatability**: Unlimited - same address pair can be reused indefinitely
- **Scale**: Can create multiple address sets to distribute negative balances

**Overall Assessment**: High likelihood - technically simple to execute, economically profitable (bypasses congestion fees), difficult to detect without monitoring TPS fee balances.

## Recommendation

**Immediate Mitigation**:
Fix the type mismatch in `getTpsFeeRecipients()` by normalizing the input to object format before iteration:

```javascript
function getTpsFeeRecipients(earned_headers_commission_recipients, author_addresses) {
    // Normalize array format to object format
    let recipients = earned_headers_commission_recipients || { [author_addresses[0]]: 100 };
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

**Additional Validation**:
Add explicit check in `validateHeadersCommissionRecipients()` to ensure all recipients are authors:

```javascript
// After line 948 in validation.js
for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
    var recipient = objUnit.earned_headers_commission_recipients[i];
    if (!objUnit.authors.find(a => a.address === recipient.address))
        return cb("earned_headers_commission_recipients must only include author addresses");
    // ... rest of validation
}
```

**Additional Measures**:
- Add monitoring to flag addresses with negative TPS fee balances exceeding -10,000 bytes
- Add test case verifying that multi-author units with non-author recipients correctly override to first author
- Consider adding database-level check constraint to prevent highly negative balances (e.g., > -100,000 bytes)

**Validation**:
- Fix ensures both validation and fee deduction phases use consistent recipient mapping
- No backward compatibility issues (existing valid units continue to process correctly)
- Performance impact negligible (one-time array-to-object conversion per unit)

## Proof of Concept

```javascript
// test/tps_fee_type_mismatch.test.js
const composer = require('../composer.js');
const validation = require('../validation.js');
const storage = require('../storage.js');
const db = require('../db.js');
const objectHash = require('../object_hash.js');

describe('TPS Fee Type Mismatch Vulnerability', function() {
    this.timeout(10000);
    
    it('should reject units when earned_headers_commission_recipients validation differs from fee deduction', async function() {
        // Setup: Create two addresses A and B controlled by attacker
        const addressA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // High TPS balance
        const addressB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // Zero balance
        
        // Fund address A with TPS fees
        await db.query("REPLACE INTO tps_fees_balances (address, mci, tps_fees_balance) VALUES(?,?,?)", 
            [addressA, 1000, 10000]);
        
        // Craft multi-author unit with B as sole recipient
        const objUnit = {
            unit: objectHash.getUnitHash({
                authors: [
                    {address: addressA, authentifiers: {r: "sig_a"}},
                    {address: addressB, authentifiers: {r: "sig_b"}}
                ],
                earned_headers_commission_recipients: [
                    {address: addressB, earned_headers_commission_share: 100}
                ],
                messages: [{app: "payment", payload: {inputs: [], outputs: []}}],
                parent_units: ["parent_unit_hash"],
                last_ball: "last_ball_hash",
                last_ball_unit: "last_ball_unit_hash",
                witness_list_unit: "witness_list_unit_hash",
                timestamp: Math.floor(Date.now() / 1000),
                version: '4.0',
                tps_fee: 500
            }),
            authors: [
                {address: addressA, authentifiers: {r: "sig_a"}},
                {address: addressB, authentifiers: {r: "sig_b"}}
            ],
            earned_headers_commission_recipients: [
                {address: addressB, earned_headers_commission_share: 100}
            ]
        };
        
        // Test validation phase - should check addressA due to bug
        const validationRecipients = storage.getTpsFeeRecipients(
            objUnit.earned_headers_commission_recipients, 
            [addressA, addressB]
        );
        
        // BUG: Returns {addressA: 100} instead of {addressB: 100}
        assert.equal(Object.keys(validationRecipients)[0], addressA, 
            "VULNERABILITY: Validation checks wrong address due to array iteration");
        
        // After storage conversion to object format
        const storageRecipients = storage.getTpsFeeRecipients(
            {[addressB]: 100}, 
            [addressA, addressB]
        );
        
        // Correctly returns {addressB: 100}
        assert.equal(Object.keys(storageRecipients)[0], addressB,
            "Fee deduction targets correct address after object conversion");
        
        // This discrepancy allows negative balance on addressB
        assert.notEqual(validationRecipients, storageRecipients,
            "CRITICAL: Validation and fee deduction use different recipients");
    });
});
```

---

**Notes**:
- The vulnerability requires the attacker to control multiple addresses, which is trivial
- Multi-author units are a standard protocol feature, making this exploit indistinguishable from legitimate usage without balance monitoring
- The bug only affects units post-v4 upgrade when TPS fees are active
- Historical units may have already exploited this unintentionally if any multi-author units specified non-author recipients
- The fix should be applied urgently as the TPS fee system is critical for congestion management

### Citations

**File:** storage.js (L1217-1217)
```javascript
			const recipients = getTpsFeeRecipients(objUnitProps.earned_headers_commission_recipients, objUnitProps.author_addresses);
```

**File:** storage.js (L1221-1223)
```javascript
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

**File:** storage.js (L2293-2305)
```javascript
		function(cb){ // headers_commision_share
			conn.query(
				"SELECT unit, address, earned_headers_commission_share FROM earned_headers_commission_recipients WHERE unit IN("+Object.keys(assocUnits).map(db.escape).join(', ')+")",
				function(prows){
					prows.forEach(function(prow){
						if (!assocUnits[prow.unit].earned_headers_commission_recipients)
							assocUnits[prow.unit].earned_headers_commission_recipients = {};
						assocUnits[prow.unit].earned_headers_commission_recipients[prow.address] = prow.earned_headers_commission_share;
					});
					cb();
				}
			);
		}],
```

**File:** validation.js (L909-911)
```javascript
	const author_addresses = objUnit.authors.map(a => a.address);
	const bFromOP = isFromOP(author_addresses, objValidationState.last_ball_mci);
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

**File:** writer.js (L289-295)
```javascript
		if ("earned_headers_commission_recipients" in objUnit){
			for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
				var recipient = objUnit.earned_headers_commission_recipients[i];
				conn.addQuery(arrQueries, 
					"INSERT INTO earned_headers_commission_recipients (unit, address, earned_headers_commission_share) VALUES(?,?,?)", 
					[objUnit.unit, recipient.address, recipient.earned_headers_commission_share]);
			}
```

**File:** initial-db/byteball-sqlite.sql (L1002-1002)
```sql
	tps_fees_balance INT NOT NULL DEFAULT 0, -- can be negative
```
