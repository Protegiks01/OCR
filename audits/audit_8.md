# Audit Report: Case-Sensitivity Mismatch in AA Address Validation

## Title
Case-Sensitivity Inconsistency Between Address Validation Functions Causes Permanent Fund Freeze for AA Payments

## Summary
A critical architectural inconsistency exists between two address validation functions in the Obyte protocol. The bounce fee validation uses the strict uppercase-only `isValidAddress` function, while general payment validation uses the permissive `isValidAddressAnyCase` function. This allows payments to AA addresses in non-uppercase format to bypass bounce fee validation entirely, resulting in permanent fund loss when units stabilize due to database JOIN failures (SQLite) or insufficient bounce fee handling (MySQL).

## Impact
**Severity**: Critical  
**Category**: Permanent Fund Freeze

Funds sent to AA addresses in lowercase or mixed-case format with insufficient bounce fees become permanently inaccessible. In SQLite deployments (case-sensitive by default), the AA trigger detection JOIN fails to match lowercase output addresses with uppercase AA addresses, leaving funds locked at a non-existent address. In MySQL deployments (case-insensitive collation), the JOIN succeeds but the AA bounces without refunding due to insufficient fees. Both outcomes result in permanent, irreversible fund loss affecting all asset types (bytes, divisible, and indivisible assets) with no upper limit per transaction.

## Finding Description

**Location**: Multiple files in `byteball/ocore`:
- `validation_utils.js`: Address validation function definitions
- `aa_addresses.js`: Bounce fee validation logic
- `validation.js`: Payment output validation
- `main_chain.js`: AA trigger detection JOIN query
- `writer.js`: Output storage without normalization
- `aa_composer.js`: Bounce logic with insufficient fee handling

**Intended Logic**: 
The bounce fee validation system should identify all AA addresses in payment outputs and verify sufficient bounce fees (minimum 10,000 bytes for base asset) are included. [1](#0-0)  This protection prevents users from losing funds when AA execution fails, as bounce responses should refund inputs minus bounce fees.

**Actual Logic**:  
The bounce fee validation silently excludes non-uppercase addresses due to function inconsistency. The `readAADefinitions` function filters addresses using the strict uppercase-only validator [2](#0-1) , causing lowercase addresses to be removed. When the filtered array is empty, the function returns immediately without error [3](#0-2) .

However, general payment validation uses the permissive validator that accepts any case [4](#0-3) , allowing the unit to enter the DAG.

**Code Evidence**:

Two validation functions with different case requirements exist:

`isValidAddress` requires uppercase: [5](#0-4) 

`isValidAddressAnyCase` accepts any case: [6](#0-5) 

The bounce fee check uses the strict function and silently bypasses validation: [2](#0-1) [3](#0-2) 

General validation uses the permissive function: [7](#0-6) [4](#0-3) 

**Exploitation Path**:

1. **Preconditions**: User wants to send payment to an AA address with insufficient bounce fees (< 10,000 bytes for base asset)

2. **Step 1**: User provides AA address in lowercase format through `wallet.js:sendMultiPayment()`
   - Entry point: [8](#0-7) 
   - Outputs array contains lowercase AA address with amount < MIN_BYTES_BOUNCE_FEE

3. **Step 2**: Bounce fee validation invoked but silently fails
   - Validation call: [9](#0-8) 
   - `checkAAOutputs` extracts addresses: [10](#0-9) 
   - `readAADefinitions` filters with uppercase-only validator: [2](#0-1) 
   - Lowercase address filtered out, empty array causes silent return: [3](#0-2) 

4. **Step 3**: Unit passes general validation and enters DAG
   - Payment validation uses permissive validator: [4](#0-3) 
   - Lowercase address passes checksum validation regardless of case
   - Unit accepted and stored without normalization: [11](#0-10) 

5. **Step 4**: Permanent fund loss when unit stabilizes
   - AA trigger detection uses database JOIN: [12](#0-11) 
   - **SQLite** (case-sensitive strings by default): [13](#0-12)  - JOIN fails to match lowercase output address with uppercase AA address → No trigger detected → Funds locked at non-existent address
   - **MySQL** (case-insensitive by default): [14](#0-13)  - JOIN succeeds but bounce logic checks insufficient fees: [15](#0-14)  → Execution returns null with no refund: [16](#0-15)  → Funds lost

**Security Property Broken**: 
Balance Conservation Invariant - All funds must either reach their intended destination or be returned to sender. This vulnerability allows funds to be sent to addresses where they become permanently inaccessible, violating the protocol's fundamental guarantee that failed AA executions refund inputs minus bounce fees.

**Root Cause Analysis**:
The root cause is architectural inconsistency in address validation. Two functions exist with different case requirements, but no address normalization reconciles them. The bounce fee checker uses the stricter function [2](#0-1) , while general validation uses the permissive function [4](#0-3) . Addresses are preserved in their original case throughout the system [11](#0-10) , with no normalization before database storage or JOIN operations. This creates a validation gap where addresses pass general validation but bypass AA-specific safety checks.

## Impact Explanation

**Affected Assets**: 
- Bytes (native currency)
- All custom divisible assets
- All custom indivisible assets
- Any funds sent to AA addresses with insufficient bounce fees in non-uppercase format

**Damage Severity**:
- **Quantitative**: Unlimited - any payment to lowercase/mixed-case AA address with insufficient bounce fees is permanently lost. A single transaction could lose arbitrary amounts. Network-wide impact: all users who provide non-uppercase AA addresses are vulnerable.
- **Qualitative**: Permanent and irreversible without hard fork intervention. Even AA owners cannot extract locked funds as they lack the private key for the lowercase address variant (which has no corresponding definition, since `getChash160` always returns uppercase).

**User Impact**:
- **Who**: All users sending payments to AA addresses, especially those using wallet UIs that accept case-insensitive address entry, copy-pasting addresses from sources that normalize case, or manually entering addresses
- **Conditions**: Triggered when AA address provided in non-uppercase format AND payment amount < required bounce fee (minimum 10,000 bytes for base asset) [1](#0-0) 
- **Recovery**: None - funds permanently inaccessible without hard fork to modify outputs table or implement special recovery logic

**Systemic Risk**:
- Silent failure mode provides no error message or warning despite critical validation bypass
- Wallet implementations that normalize addresses to lowercase would systematically trigger this vulnerability
- Social engineering attacks possible where adversaries provide lowercase AA addresses to victims
- Creates dangerous "footgun" scenario where honest users following normal procedures can lose funds

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with wallet access, or adversary providing addresses to victims
- **Resources Required**: Minimal - only standard transaction fees (typically < 1000 bytes)
- **Technical Skill**: None required - simply provide lowercase address (can occur accidentally through copy-paste or manual entry)

**Preconditions**:
- **Network State**: Normal operation, no special conditions needed
- **Attacker State**: Standard wallet with any amount of funds to send
- **Timing**: No timing constraints - works at any time

**Execution Complexity**:
- **Transaction Count**: Single transaction
- **Coordination**: None required
- **Detection Risk**: Low - appears as normal payment, silent validation bypass provides no error logs

**Frequency**:
- **Repeatability**: Unlimited - works for any payment to any AA in lowercase/mixed-case format
- **Scale**: Per-transaction, affects individual payments

**Overall Assessment**: High likelihood due to extremely low technical barrier, potential for accidental triggering through user error or UI case normalization, and complete lack of warning or error messaging during the critical validation bypass.

## Recommendation

**Immediate Mitigation**:
Normalize all addresses to uppercase before storage in the `writer.js` module to ensure consistency with AA address format.

**Permanent Fix**:
Add address normalization in the validation layer or modify `checkAAOutputs` to use `isValidAddressAnyCase` and convert addresses to uppercase for database lookup:

1. **Option 1**: Normalize at storage time in `writer.js` before INSERT
2. **Option 2**: Modify `readAADefinitions` to normalize addresses: `arrAddresses = arrAddresses.filter(isValidAddressAnyCase).map(addr => addr.toUpperCase())`
3. **Option 3**: Reject non-uppercase addresses in payment validation to enforce canonical format

**Additional Measures**:
- Add validation to reject non-uppercase AA addresses with clear error message
- Add test case verifying lowercase AA addresses are properly handled or rejected
- Database migration: Audit existing outputs table for lowercase AA addresses and implement recovery mechanism
- Update wallet UI to normalize addresses to uppercase before submission

**Validation**:
- Fix prevents bypass of bounce fee validation
- No breaking changes to existing valid transactions
- Maintains deterministic address matching in JOIN operations
- Performance impact minimal (single `.toUpperCase()` call per address)

## Proof of Concept

```javascript
const { createDatabase } = require('./test/create_db.js');
const composer = require('./composer.js');
const network = require('./network.js');
const objectHash = require('./object_hash.js');
const db = require('./db.js');

// Test demonstrating the vulnerability
async function testLowercaseAABypass() {
    await createDatabase();
    
    // Step 1: Create AA at uppercase address
    const aaDefinition = ['autonomous agent', {
        bounce_fees: { base: 10000 },
        messages: []
    }];
    const aaAddressUppercase = objectHash.getChash160(aaDefinition);
    console.log('AA Address (uppercase):', aaAddressUppercase);
    
    // Step 2: Send payment to lowercase variant with insufficient bounce fee
    const aaAddressLowercase = aaAddressUppercase.toLowerCase();
    console.log('Sending to (lowercase):', aaAddressLowercase);
    
    const payment = {
        outputs: [{
            address: aaAddressLowercase,
            amount: 5000  // Less than MIN_BYTES_BOUNCE_FEE (10000)
        }]
    };
    
    // Step 3: Verify bounce fee check is bypassed (no error thrown)
    try {
        const aa_addresses = require('./aa_addresses.js');
        await new Promise(resolve => {
            aa_addresses.checkAAOutputs([{ asset: null, outputs: payment.outputs }], (err) => {
                console.log('Bounce fee check result:', err ? err.toString() : 'NO ERROR');
                // Expected: NO ERROR (should have failed but bypassed due to case mismatch)
                resolve();
            });
        });
    } catch (e) {
        console.log('Unexpected error:', e);
    }
    
    // Step 4: Compose and submit unit (would succeed in validation)
    // Step 5: After stabilization, check if AA trigger was created
    const rows = await new Promise(resolve => {
        db.query(
            "SELECT * FROM outputs WHERE address=?",
            [aaAddressLowercase],
            resolve
        );
    });
    console.log('Output stored with lowercase address:', rows.length > 0);
    
    // In SQLite: JOIN will fail, no trigger created, funds locked
    // In MySQL: JOIN succeeds, but bounce with no refund, funds absorbed
}

testLowercaseAABypass().catch(console.error);
```

## Notes

This vulnerability affects all users interacting with Autonomous Agents. The silent bypass of bounce fee validation combined with case-sensitive database behavior in SQLite (or insufficient fee handling in MySQL) creates a permanent fund loss scenario. The fix requires careful consideration of backward compatibility, as normalizing all existing addresses might affect historical data. A phased approach with clear deprecation warnings for non-uppercase addresses is recommended.

### Citations

**File:** constants.js (L70-70)
```javascript
exports.MIN_BYTES_BOUNCE_FEE = process.env.MIN_BYTES_BOUNCE_FEE || 10000;
```

**File:** aa_addresses.js (L37-37)
```javascript
	arrAddresses = arrAddresses.filter(isValidAddress);
```

**File:** aa_addresses.js (L38-39)
```javascript
	if (arrAddresses.length === 0)
		return handleRows([]);
```

**File:** aa_addresses.js (L123-123)
```javascript
	var arrAddresses = Object.keys(assocAmounts);
```

**File:** validation.js (L1945-1946)
```javascript
			if ("address" in output && !ValidationUtils.isValidAddressAnyCase(output.address))
				return callback("output address "+output.address+" invalid");
```

**File:** validation.js (L1955-1956)
```javascript
			if (!ValidationUtils.isValidAddressAnyCase(output.address))
				return callback("output address "+output.address+" invalid");
```

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

**File:** wallet.js (L1894-1894)
```javascript
function sendMultiPayment(opts, handleResult)
```

**File:** wallet.js (L1965-1966)
```javascript
	if (!opts.aa_addresses_checked) {
		aa_addresses.checkAAOutputs(arrPayments, function (err) {
```

**File:** writer.js (L397-397)
```javascript
									[objUnit.unit, i, j, output.address, parseInt(output.amount), payload.asset, denomination]
```

**File:** main_chain.js (L1606-1607)
```javascript
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
```

**File:** initial-db/byteball-sqlite.sql (L325-325)
```sql
	address CHAR(32) NULL,  -- NULL if hidden by output_hash
```

**File:** initial-db/byteball-mysql.sql (L803-803)
```sql
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
```

**File:** aa_composer.js (L880-881)
```javascript
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
```

**File:** aa_composer.js (L1680-1687)
```javascript
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
```
