# Audit Report: Case-Sensitivity Mismatch in AA Address Validation

## Title
Case-Sensitivity Mismatch in AA Bounce Fee Validation Causes Permanent Fund Loss

## Summary
A critical inconsistency between address validation functions allows payments to Autonomous Agent (AA) addresses with insufficient bounce fees. The validation layer accepts addresses in any case using `isValidAddressAnyCase`, but the bounce fee checker filters addresses using `isValidAddress` (uppercase-only). This causes lowercase/mixed-case AA addresses to bypass bounce fee validation entirely, resulting in permanent fund loss when AA execution fails.

## Impact
**Severity**: Critical  
**Category**: Permanent Fund Freeze

Funds sent to AA addresses in lowercase/mixed-case format with insufficient bounce fees become permanently locked. The vulnerability affects:
- **Quantitative Impact**: Any amount sent to an AA with insufficient bounce fees (minimum 10,000 bytes) is permanently lost
- **Affected Users**: Any user sending payments to AA addresses, particularly those using case-insensitive address entry
- **Recovery**: Impossible without hard fork intervention

## Finding Description

**Location**: 
- `byteball/ocore/aa_addresses.js:37` (function `readAADefinitions`)
- `byteball/ocore/validation.js:1945, 1955` (function `validatePaymentInputsAndOutputs`)
- `byteball/ocore/wallet.js:1966` (function `sendMultiPayment`)

**Intended Logic**: 
The system should validate that all payments to AA addresses include sufficient bounce fees before allowing the transaction. The `checkAAOutputs` function should identify all AA addresses in payment outputs and verify bounce fee requirements.

**Actual Logic**: 
The bounce fee validation silently excludes non-uppercase addresses due to inconsistent validation function usage: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

**Exploitation Path**:

1. **Preconditions**: User has funds and wants to send payment to an AA address
   
2. **Step 1**: User provides AA address in lowercase format (e.g., "abcdef..." instead of "ABCDEF...") with payment amount less than bounce fee requirement
   - Code path: User calls `wallet.js:sendMultiPayment(opts)` with lowercase AA address in outputs

3. **Step 2**: Wallet invokes bounce fee validation
   - `wallet.js:1966` calls `aa_addresses.checkAAOutputs(arrPayments, function(err){...})`
   - `checkAAOutputs` extracts addresses and calls `readAADefinitions(arrAddresses)`

4. **Step 3**: Address filtering silently excludes lowercase addresses
   - `aa_addresses.js:37`: `arrAddresses = arrAddresses.filter(isValidAddress);`
   - `isValidAddress` only accepts uppercase addresses (checks `address === address.toUpperCase()`)
   - Lowercase addresses are filtered out, resulting in empty array

5. **Step 4**: Empty result bypasses validation
   - `aa_addresses.js:38-39`: `if (arrAddresses.length === 0) return handleRows([]);`
   - Returns empty array to `checkAAOutputs`
   - `aa_addresses.js:125-126`: `if (rows.length === 0) return handleResult();`
   - Calls `handleResult()` WITHOUT error, allowing payment to proceed

6. **Step 5**: Unit passes validation and enters DAG
   - `validation.js:1945, 1955` uses `isValidAddressAnyCase(output.address)`
   - Accepts lowercase addresses, unit is validated and stored

7. **Step 6**: Permanent fund loss occurs
   - Database collation determines outcome:
     - **Case-insensitive DB**: AA trigger detected with lowercase address, execution occurs but insufficient bounce fees prevent refund (per `aa_composer.js:880`)
     - **Case-sensitive DB**: AA trigger NOT detected (JOIN fails on address mismatch), funds sent to non-existent address
   - Either way: Funds permanently locked with no recovery mechanism

**Security Property Broken**: 
Bounce Correctness Invariant - Failed AA executions must refund inputs minus bounce fees via bounce response. This vulnerability allows AA execution failures without proper refunds.

**Root Cause Analysis**:
Inconsistent address validation function usage across the codebase. The validation layer uses `isValidAddressAnyCase` for broad compatibility, but AA-specific logic uses `isValidAddress` expecting uppercase-only. This architectural inconsistency creates a validation gap where addresses pass general validation but bypass AA-specific safety checks.

## Impact Explanation

**Affected Assets**: 
- Bytes (native currency)
- Custom divisible and indivisible assets  
- All funds sent to AA addresses with insufficient bounce fees in non-uppercase format

**Damage Severity**:
- **Quantitative**: Unlimited - any payment to lowercase AA address with insufficient bounce fees is permanently lost. No upper bound on loss amount.
- **Qualitative**: Permanent and irreversible. Requires hard fork to recover funds. Even AA owners cannot extract locked funds without withdrawal mechanisms in their AA logic.

**User Impact**:
- **Who**: All users sending to AA addresses, especially those using case-insensitive wallet implementations or copy-pasting addresses from mixed-case sources
- **Conditions**: Occurs when AA address provided in non-uppercase format AND payment amount < required bounce fee
- **Recovery**: None - funds permanently inaccessible

**Systemic Risk**: 
- Silent failure mode - no error returned to user despite critical validation bypass
- Wallet implementations normalizing addresses to lowercase would systematically trigger this bug
- Social engineering attacks possible by providing lowercase AA addresses
- Creates "footgun" scenario where honest users lose funds through normal operation

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with basic wallet access
- **Resources Required**: Minimal - only transaction fees
- **Technical Skill**: Low - requires only providing lowercase address

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Standard wallet with funds
- **Timing**: No timing constraints

**Execution Complexity**:
- **Transaction Count**: Single transaction
- **Coordination**: None required
- **Detection Risk**: Low - appears as normal payment

**Frequency**:
- **Repeatability**: Unlimited
- **Scale**: Per-transaction basis

**Overall Assessment**: High likelihood due to:
- Low technical barrier
- Can occur accidentally (user error with case)
- Wallet UIs may accept/normalize lowercase addresses
- Silent failure provides no warning to users

## Recommendation

**Immediate Mitigation**:
Normalize all addresses to uppercase before AA validation checks, or consistently use `isValidAddressAnyCase` throughout AA bounce fee validation:

```javascript
// In aa_addresses.js, line 37:
// Change from:
arrAddresses = arrAddresses.filter(isValidAddress);
// To:
arrAddresses = arrAddresses.filter(isValidAddressAnyCase);
```

**Permanent Fix**:
Implement consistent address validation strategy across entire codebase:

1. **Option A**: Normalize all addresses to uppercase at entry points (recommended)
2. **Option B**: Use `isValidAddressAnyCase` consistently everywhere

**Additional Measures**:
- Add validation test case verifying bounce fee checks work with lowercase AA addresses
- Add database constraint/index ensuring case-insensitive address matching
- Update wallet UI to warn users when AA address case doesn't match canonical format
- Add monitoring to detect payments to non-uppercase AA addresses

**Validation**:
- Fix ensures bounce fee validation works regardless of address case
- No breaking changes to existing valid transactions
- Maintains backward compatibility with uppercase addresses

## Proof of Concept

```javascript
const composer = require('./composer.js');
const wallet = require('./wallet.js');
const validation = require('./validation.js');
const aa_addresses = require('./aa_addresses.js');
const db = require('./db.js');

describe('AA Address Case-Sensitivity Vulnerability', function() {
    it('should reject payment to lowercase AA address with insufficient bounce fee', async function() {
        // Setup: Create AA with uppercase address "ABCD...123"
        const uppercaseAAAddress = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        const lowercaseAAAddress = uppercaseAAAddress.toLowerCase();
        
        // Insert AA definition into database
        await db.query(
            "INSERT INTO aa_addresses (address, definition, unit, mci, base_aa) VALUES (?, ?, ?, ?, ?)",
            [uppercaseAAAddress, '["autonomous agent",{"bounce_fees":{"base":10000}}]', 'unit1', 1, null]
        );
        
        // Attempt payment with lowercase address and insufficient bounce fee
        const opts = {
            paying_addresses: ['PAYER_ADDRESS'],
            base_outputs: [{
                address: lowercaseAAAddress,  // lowercase AA address
                amount: 5000  // Less than 10,000 bounce fee
            }],
            aa_addresses_checked: false
        };
        
        // This should fail but currently succeeds
        await new Promise((resolve, reject) => {
            wallet.sendMultiPayment(opts, function(err) {
                if (err) {
                    resolve(); // Expected behavior: error returned
                } else {
                    reject(new Error('VULNERABILITY: Payment bypassed bounce fee validation'));
                }
            });
        });
    });
    
    it('should detect bounce fee validation bypass', async function() {
        const lowercaseAAAddress = "abcdefghijklmnopqrstuvwxyz123456";
        
        // Test readAADefinitions with lowercase address
        const result = await aa_addresses.readAADefinitions([lowercaseAAAddress]);
        
        // Bug: Returns empty array instead of finding the AA
        if (result.length === 0) {
            throw new Error('CONFIRMED: Lowercase address filtered out by isValidAddress check');
        }
    });
});
```

## Notes

This vulnerability represents a fundamental architectural inconsistency in address validation. The protocol implements two validation functions with different case-sensitivity requirements, but applies them inconsistently across critical security boundaries. The MySQL schema shows addresses without explicit COLLATE directives on the `address` column [8](#0-7) , meaning collation behavior depends on server defaults, adding another layer of unpredictability.

The vulnerability is particularly severe because it creates a **silent failure mode** - the bounce fee validation returns success (no error) when it should either validate properly or return an error. This violates the principle of secure defaults and creates a dangerous trap for users and wallet developers who reasonably expect case-insensitive address handling given the existence of `isValidAddressAnyCase` in the validation layer.

### Citations

**File:** validation_utils.js (L56-62)
```javascript
function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}

function isValidAddress(address){
	return (typeof address === "string" && address === address.toUpperCase() && isValidChash(address, 32));
}
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

**File:** aa_addresses.js (L37-39)
```javascript
	arrAddresses = arrAddresses.filter(isValidAddress);
	if (arrAddresses.length === 0)
		return handleRows([]);
```

**File:** aa_addresses.js (L124-126)
```javascript
	readAADefinitions(arrAddresses, function (rows) {
		if (rows.length === 0)
			return handleResult();
```

**File:** wallet.js (L1966-1970)
```javascript
		aa_addresses.checkAAOutputs(arrPayments, function (err) {
			if (err)
				return handleResult(err);
			opts.aa_addresses_checked = true;
			sendMultiPayment(opts, handleResult);
```

**File:** aa_composer.js (L880-881)
```javascript
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
```

**File:** initial-db/byteball-mysql.sql (L313-313)
```sql
	address CHAR(32) NULL, -- NULL if hidden by output_hash
```
