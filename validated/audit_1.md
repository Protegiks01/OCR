# Audit Report: Case-Sensitivity Bypass in AA Bounce Fee Validation

## Title
Inconsistent Address Validation Creates Permanent Fund Loss When Sending to Lowercase AA Addresses

## Summary
The Obyte protocol uses two different address validation functions inconsistently: `isValidAddressAnyCase()` in payment validation and `isValidAddress()` (uppercase-only) in AA bounce fee checking. This allows users to send payments to AA addresses in lowercase format without bounce fee validation, resulting in permanent fund loss when the AA execution fails due to insufficient fees.

## Impact

**Severity**: Critical  
**Category**: Permanent Fund Freeze

Users sending payments to AA addresses in lowercase or mixed-case format with insufficient bounce fees will permanently lose their funds. The impact differs by database backend:
- **MySQL (case-insensitive)**: AA executes but cannot refund due to insufficient bounce fees; AA keeps all funds
- **SQLite (case-sensitive)**: AA trigger not detected; funds sent to non-existent lowercase address with no recovery mechanism

All users are affected, especially those using wallet implementations that normalize addresses to lowercase. Recovery is impossible without a hard fork.

## Finding Description

**Location**: Multiple files demonstrating inconsistent address validation

**Root Cause**: The codebase uses `isValidAddress()` (uppercase-only) for bounce fee checks but `isValidAddressAnyCase()` (any case) for general payment validation, creating a security gap.

### Intended Logic
All payments to AA addresses must undergo bounce fee validation via `checkAAOutputs()` before acceptance. This function should identify all AA addresses in payment outputs and verify bounce fee requirements are met.

### Actual Logic  
The bounce fee checker silently filters out non-uppercase addresses, causing them to bypass validation entirely.

### Code Evidence

**Address validation functions have different case requirements:** [1](#0-0) [2](#0-1) 

**Bounce fee check filters with uppercase-only validation:** [3](#0-2) 

**Payment validation accepts any case:** [4](#0-3) [5](#0-4) 

**Addresses stored as-is without normalization:** [6](#0-5) 

**Bounce logic permanently keeps funds when insufficient:** [7](#0-6) [8](#0-7) 

### Exploitation Path

1. **Preconditions**: User has funds and wants to send payment to an AA address
   
2. **Step 1**: User provides AA address in lowercase format (e.g., `abc123...xyz` instead of `ABC123...XYZ`) with payment below bounce fee requirement
   - Code path: `wallet.js:sendMultiPayment()` constructs payment array
   
3. **Step 2**: Wallet invokes bounce fee validation [9](#0-8) 
   
4. **Step 3**: Address filtering silently excludes lowercase addresses
   - `aa_addresses.js:checkAAOutputs()` extracts addresses
   - Calls `readAADefinitions(arrAddresses)` which filters with `isValidAddress`
   - Lowercase addresses removed from array
   - Empty result returned, no error raised
   
5. **Step 4**: Transaction passes validation and enters DAG
   - General validation uses `isValidAddressAnyCase()` which accepts lowercase
   - Unit validated and stored with lowercase address intact
   
6. **Step 5**: AA trigger detection behavior differs by database [10](#0-9) 
   
   Database schema shows collation differences: [11](#0-10) [12](#0-11) 
   
7. **Step 6**: Permanent fund loss
   - **MySQL**: Case-insensitive JOIN succeeds, AA triggered with insufficient bounce fees, `bounce()` returns without refund
   - **SQLite**: Case-sensitive JOIN fails, no AA trigger, funds sit at lowercase address with no definition (computationally infeasible to recover)

**Security Property Broken**: Balance Conservation Invariant - Failed AA executions must refund inputs minus bounce fees. This vulnerability allows complete fund loss.

## Impact Explanation

**Affected Assets**: Bytes (native currency), all divisible and indivisible custom assets

**Damage Severity**:
- **Quantitative**: Unbounded - any payment to lowercase AA addresses with insufficient bounce fees (<10,000 bytes minimum) is permanently lost
- **Qualitative**: Permanent and irreversible. Requires hard fork intervention for recovery.

**User Impact**:
- **Who**: All users, especially those using wallets that normalize addresses to lowercase
- **Conditions**: Payment to AA in non-uppercase format AND amount below required bounce fee
- **Recovery**: None - funds permanently inaccessible

**Systemic Risk**:
- Silent failure provides no warning to users
- Any wallet normalizing addresses to lowercase systematically triggers this
- Creates "footgun" where honest users lose funds through normal operation

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user (can occur accidentally)
- **Resources**: Standard transaction fees only
- **Technical Skill**: None - simply providing lowercase address triggers vulnerability

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Standard wallet with funds
- **Timing**: No constraints

**Execution Complexity**:
- **Transaction Count**: Single transaction
- **Coordination**: None
- **Detection Risk**: Low - appears normal until funds lost

**Overall Assessment**: High likelihood - low barrier, can occur accidentally, provides no warning, silent failure mode.

## Recommendation

**Immediate Mitigation**:
Normalize addresses to uppercase in `readAADefinitions()` before filtering:

```javascript
// File: aa_addresses.js, line 37
arrAddresses = arrAddresses.map(addr => addr.toUpperCase()).filter(isValidAddress);
```

**Alternative Fix**:
Use `isValidAddressAnyCase` consistently:

```javascript
// File: aa_addresses.js, line 37
arrAddresses = arrAddresses.filter(ValidationUtils.isValidAddressAnyCase);
```

**Additional Measures**:
- Add address case normalization at wallet composition layer
- Add validation to reject non-uppercase addresses in payment outputs
- Add test case verifying bounce fee checks work with lowercase addresses
- Database migration to normalize existing lowercase addresses (if any)

## Proof of Concept

The vulnerability is demonstrable through code inspection and doesn't require a complex PoC. A test would:

1. Create AA with bounce_fees requirement
2. Compose payment to AA address in lowercase with insufficient fees
3. Verify `checkAAOutputs()` returns success (no error)
4. Verify general validation accepts the unit
5. Verify funds are lost (database-dependent behavior)

**Notes**

This is a critical vulnerability caused by inconsistent use of two similar validation functions. The fix is straightforward - normalize addresses to uppercase before filtering, or use the case-insensitive validation function consistently. The vulnerability affects all users and can result in permanent, unrecoverable fund loss through normal wallet operations.

### Citations

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

**File:** aa_addresses.js (L37-39)
```javascript
	arrAddresses = arrAddresses.filter(isValidAddress);
	if (arrAddresses.length === 0)
		return handleRows([]);
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

**File:** writer.js (L395-397)
```javascript
									"INSERT INTO outputs \n\
									(unit, message_index, output_index, address, amount, asset, denomination, is_serial) VALUES(?,?,?,?,?,?,?,1)",
									[objUnit.unit, i, j, output.address, parseInt(output.amount), payload.asset, denomination]
```

**File:** aa_composer.js (L880-881)
```javascript
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
```

**File:** aa_composer.js (L886-887)
```javascript
			if (fee > amount)
				return finish(null);
```

**File:** wallet.js (L1965-1972)
```javascript
	if (!opts.aa_addresses_checked) {
		aa_addresses.checkAAOutputs(arrPayments, function (err) {
			if (err)
				return handleResult(err);
			opts.aa_addresses_checked = true;
			sendMultiPayment(opts, handleResult);
		});
		return;
```

**File:** main_chain.js (L1603-1610)
```javascript
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
```

**File:** initial-db/byteball-mysql.sql (L803-803)
```sql
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
```

**File:** initial-db/byteball-sqlite.sql (L812-813)
```sql
CREATE TABLE aa_addresses (
	address CHAR(32) NOT NULL PRIMARY KEY,
```
