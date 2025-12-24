# Vulnerability Validation Report

## Title
JavaScript Precision Loss in Indivisible Asset Serial Number Causes Permanent Issuance Freeze

## Summary
The validation system does not enforce a maximum safe integer limit on serial numbers for indivisible assets. An attacker can issue an asset with `serial_number` exceeding JavaScript's `MAX_SAFE_INTEGER` (2^53-1), which passes validation but causes arithmetic precision loss in subsequent issuance operations, permanently freezing all future issuance for that asset denomination.

## Impact

**Severity**: High  
**Category**: Permanent Fund Freeze

The vulnerability causes complete and permanent loss of issuance capability for the affected indivisible asset denomination. Once exploited, all subsequent attempts to automatically issue new coins for that denomination fail with database UNIQUE constraint violations due to JavaScript floating-point arithmetic limitations. 

**Affected Parties**: 
- Asset definers/owners who lose ability to issue new NFTs
- Users expecting to receive NFTs from the compromised denomination
- AA contracts that attempt to issue the asset automatically

**Recovery**: No on-chain recovery mechanism exists. Requires manual database intervention or protocol hard fork requiring network consensus.

## Finding Description

**Location**: 
- `byteball/ocore/validation_utils.js` lines 27-29, function `isPositiveInteger()`
- `byteball/ocore/validation.js` lines 2087-2088, serial number validation
- `byteball/ocore/indivisible_asset.js` line 518, function `issueNextCoin()`

**Intended Logic**: Serial numbers for indivisible asset issuance should be validated to remain within JavaScript's safe integer range (≤ 2^53-1 = 9,007,199,254,740,991) to prevent arithmetic precision loss.

**Actual Logic**: Validation only checks that serial numbers are positive integers without any upper bound check [1](#0-0) , while amounts are checked against `MAX_CAP` [2](#0-1) . The `isPositiveInteger()` function only validates positivity [3](#0-2) , allowing values exceeding `MAX_SAFE_INTEGER` [4](#0-3) .

**Exploitation Path**:

1. **Preconditions**: Attacker has issuance rights for an uncapped indivisible asset (`fixed_denominations=true`, `cap=null`)

2. **Step 1 - Malicious Issuance**: 
   - Attacker submits unit with issue input containing `serial_number: 9007199254740992` (exactly 2^53)
   - Validation at `validation.js:2087-2088` passes: `isPositiveInteger(9007199254740992)` returns true
   - For uncapped assets, validation at lines 2089-2092 [5](#0-4)  does not restrict serial_number value
   - Unit is accepted and stored successfully

3. **Step 2 - Database Storage**: 
   - Database correctly stores `serial_number` as BIGINT [6](#0-5) 
   - UNIQUE constraint [7](#0-6)  satisfied (first occurrence)
   - `asset_denominations.max_issued_serial_number` recorded as 9007199254740992

4. **Step 3 - Precision Loss Trigger**: 
   - Legitimate user attempts automatic issuance via `issueNextCoin()` 
   - Line 518 executes: `var serial_number = row.max_issued_serial_number+1` [8](#0-7) 
   - **IEEE 754 precision loss**: `9007199254740992 + 1` evaluates to `9007199254740992` (no change!)
   - Database UPDATE [9](#0-8)  correctly increments to 9007199254740993
   - JavaScript variable `serial_number` remains 9007199254740992

5. **Step 4 - Permanent Freeze**: 
   - INSERT attempt into `inputs` table with serial_number = 9007199254740992
   - UNIQUE constraint violation (conflicts with malicious issuance)
   - All subsequent issuance attempts repeat this failure indefinitely

**Security Property Broken**: Indivisible asset issuance mechanism integrity - The serial number sequence becomes permanently unusable despite database preventing actual duplicates.

**Root Cause Analysis**:
- JavaScript IEEE 754 double-precision numbers have 53-bit mantissa (safe integer range: ±2^53-1)
- Database BIGINT supports 63-bit signed integers
- Asymmetric validation: `amount` has MAX_CAP check, `serial_number` has none
- No validation bridge between JavaScript arithmetic limits and database storage capacity

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with issuance rights for uncapped indivisible assets
- **Resources**: Minimal - standard unit fee (<$0.01)
- **Technical Skill**: Low - requires only understanding of JSON unit structure

**Preconditions**:
- Normal network operation (no special conditions)
- Access to uncapped indivisible asset with issuance rights
- No timing constraints

**Execution Complexity**:
- Single unit submission
- No coordination required
- Appears as legitimate asset issuance

**Overall Assessment**: High likelihood - trivial execution, minimal cost, permanent impact, repeatable across multiple assets.

## Recommendation

**Immediate Mitigation**:
Add validation check for serial_number upper bound in `validation.js`:

```javascript
// In validation.js, after line 2088
if (input.serial_number > Number.MAX_SAFE_INTEGER)
    return cb("serial_number exceeds MAX_SAFE_INTEGER: " + input.serial_number);
```

**Permanent Fix**:
Validate all user-provided numeric inputs against MAX_SAFE_INTEGER throughout the codebase to ensure JavaScript arithmetic safety.

**Additional Measures**:
- Add test case verifying serial_number bounds validation
- Database migration: Check for existing assets with problematic serial numbers
- Documentation: Clarify safe integer limits for asset issuance

## Proof of Concept

```javascript
const test = require('ava');
const composer = require('../composer.js');
const validation = require('../validation.js');

test('serial_number exceeding MAX_SAFE_INTEGER causes permanent freeze', async t => {
    // Setup: Create uncapped indivisible asset
    const asset = 'test_asset_hash';
    const denomination = 1000;
    
    // Step 1: Submit unit with serial_number = 2^53
    const maliciousUnit = {
        messages: [{
            app: 'payment',
            payload_location: 'inline',
            payload: {
                asset: asset,
                denomination: denomination,
                inputs: [{
                    type: 'issue',
                    serial_number: 9007199254740992, // 2^53
                    amount: denomination
                }],
                outputs: [{address: 'ATTACKER_ADDRESS', amount: denomination}]
            }
        }]
    };
    
    // Verify malicious unit passes validation
    const validationResult = await validation.validate(maliciousUnit);
    t.is(validationResult, null, 'Malicious unit should pass validation');
    
    // Step 2: Attempt subsequent issuance via issueNextCoin()
    const indivisibleAsset = require('../indivisible_asset.js');
    
    try {
        await indivisibleAsset.issueNextCoin(asset, denomination);
        t.fail('Should have failed with UNIQUE constraint violation');
    } catch (err) {
        // Verify it's a UNIQUE constraint error
        t.regex(err.message, /UNIQUE.*constraint/i, 'Should fail with UNIQUE constraint error');
    }
    
    // Step 3: Verify precision loss
    const maxSerial = 9007199254740992;
    const nextSerial = maxSerial + 1;
    t.is(nextSerial, maxSerial, 'JavaScript fails to increment beyond MAX_SAFE_INTEGER');
    
    // Step 4: Verify permanent freeze
    // Any subsequent issuance attempts will fail with same error
    try {
        await indivisibleAsset.issueNextCoin(asset, denomination);
        t.fail('Second attempt should also fail');
    } catch (err) {
        t.regex(err.message, /UNIQUE.*constraint/i, 'Freeze is permanent');
    }
});
```

## Notes

This vulnerability demonstrates a critical mismatch between JavaScript's numeric limitations and database storage capabilities. The asymmetric validation (checking `amount` against MAX_CAP but not checking `serial_number` bounds) creates an exploitable gap. While the database correctly prevents duplicate serial numbers, the JavaScript arithmetic failure causes a permanent denial-of-service condition for that asset denomination's issuance mechanism.

### Citations

**File:** validation.js (L2083-2086)
```javascript
					if (!isPositiveInteger(input.amount))
						return cb("amount must be positive");
					if (input.amount > constants.MAX_CAP)
						return cb("issue ampunt too large: " + input.amount)
```

**File:** validation.js (L2087-2088)
```javascript
					if (!isPositiveInteger(input.serial_number))
						return cb("serial_number must be positive");
```

**File:** validation.js (L2089-2092)
```javascript
					if (!objAsset || objAsset.cap){
						if (input.serial_number !== 1)
							return cb("for capped asset serial_number must be 1");
					}
```

**File:** validation_utils.js (L27-29)
```javascript
function isPositiveInteger(int){
	return (isInteger(int) && int > 0);
}
```

**File:** constants.js (L10-11)
```javascript
if (!Number.MAX_SAFE_INTEGER)
	Number.MAX_SAFE_INTEGER = Math.pow(2, 53) - 1; // 9007199254740991
```

**File:** initial-db/byteball-mysql.sql (L291-291)
```sql
	serial_number BIGINT NULL, -- issue
```

**File:** initial-db/byteball-mysql.sql (L297-297)
```sql
	UNIQUE KEY byAssetDenominationSerialAddress(asset, denomination, serial_number, address, is_unique), -- UNIQUE guarantees there'll be no double issue
```

**File:** indivisible_asset.js (L518-518)
```javascript
					var serial_number = row.max_issued_serial_number+1;
```

**File:** indivisible_asset.js (L521-523)
```javascript
					conn.query(
						"UPDATE asset_denominations SET max_issued_serial_number=max_issued_serial_number+1 WHERE denomination=? AND asset=?", 
						[denomination, asset], 
```
