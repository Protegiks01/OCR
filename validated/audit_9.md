# Audit Report: Async Error Propagation Failure in Light Client AA Definition Fetch

## Summary

The `readAADefinitions()` function in `aa_addresses.js` contains improper async error handling that silently swallows light vendor request failures. [1](#0-0)  When light clients cannot fetch AA definitions due to network errors, the validation callback is invoked without error parameters, causing `async.each` to treat failures as successes. This allows bounce fee validation to proceed with incomplete data, permitting transactions with insufficient bounce fees to reach the network. When these AAs fail during execution, the bounce mechanism detects insufficient fees and silently abandons the refund, permanently locking user funds. [2](#0-1) 

## Impact

**Severity**: Critical  
**Category**: Direct Loss of Funds

Light client users suffer permanent, unrecoverable loss of their payment amounts when network conditions prevent AA definition fetching. The minimum loss is 10,000 bytes per transaction [3](#0-2)  but can be substantially higher for AAs with custom bounce_fees or multiple asset requirements. Affected users include all light client operators interacting with AAs not in their local cache during network instability, light vendor downtime, or when encountering newly deployed AAs.

## Finding Description

**Location**: `byteball/ocore/aa_addresses.js:34-109`, function `readAADefinitions()`

**Intended Logic**: Light clients fetching AA definitions from remote vendors must propagate all failures (network errors, null responses, hash mismatches) as errors to the callback, blocking transaction composition until bounce fee requirements can be validated.

**Actual Logic**: Three error conditions call `cb()` without an error parameter: network error responses [4](#0-3) , null responses indicating unknown addresses [5](#0-4) , and definition hash mismatches [6](#0-5) . The `async.each` library interprets these as successful completions [7](#0-6) , allowing the completion callback to execute with incomplete data.

**Exploitation Path**:

1. **Preconditions**: User operates light client [8](#0-7)  with target AA address not in local database cache, during network timeout or light vendor unavailability.

2. **Step 1**: User initiates payment to AA via `sendMultiPayment()` [9](#0-8) , triggering `checkAAOutputs()` to verify bounce fees [10](#0-9) .

3. **Step 2**: Database query finds no cached definition [11](#0-10) , light client path executes requesting definition from vendor [12](#0-11) . Vendor request fails but iterator callback incorrectly signals success by calling `cb()` without error.

4. **Step 3**: Bounce fee validation loop processes only successfully loaded rows [13](#0-12) , missing target AA entirely, returning no error.

5. **Step 4**: Transaction proceeds with insufficient bounce fees. When AA execution encounters failure, bounce mechanism checks fees [14](#0-13)  and detects insufficiency [2](#0-1) , calling `finish(null)` with no bounce response sent. User funds remain permanently locked in AA.

**Security Property Broken**: Bounce Correctness Invariant - Failed AA executions must refund inputs minus bounce fees via bounce response.

**Root Cause**: Incorrect `async.each` callback semantics. The iterator expects `cb(err)` with truthy error to signal failure, but code calls `cb()` (equivalent to `cb(null)`) for all error scenarios, causing library to interpret failures as successes.

## Impact Explanation

**Affected Assets**: Base bytes (native currency), custom divisible/indivisible assets in AA bounce_fees, user wallet balances.

**Damage Severity**:
- **Quantitative**: Minimum 10,000 bytes per transaction, potentially thousands of dollars for AAs with high custom bounce_fees or multiple asset requirements
- **Qualitative**: Complete, permanent, unrecoverable fund loss with no bounce response generated

**User Impact**:
- **Who**: All light client users (mobile wallets, browser extensions) interacting with uncached AAs
- **Conditions**: Network instability, light vendor downtime, newly deployed AAs, cache cleared
- **Recovery**: None - no refund mechanism available once funds locked

**Systemic Risk**: Erodes light client user trust after unexplained losses during routine network issues; multiple users affected simultaneously during vendor infrastructure problems; users incorrectly blame AAs or protocol; creates perverse incentive for AAs to set excessive bounce fees as "insurance."

## Likelihood Explanation

**Attacker Profile**: None required - vulnerability triggers naturally during network issues. No active attacker, resources, or technical skill needed.

**Preconditions**: Light vendor timeout/overload (common during high load), AA address not in local cache (first interaction), any timing when light client encounters uncached AA during network instability.

**Execution Complexity**: Single payment transaction, no coordination, very low detection risk (appears as normal payment, logs show "failed to get definition" but transaction proceeds).

**Frequency**: Every occurrence of failed definition fetch; all light client users affected during light vendor outages.

**Overall Assessment**: High likelihood - Network instability and vendor issues occur regularly in production. Bug is deterministic once preconditions met.

## Recommendation

**Immediate Mitigation**: Modify error handling to propagate failures correctly:
```javascript
// aa_addresses.js lines 74-86
if (response && response.error)
    return cb(response.error); // Pass error to async.each

if (!response)
    return cb('Address ' + address + ' not known to light vendor');

if (objectHash.getChash160(arrDefinition) !== address)
    return cb('Definition hash mismatch for ' + address);
```

**Additional Measures**:
- Add retry logic with exponential backoff for transient network errors
- Implement client-side cache with reasonable TTL to reduce vendor dependency
- Add explicit warning to users when AA definitions cannot be verified
- Monitor and alert on light vendor availability issues

## Proof of Concept

```javascript
const test = require('ava');
const aa_addresses = require('../aa_addresses.js');
const network = require('../network.js');
const conf = require('../conf.js');

test('Light client bounce fee validation bypass on vendor failure', async t => {
    // Setup: Configure as light client
    const originalBLight = conf.bLight;
    conf.bLight = true;
    
    // Mock requestFromLightVendor to simulate network error
    const originalRequest = network.requestFromLightVendor;
    network.requestFromLightVendor = function(command, params, callback) {
        // Simulate vendor returning error
        callback(null, null, {error: 'connection timeout'});
    };
    
    try {
        // Test: Attempt to check AA outputs for uncached AA
        const testAAAddress = 'TEST_AA_ADDRESS_NOT_IN_DB';
        const payments = [{
            asset: 'base',
            outputs: [{
                address: testAAAddress,
                amount: 5000 // Insufficient for MIN_BYTES_BOUNCE_FEE (10000)
            }]
        }];
        
        // Execute validation
        await new Promise((resolve, reject) => {
            aa_addresses.checkAAOutputs(payments, (err) => {
                if (err) {
                    // Expected: Should reject with bounce fee error
                    t.fail('Validation should have failed but error propagated: ' + err);
                    reject(err);
                } else {
                    // Bug confirmed: Validation passed despite insufficient fees
                    t.pass('BUG CONFIRMED: Validation passed with insufficient bounce fees');
                    resolve();
                }
            });
        });
        
    } finally {
        // Cleanup
        conf.bLight = originalBLight;
        network.requestFromLightVendor = originalRequest;
    }
});
```

## Notes

This vulnerability affects **only light clients** - full nodes query their complete local database and never execute the vulnerable vendor request code path. The issue is particularly critical because light clients are the primary interface for mobile and web users, representing a significant portion of the user base. Network vendor failures are not exceptional edge cases but routine operational realities, making this a high-probability attack surface with no attacker coordination required.

### Citations

**File:** aa_addresses.js (L40-42)
```javascript
	db.query("SELECT definition, address, base_aa FROM aa_addresses WHERE address IN (" + arrAddresses.map(db.escape).join(', ') + ")", function (rows) {
		if (!conf.bLight || arrAddresses.length === rows.length)
			return handleRows(rows);
```

**File:** aa_addresses.js (L73-73)
```javascript
						network.requestFromLightVendor('light/get_definition', address, function (ws, request, response) {
```

**File:** aa_addresses.js (L74-86)
```javascript
							if (response && response.error) { 
								console.log('failed to get definition of ' + address + ': ' + response.error);
								return cb();
							}
							if (!response) {
								cacheOfNewAddresses[address] = Date.now();
								console.log('address ' + address + ' not known yet');
								return cb();
							}
							var arrDefinition = response;
							if (objectHash.getChash160(arrDefinition) !== address) {
								console.log("definition doesn't match address: " + address);
								return cb();
```

**File:** aa_addresses.js (L102-104)
```javascript
					function () {
						handleRows(rows);
					}
```

**File:** aa_addresses.js (L124-124)
```javascript
	readAADefinitions(arrAddresses, function (rows) {
```

**File:** aa_addresses.js (L128-140)
```javascript
		rows.forEach(function (row) {
			var arrDefinition = JSON.parse(row.definition);
			var bounce_fees = arrDefinition[1].bounce_fees;
			if (!bounce_fees)
				bounce_fees = { base: constants.MIN_BYTES_BOUNCE_FEE };
			if (!bounce_fees.base)
				bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
			for (var asset in bounce_fees) {
				var amount = assocAmounts[row.address][asset] || 0;
				if (amount < bounce_fees[asset])
					arrMissingBounceFees.push({ address: row.address, asset: asset, missing_amount: bounce_fees[asset] - amount, recommended_amount: bounce_fees[asset] });
			}
		});
```

**File:** aa_composer.js (L411-413)
```javascript
	var bounce_fees = template.bounce_fees || {base: constants.MIN_BYTES_BOUNCE_FEE};
	if (!bounce_fees.base)
		bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
```

**File:** aa_composer.js (L880-887)
```javascript
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
```

**File:** constants.js (L70-70)
```javascript
exports.MIN_BYTES_BOUNCE_FEE = process.env.MIN_BYTES_BOUNCE_FEE || 10000;
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
