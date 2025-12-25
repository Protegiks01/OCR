# Audit Report: Light Client Network Error Bypass in AA Bounce Fee Validation

## Summary

The `readAADefinitions()` function in `aa_addresses.js` improperly handles network errors when fetching AA definitions from light vendors, causing the function to return success instead of failure. [1](#0-0)  This allows light client transaction validation to proceed without verifying bounce fees, resulting in permanent fund loss when users send amounts below the minimum bounce fee threshold to Autonomous Agents. [2](#0-1) 

## Impact

**Severity**: High  
**Category**: Permanent Freezing of Funds

Light client users permanently lose funds when network failures prevent bounce fee validation during AA transactions. With the default minimum bounce fee of 10,000 bytes, [3](#0-2)  amounts sent below this threshold become irrecoverable. This affects all light client implementations (mobile wallets, browser wallets) during routine network connectivity issues.

**Affected Assets**: Bytes (native currency) and custom assets with AA-defined bounce fees

**Damage Severity**: 100% loss of sent amount when below bounce fee threshold. Permanent and irreversible with no recovery mechanism.

**User Impact**: All light client users interacting with AAs under any network instability (mobile data drops, WiFi timeouts, light vendor downtime).

## Finding Description

**Location**: `byteball/ocore/aa_addresses.js:73-81` in function `readAADefinitions()`

**Intended Logic**: When a light client cannot fetch an AA definition due to network failure, the validation should fail-safe by returning an error to prevent the user from sending a potentially unsafe transaction.

**Actual Logic**: Network errors are logged but not propagated. The callback is invoked without an error parameter, causing `async.each` to complete successfully with an incomplete results array. [1](#0-0) 

When `network.requestFromLightVendor()` encounters a connection failure, it returns `(null, null, {error: "..."})`. [4](#0-3)  Both the `response.error` case and the `!response` case call `cb()` without an error parameter, treating network failures the same as "address not found" results.

**Exploitation Path**:

1. **Preconditions**:
   - Light client operation (`conf.bLight = true`)
   - Payment to AA address not cached locally
   - Network connectivity issue (mobile data drop, WiFi timeout, light vendor unavailable)

2. **Step 1 - Transaction Composition**: User initiates payment to AA. Wallet calls `checkAAOutputs()` for bounce fee validation. [5](#0-4) 

3. **Step 2 - Network Failure**: `readAADefinitions()` attempts to fetch AA definition from light vendor. Network error occurs, returning `(null, null, {error: "..."})`. Error handler logs error but calls `cb()` without error, allowing `async.each` to succeed.

4. **Step 3 - Validation Bypass**: `checkAAOutputs()` receives empty `rows` array and returns success without error. [6](#0-5)  Transaction proceeds without bounce fee validation.

5. **Step 4 - Full Node Acceptance**: Full nodes accept the transaction because `validateAATrigger()` only counts AA triggers but does not validate bounce fee amounts. [7](#0-6) 

6. **Step 5 - Fund Loss**: AA executes and `bounce()` function checks if amount meets minimum bounce fee. [8](#0-7)  When amount is insufficient, the function returns without sending refund, permanently locking user's funds in the AA's balance.

**Security Property Broken**: **Balance Conservation & Client-Side Validation Correctness** - The protocol's client-side validation should prevent users from sending unsafe transactions. This fail-open bug bypasses the protective mechanism.

**Root Cause**: Error handling conflates network failures with "address not found" results. Network errors should propagate as validation failures (fail-safe), but instead return success (fail-open).

## Likelihood Explanation

**Attacker Profile**: None required - passive exploitation through natural network failures

**Preconditions**:
- Light client operation (all mobile wallets)
- Payment to uncached AA address
- Network timeout/connection failure (common on mobile networks)

**Execution Complexity**: Zero - occurs automatically during routine network issues

**Frequency**: High - affects every AA interaction under poor network conditions. The 60-second cache only stores "not found" responses, not network errors, [9](#0-8)  providing no protection against repeated failures.

**Overall Assessment**: High likelihood due to prevalence of mobile network unreliability and light vendor unavailability.

## Recommendation

**Immediate Mitigation**:
Propagate network errors in `readAADefinitions()`:

```javascript
// File: byteball/ocore/aa_addresses.js:73-81
network.requestFromLightVendor('light/get_definition', address, function (ws, request, response) {
    if (response && response.error) { 
        console.log('failed to get definition of ' + address + ': ' + response.error);
        return cb(response.error); // CHANGED: propagate error
    }
    if (!response) {
        cacheOfNewAddresses[address] = Date.now();
        console.log('address ' + address + ' not known yet');
        return cb();
    }
    // ... rest of function
});
```

**Additional Measures**:
- Add retry logic with exponential backoff for transient network failures
- Display user warning when AA validation cannot be completed
- Add test case verifying network errors block transaction composition

## Proof of Concept

```javascript
// File: test/light_client_bounce_fee_bypass.test.js
const test = require('ava');
const aa_addresses = require('../aa_addresses.js');
const network = require('../network.js');
const conf = require('../conf.js');

test.before(t => {
    conf.bLight = true; // Enable light client mode
});

test('network error bypasses bounce fee validation', async t => {
    // Mock network failure
    const original = network.requestFromLightVendor;
    network.requestFromLightVendor = function(command, params, cb) {
        // Simulate connection failure
        cb(null, null, {error: "connection refused"});
    };

    const payments = [{
        asset: null,
        outputs: [{address: 'AA_ADDRESS_HERE', amount: 5000}] // Below 10k bounce fee
    }];

    // This should fail but will succeed due to bug
    aa_addresses.checkAAOutputs(payments, function(err) {
        t.is(err, undefined); // BUG: Should be an error but is undefined
        network.requestFromLightVendor = original;
    });
});
```

## Notes

This vulnerability represents a classic fail-open security bug where error handling in a protective mechanism causes it to be bypassed rather than to fail safely. The fix is straightforward but critical for light client safety. The bug does not affect full nodes since they have local AA definition storage and do not use `requestFromLightVendor()`.

### Citations

**File:** aa_addresses.js (L57-81)
```javascript
				var arrCachedNewAddresses = [];
				arrRemainingAddresses.forEach(function (address) {
					var ts = cacheOfNewAddresses[address]
					if (!ts)
						return;
					if (Date.now() - ts > 60 * 1000)
						delete cacheOfNewAddresses[address];
					else
						arrCachedNewAddresses.push(address);
				});
				arrRemainingAddresses = _.difference(arrRemainingAddresses, arrCachedNewAddresses);
				if (arrRemainingAddresses.length === 0)
					return handleRows(rows);
				async.each(
					arrRemainingAddresses,
					function (address, cb) {
						network.requestFromLightVendor('light/get_definition', address, function (ws, request, response) {
							if (response && response.error) { 
								console.log('failed to get definition of ' + address + ': ' + response.error);
								return cb();
							}
							if (!response) {
								cacheOfNewAddresses[address] = Date.now();
								console.log('address ' + address + ' not known yet');
								return cb();
```

**File:** aa_addresses.js (L124-126)
```javascript
	readAADefinitions(arrAddresses, function (rows) {
		if (rows.length === 0)
			return handleResult();
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

**File:** network.js (L750-754)
```javascript
	findOutboundPeerOrConnect(exports.light_vendor_url, function(err, ws){
		if (err)
			return responseHandler(null, null, {error: "[connect to light vendor failed]: "+err});
		sendRequest(ws, command, params, false, responseHandler);
	});
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

**File:** validation.js (L839-869)
```javascript
async function validateAATrigger(conn, objUnit, objValidationState, callback) {
	if (objValidationState.last_ball_mci < constants.v4UpgradeMci || objValidationState.bAA || !objValidationState.last_ball_mci) {
		if ("max_aa_responses" in objUnit)
			return callback(`max_aa_responses should not be there`);
		if (objValidationState.bAA || !objValidationState.last_ball_mci)
			return callback();
	}
	if ("content_hash" in objUnit) { // messages already stripped off
		objValidationState.count_primary_aa_triggers = 0;
		return callback();
	}
	let arrOutputAddresses = [];
	for (let m of objUnit.messages) {
		if (m.app === 'payment' && m.payload) {
			for (let o of m.payload.outputs)
				if (!arrOutputAddresses.includes(o.address))
					arrOutputAddresses.push(o.address);
		}
	}

	// Look for AA triggers
	// There might be actually more triggers due to AAs defined between last_ball_mci and our unit, so our validation of tps fee might require a smaller fee than the fee actually charged when the trigger executes
	const rows = await conn.query("SELECT 1 FROM aa_addresses WHERE address IN (?) AND mci<=?", [arrOutputAddresses, objValidationState.last_ball_mci]);
	if (rows.length === 0) {
		if ("max_aa_responses" in objUnit)
			return callback(`no outputs to AAs, max_aa_responses should not be there`);
		return callback();
	}
	objValidationState.count_primary_aa_triggers = rows.length;
	callback();
}
```
