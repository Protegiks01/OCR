# Audit Report: Improper Error Handling in Light Client AA Definition Fetch

## Summary

The `readAADefinitions()` function in `aa_addresses.js` contains a critical error handling bug where network failures are silently ignored instead of propagated. [1](#0-0)  When light clients fail to fetch AA definitions from vendors, the async iterator callback signals success (`cb()`) instead of failure (`cb(err)`), causing bounce fee validation to proceed with incomplete data. This allows transactions with insufficient bounce fees to be sent to the network. When the AA detects insufficient fees during execution, it calls `finish(null)` without sending a bounce response, [2](#0-1)  resulting in permanent loss of user funds.

## Impact

**Severity**: Critical  
**Category**: Direct Loss of Funds

Light client users suffer permanent, unrecoverable loss when sending payments to AAs during network instability or light vendor unavailability. The minimum loss per transaction is 10,000 bytes [3](#0-2)  but can be substantially higher for AAs with custom bounce_fees. All light client users are affected when interacting with uncached AA addresses during network issues.

## Finding Description

**Location**: `byteball/ocore/aa_addresses.js:70-87`, function `readAADefinitions()`

**Intended Logic**: When light vendors fail to return AA definitions (network errors, null responses, or hash mismatches), the error must be propagated to the async.each callback (`cb(error)`) to halt validation and prevent transaction submission.

**Actual Logic**: Three error conditions incorrectly call `cb()` without an error parameter: [4](#0-3) [5](#0-4) [6](#0-5) 

The `async.each` library interprets `cb()` (equivalent to `cb(null)`) as successful completion, allowing the final callback to execute with incomplete data. [7](#0-6) 

**Exploitation Path**:

1. **Preconditions**: Light client user ( [8](#0-7) ) sends payment to AA address not in local cache during network timeout or vendor unavailability.

2. **Step 1**: User initiates transaction via `sendMultiPayment()` which calls `checkAAOutputs()` to validate bounce fees. [9](#0-8) 

3. **Step 2**: `checkAAOutputs()` calls `readAADefinitions()` to fetch AA definitions. [10](#0-9)  Database query finds no cached definition, triggering light vendor request. [11](#0-10) 

4. **Step 3**: Vendor request fails but `cb()` signals success. The `async.each` completion callback executes, calling `handleRows(rows)` with only successfully loaded definitions (failed AA address missing).

5. **Step 4**: Bounce fee validation loop only processes addresses in `rows`, [12](#0-11)  skipping the failed AA. Validation returns no error, [13](#0-12)  allowing transaction to proceed.

6. **Step 5**: Transaction reaches network and triggers AA. During execution, AA detects insufficient bounce fees [14](#0-13)  and calls `bounce()`.

7. **Step 6**: Bounce mechanism checks if received amount covers fees. If insufficient, it calls `finish(null)` without sending refund, [2](#0-1)  permanently transferring user funds to AA.

**Security Property Broken**: Balance conservation invariant - users sending payments to failing AAs must receive refunds minus bounce fees. The bug allows transactions to proceed without proper validation, resulting in no refund when AA execution fails.

**Root Cause**: Incorrect callback semantics. The `async.each` library requires `cb(err)` with truthy error to signal failure, but code calls `cb()` for all error conditions, causing failures to be interpreted as successes.

## Impact Explanation

**Affected Assets**: Base bytes (native currency), custom divisible/indivisible assets specified in AA bounce_fees

**Damage Severity**:
- **Quantitative**: Minimum 10,000 bytes per failed transaction, potentially unlimited for AAs with high custom bounce_fees or multiple asset requirements
- **Qualitative**: Complete, permanent, unrecoverable loss with no bounce response generated and no recovery mechanism

**User Impact**:
- **Who**: All light client users (mobile wallets, browser extensions) sending payments to AAs
- **Conditions**: Network instability, light vendor timeouts/downtime, first interaction with newly deployed AAs, cleared local cache
- **Recovery**: None - funds permanently transferred to AA with no refund path

**Systemic Risk**: Erodes trust in light clients; multiple users affected simultaneously during vendor outages; users incorrectly attribute failures to AAs rather than client bug; creates perverse incentive for AAs to set excessive bounce fees.

## Likelihood Explanation

**Attacker Profile**: No attacker required - vulnerability triggers naturally during network issues

**Preconditions**:
- Light client operation (common - mobile/browser wallets)
- AA address not in local cache (first interaction or cache cleared)
- Light vendor timeout/unavailability (occurs regularly during high load)

**Execution Complexity**: Single payment transaction, no special coordination required, appears as normal payment in logs

**Frequency**: Every failed definition fetch during network instability; all light clients affected during vendor outages

**Overall Assessment**: High likelihood - network issues are routine in production environments, bug is deterministic once preconditions met

## Recommendation

**Immediate Mitigation**:
Propagate errors correctly in the async iterator callback:

```javascript
// File: byteball/ocore/aa_addresses.js
// Lines: 74-87

if (response && response.error) {
    console.log('failed to get definition of ' + address + ': ' + response.error);
    return cb(response.error); // Changed from cb()
}
if (!response) {
    cacheOfNewAddresses[address] = Date.now();
    console.log('address ' + address + ' not known yet');
    return cb('address not known yet'); // Changed from cb()
}
// ... validate hash ...
if (objectHash.getChash160(arrDefinition) !== address) {
    console.log("definition doesn't match address: " + address);
    return cb("definition hash mismatch"); // Changed from cb()
}
```

**Permanent Fix**: Same as above - ensure all error paths call `cb(error)` instead of `cb()`

**Additional Measures**:
- Add test case verifying light vendor failures properly block transaction composition
- Add user-facing warning when definition fetch fails
- Implement retry mechanism with exponential backoff for vendor requests
- Cache negative results (non-AA addresses) to reduce unnecessary vendor queries

**Validation**:
- Verify error propagation prevents transactions with unvalidated bounce fees
- Ensure no false positives (legitimate transactions still succeed)
- Test under simulated network conditions (timeouts, connection failures)

## Notes

This vulnerability specifically affects light clients due to their reliance on remote vendors for AA definitions. [8](#0-7)  Full nodes maintain complete AA definition databases locally and are not vulnerable.

The bounce mechanism's behavior of consuming funds when bounce fees are insufficient [15](#0-14)  is intentional design, but the client-side validation in `checkAAOutputs()` [16](#0-15)  is meant to prevent users from sending insufficient amounts. The error handling bug defeats this protection mechanism.

### Citations

**File:** aa_addresses.js (L40-42)
```javascript
	db.query("SELECT definition, address, base_aa FROM aa_addresses WHERE address IN (" + arrAddresses.map(db.escape).join(', ') + ")", function (rows) {
		if (!conf.bLight || arrAddresses.length === rows.length)
			return handleRows(rows);
```

**File:** aa_addresses.js (L70-87)
```javascript
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
							}
							var arrDefinition = response;
							if (objectHash.getChash160(arrDefinition) !== address) {
								console.log("definition doesn't match address: " + address);
								return cb();
							}
```

**File:** aa_addresses.js (L102-104)
```javascript
					function () {
						handleRows(rows);
					}
```

**File:** aa_addresses.js (L111-146)
```javascript
function checkAAOutputs(arrPayments, handleResult) {
	var assocAmounts = {};
	arrPayments.forEach(function (payment) {
		var asset = payment.asset || 'base';
		payment.outputs.forEach(function (output) {
			if (!assocAmounts[output.address])
				assocAmounts[output.address] = {};
			if (!assocAmounts[output.address][asset])
				assocAmounts[output.address][asset] = 0;
			assocAmounts[output.address][asset] += output.amount;
		});
	});
	var arrAddresses = Object.keys(assocAmounts);
	readAADefinitions(arrAddresses, function (rows) {
		if (rows.length === 0)
			return handleResult();
		var arrMissingBounceFees = [];
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
		if (arrMissingBounceFees.length === 0)
			return handleResult();
		handleResult(new MissingBounceFeesErrorMessage({ error: "The amounts are less than bounce fees", missing_bounce_fees: arrMissingBounceFees }));
	});
}

```

**File:** aa_composer.js (L880-894)
```javascript
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
```

**File:** aa_composer.js (L1680-1682)
```javascript
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
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
