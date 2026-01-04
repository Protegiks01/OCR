# Audit Report: Private Payment Loss on Full Nodes Due to Missing Unstable Asset Check

## Summary

Full nodes permanently lose private payments for recently-created assets due to missing stability checks that light clients perform. When a private payment arrives for an unstable asset, full nodes immediately attempt validation, fail with a temporary error, and irreversibly delete the payment from the retry queue. Light clients correctly detect unstable assets and queue for retry. [1](#0-0) 

## Impact

**Severity**: High  
**Category**: Permanent Freezing of Funds

Recipients operating full nodes permanently lose access to private payments when asset definition units have not yet stabilized (30-60 seconds after creation). The private payment data is irretrievably deleted from the `unhandled_private_payments` database table, preventing the recipient from claiming the on-chain outputs. While outputs remain on-chain, the recipient has lost the private keys/data necessary to prove ownership. Recovery requires the sender to manually detect the failure and retransmit after the asset stabilizes.

**Affected Parties**: All full node operators receiving private payments for assets created within the last 30-60 seconds  
**Financial Impact**: Complete loss of individual private payment amounts (unbounded per payment)

## Finding Description

**Location**: `byteball/ocore/private_payment.js:85-90`, function `validateAndSavePrivatePaymentChain()`

**Intended Logic**: Both light and full nodes should gracefully handle private payments where the asset definition unit exists but has not yet reached stability by queuing them for retry.

**Actual Logic**: Full nodes skip the stability check entirely, immediately calling `validateAndSave()`. When the asset definition's MCI exceeds `last_stable_mci`, validation fails with error "asset definition must be before last ball", and the error handler permanently deletes the payment.

**Exploitation Path**:

1. **Preconditions**:
   - Asset definition unit is created and assigned an MCI but not yet stable
   - Private payment is sent for that asset to recipient on full node  
   - Payment arrives during 30-60 second stability window

2. **Step 1**: Full node processes saved private payment
   - `handleSavedPrivatePayments()` runs every 5 seconds [2](#0-1) 
   - Reads payment from `unhandled_private_payments` table [3](#0-2) 
   - Calls `validateAndSavePrivatePaymentChain()` [4](#0-3) 

3. **Step 2**: Validation path diverges between node types
   - **Light nodes**: Execute `findUnfinishedPastUnitsOfPrivateChains()` which calls `filterNewOrUnstableUnits()` [5](#0-4) 
   - If asset definition is unstable, callback `ifWaitingForChain()` is invoked [5](#0-4) 
   - **Full nodes**: Skip the check entirely, go directly to `validateAndSave()` [6](#0-5) 

4. **Step 3**: Asset validation fails on full nodes
   - `storage.readAsset()` is called with `last_ball_mci = null` [7](#0-6) 
   - For full nodes, this triggers `readLastStableMcIndex()` to set `last_ball_mci = last_stable_mci` [8](#0-7) 
   - Validation checks if `objAsset.main_chain_index <= last_ball_mci` [9](#0-8) 
   - For unstable assets, this condition fails and returns error "asset definition must be before last ball"

5. **Step 4**: Error handler permanently deletes payment
   - Error flows to `ifError` callback in `handleSavedPrivatePayments()` [10](#0-9) 
   - Calls `deleteHandledPrivateChain()` [11](#0-10) 
   - Executes `DELETE FROM unhandled_private_payments` query [12](#0-11) 
   - Payment is permanently removed from database with no recovery mechanism
   
   **Light node contrast**: `ifWaitingForChain` callback simply calls `cb()` without deleting [13](#0-12) 

**Security Property Broken**: Private payment reliability - valid private payments should eventually be processed regardless of asset stability timing.

**Root Cause Analysis**: The code treats light and full nodes asymmetrically. Light nodes check for unstable units via `findUnfinishedPastUnitsOfPrivateChains()` and handle them as a retryable condition. Full nodes skip this check, causing validation to fail with a temporary condition (asset not yet stable) that is incorrectly treated as a permanent failure, triggering payment deletion.

## Impact Explanation

**Affected Assets**: All custom divisible and indivisible assets received as private payments on full nodes during the 30-60 second stability window after asset creation.

**Damage Severity**:
- **Quantitative**: Any private payment amount for newly-created assets. Each affected payment is permanently lost to the recipient until sender retransmits.
- **Qualitative**: Recipients lose legitimate payments without notification, creating loss of funds and trust degradation.

**User Impact**:
- **Who**: Full node operators receiving private payments (not light clients)
- **Conditions**: Asset definition unit created within last 30-60 seconds when payment arrives
- **Recovery**: Sender must manually detect failure and retransmit after asset stabilizes

**Systemic Risk**:
- Degrades private payment reliability for new assets
- No notification mechanism for discarded payments
- Silent failures create user confusion and potential disputes

## Likelihood Explanation

**Attacker Profile**: No attacker required - this is a timing-dependent defect in normal operations

**Preconditions**:
- **Network State**: Normal operation
- **Timing**: Private payment sent/received within 30-60 seconds of asset definition creation  
- **Node Type**: Recipient operates full node (not light client)

**Execution Complexity**: None - occurs automatically during normal protocol usage

**Frequency**: Affects every private payment for newly-created assets sent to full nodes during the stability window. Given the 5-second retry interval, payments arriving during this window will be processed and deleted before stabilization.

**Overall Assessment**: Medium likelihood - requires specific timing (new asset + immediate payment) but occurs without malicious actor in normal protocol usage.

## Recommendation

**Immediate Mitigation**: Apply the same stability check used by light clients to full nodes in `validateAndSavePrivatePaymentChain()`:

Modify `private_payment.js:85-90` to check for unstable units on both light and full nodes before validation.

**Permanent Fix**: Refactor to unified handling:
- Call `findUnfinishedPastUnitsOfPrivateChains()` for both node types
- Only invoke `ifWaitingForChain()` (queue for retry) when assets are unstable
- Only invoke `validateAndSave()` when all referenced units are stable

**Additional Measures**:
- Add integration test verifying private payments for unstable assets queue correctly on full nodes
- Add monitoring to detect payments stuck in retry queue  
- Document retry behavior in private payment specification

## Notes

This vulnerability demonstrates a critical asymmetry in how light and full nodes process private payments. The light client code path correctly identifies unstable assets as a retryable condition via `filterNewOrUnstableUnits()` [14](#0-13) , which queries for units with `is_stable=0`. Full nodes skip this check, immediately attempting validation that will fail temporarily but trigger permanent deletion.

The fix is straightforward: ensure both node types execute the stability check before attempting validation. This aligns with Obyte's design principle that units should only be processed after they reach stability to ensure consensus consistency.

### Citations

**File:** private_payment.js (L36-36)
```javascript
		storage.readAsset(db, asset, null, function(err, objAsset){
```

**File:** private_payment.js (L85-90)
```javascript
	if (conf.bLight)
		findUnfinishedPastUnitsOfPrivateChains([arrPrivateElements], false, function(arrUnfinishedUnits){
			(arrUnfinishedUnits.length > 0) ? callbacks.ifWaitingForChain() : validateAndSave();
		});
	else
		validateAndSave();
```

**File:** network.js (L2191-2192)
```javascript
			? "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments WHERE unit="+db.escape(unit)
			: "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments CROSS JOIN units USING(unit)";
```

**File:** network.js (L2217-2217)
```javascript
						privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
```

**File:** network.js (L2228-2235)
```javascript
							ifError: function(error){
								console.log("validation of priv: "+error);
							//	throw Error(error);
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: error});
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								eventBus.emit(key, false);
							},
```

**File:** network.js (L2237-2240)
```javascript
							ifWaitingForChain: function(){
								console.log('waiting for chain: unit '+row.unit+', message '+row.message_index+' output '+row.output_index);
								cb();
							}
```

**File:** network.js (L2261-2264)
```javascript
function deleteHandledPrivateChain(unit, message_index, output_index, cb){
	db.query("DELETE FROM unhandled_private_payments WHERE unit=? AND message_index=? AND output_index=?", [unit, message_index, output_index], function(){
		cb();
	});
```

**File:** network.js (L4069-4069)
```javascript
	setInterval(handleSavedPrivatePayments, 5*1000);
```

**File:** storage.js (L1844-1850)
```javascript
	if (last_ball_mci === null){
		if (conf.bLight)
			last_ball_mci = MAX_INT32;
		else
			return readLastStableMcIndex(conn, function(last_stable_mci){
				readAsset(conn, asset, last_stable_mci, bAcceptUnconfirmedAA, handleAsset);
			});
```

**File:** storage.js (L1888-1892)
```javascript
		if (objAsset.main_chain_index !== null && objAsset.main_chain_index <= last_ball_mci)
			return addAttestorsIfNecessary();
		// && objAsset.main_chain_index !== null below is for bug compatibility with the old version
		if (!bAcceptUnconfirmedAA || constants.bTestnet && last_ball_mci < testnetAssetsDefinedByAAsAreVisibleImmediatelyUpgradeMci && objAsset.main_chain_index !== null)
			return handleAsset("asset definition must be before last ball");
```

**File:** storage.js (L1971-1977)
```javascript
function filterNewOrUnstableUnits(arrUnits, handleFilteredUnits){
	sliceAndExecuteQuery("SELECT unit FROM units WHERE unit IN(?) AND is_stable=1", [arrUnits], arrUnits, function(rows) {
		var arrKnownStableUnits = rows.map(function(row){ return row.unit; });
		var arrNewOrUnstableUnits = _.difference(arrUnits, arrKnownStableUnits);
		handleFilteredUnits(arrNewOrUnstableUnits);
	});
}
```
