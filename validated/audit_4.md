# Audit Report: Private Payment Loss on Full Nodes Due to Missing Unstable Asset Check

## Summary

Full nodes permanently lose private payments for recently-created assets because they skip stability checks that light nodes perform. When a private payment arrives for an asset whose definition unit has not yet stabilized, full nodes immediately attempt validation, fail due to the temporary instability condition, and permanently delete the payment from the retry queue. Light nodes correctly check for unstable units and queue payments for retry.

## Impact

**Severity**: High  
**Category**: Permanent Freezing of Funds

Recipients operating full nodes permanently lose access to private payments when asset definition units have not yet reached stability (30-60 seconds after creation). The private payment data is irretrievably deleted from the `unhandled_private_payments` queue, preventing the recipient from claiming the on-chain outputs without sender retransmission. While the outputs remain on-chain, the recipient has lost the private data necessary to prove ownership and spend them.

**Affected Parties**: All full node operators receiving private payments for recently-created assets  
**Financial Impact**: Complete loss of individual private payment amounts (unbounded)  
**Recovery**: Requires sender to manually retransmit the private payment after asset stabilizes

## Finding Description

**Location**: `byteball/ocore/private_payment.js`, function `validateAndSavePrivatePaymentChain()`

**Intended Logic**: Both light and full nodes should gracefully handle private payments where the asset definition unit exists but has not yet reached stability, queuing them for retry until validation can succeed.

**Actual Logic**: Full nodes skip the stability check entirely, immediately calling `validateAndSave()`. When the asset definition's MCI exceeds `last_stable_mci`, validation fails with error "asset definition must be before last ball", and the error handler permanently deletes the payment. [1](#0-0) 

**Exploitation Path**:

1. **Preconditions**:
   - Asset definition unit created and broadcast (MCI assigned but not yet stable)
   - Private payment sent for that asset to recipient on full node
   - Payment arrives during 30-60 second stability window

2. **Step 1**: Full node receives private payment
   - If unit known: `handleOnlinePrivatePayment()` calls validation immediately [2](#0-1) 
   - If unit not known: Saved to `unhandled_private_payments`, processed by `handleSavedPrivatePayments()` every 5 seconds [3](#0-2) 

3. **Step 2**: Validation path diverges
   - **Light nodes**: Call `findUnfinishedPastUnitsOfPrivateChains()` which checks `filterNewOrUnstableUnits()` [4](#0-3) [5](#0-4) 
   - If asset definition unstable, returns `ifWaitingForChain()` callback
   - **Full nodes**: Skip check entirely, go straight to `validateAndSave()`

4. **Step 3**: Asset validation fails on full nodes
   - `storage.readAsset()` reads `last_stable_mci` for full nodes [6](#0-5) 
   - Checks if `objAsset.main_chain_index <= last_ball_mci` [7](#0-6) 
   - Returns error "asset definition must be before last ball"

5. **Step 4**: Error handler permanently deletes payment
   - In `handleSavedPrivatePayments()`, `ifError` callback calls `deleteHandledPrivateChain()` [8](#0-7) 
   - Executes DELETE query removing payment from database [9](#0-8) 
   - In contrast, `ifWaitingForChain` callback (light nodes) simply returns without deleting [10](#0-9) 

**Security Property Broken**: Private payment reliability - Valid private payments should eventually be processed regardless of asset definition stability timing.

**Root Cause Analysis**:
The code treats light and full nodes asymmetrically. Light nodes check for unstable units before validation and handle them as a retry-able condition via `ifWaitingForChain()`. Full nodes skip this check, causing validation to fail with a temporary condition (asset not yet stable) that is incorrectly treated as a permanent failure, triggering payment deletion.

## Impact Explanation

**Affected Assets**: All custom assets (divisible and indivisible) received as private payments on full nodes during the stability window

**Damage Severity**:
- **Quantitative**: Any private payment amount for assets created within the last 30-60 seconds. Each affected payment is permanently lost to the recipient.
- **Qualitative**: Recipients lose legitimate payments without notification, assuming they were never sent or failed.

**User Impact**:
- **Who**: Full node operators receiving private payments (not light clients)
- **Conditions**: Asset definition unit hasn't stabilized (30-60 second window after creation)
- **Recovery**: Sender must manually detect failure and retransmit after stabilization

**Systemic Risk**:
- Degrades private payment reliability for new assets
- No error notification to recipient about discarded payments
- Creates trust issues when payments appear to vanish

## Likelihood Explanation

**Attacker Profile**: No attacker required - this is a timing-dependent bug in normal operations

**Preconditions**:
- **Network State**: Normal operation
- **Timing**: Private payment sent/received within 30-60 seconds of asset definition creation
- **Node Type**: Recipient operates full node

**Execution Complexity**: None - occurs automatically under normal usage

**Frequency**: Affects every private payment for newly-created assets sent to full nodes during stability window

**Overall Assessment**: Medium likelihood - dependent on specific timing pattern but occurs in normal protocol usage without malicious actor

## Recommendation

**Immediate Fix**:
Apply the same stability check to full nodes that light nodes use:

```javascript
// File: byteball/ocore/private_payment.js
// Function: validateAndSavePrivatePaymentChain()

// Lines 85-90 should be changed to:
findUnfinishedPastUnitsOfPrivateChains([arrPrivateElements], false, function(arrUnfinishedUnits){
    (arrUnfinishedUnits.length > 0) ? callbacks.ifWaitingForChain() : validateAndSave();
});
```

Remove the `if (conf.bLight)` condition so both node types check stability before validation.

**Additional Measures**:
- Add test case verifying full nodes queue payments when asset definitions are unstable
- Add logging when payments are queued due to unstable assets
- Consider notification mechanism to alert recipients of queued payments

## Proof of Concept

```javascript
// Test: Full nodes should queue private payments for unstable assets
// File: test/private_payment_unstable_asset.test.js

const db = require('../db.js');
const storage = require('../storage.js');
const privatePayment = require('../private_payment.js');
const network = require('../network.js');

describe('Private payment handling for unstable assets', function() {
    it('should queue payment when asset definition is not yet stable', function(done) {
        // 1. Create asset definition unit (not yet stable)
        const assetUnit = createAssetDefinitionUnit();
        storage.saveJoint(assetUnit, function() {
            
            // 2. Create private payment for that asset
            const privateElements = createPrivatePaymentChain(assetUnit.unit);
            
            // 3. Process payment on full node (conf.bLight = false)
            privatePayment.validateAndSavePrivatePaymentChain(privateElements, {
                ifOk: function() {
                    done(new Error('Should not validate before asset is stable'));
                },
                ifError: function(error) {
                    // Current bug: Payment gets deleted here
                    done(new Error('Should not error, should queue: ' + error));
                },
                ifWaitingForChain: function() {
                    // Expected: Payment should be queued
                    // Verify payment remains in unhandled_private_payments
                    db.query(
                        "SELECT * FROM unhandled_private_payments WHERE unit=?",
                        [privateElements[0].unit],
                        function(rows) {
                            if (rows.length === 0) {
                                done(new Error('Payment was not queued'));
                            } else {
                                done(); // Success - payment queued for retry
                            }
                        }
                    );
                }
            });
        });
    });
});
```

**Notes**:
- The vulnerability is specific to full nodes - light nodes are unaffected due to their explicit stability check
- The 30-60 second window refers to typical stability time in Obyte (varies based on network conditions)
- Light nodes use `MAX_INT32` as `last_ball_mci`, effectively disabling the stability check in `storage.readAsset()`
- The bug causes silent data loss - recipients receive no notification that payments were discarded

### Citations

**File:** private_payment.js (L11-20)
```javascript
function findUnfinishedPastUnitsOfPrivateChains(arrChains, includeLatestElement, handleUnits){
	var assocUnits = {};
	arrChains.forEach(function(arrPrivateElements){
		assocUnits[arrPrivateElements[0].payload.asset] = true; // require asset definition
		for (var i = includeLatestElement ? 0 : 1; i<arrPrivateElements.length; i++) // skip latest element
			assocUnits[arrPrivateElements[i].unit] = true;
	});
	var arrUnits = Object.keys(assocUnits);
	storage.filterNewOrUnstableUnits(arrUnits, handleUnits);
}
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

**File:** network.js (L2150-2166)
```javascript
	joint_storage.checkIfNewUnit(unit, {
		ifKnown: function(){
			//assocUnitsInWork[unit] = true;
			privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
				ifOk: function(){
					//delete assocUnitsInWork[unit];
					callbacks.ifAccepted(unit);
					eventBus.emit("new_my_transactions", [unit]);
				},
				ifError: function(error){
					//delete assocUnitsInWork[unit];
					callbacks.ifValidationError(unit, error);
				},
				ifWaitingForChain: function(){
					savePrivatePayment();
				}
			});
```

**File:** network.js (L2228-2234)
```javascript
							ifError: function(error){
								console.log("validation of priv: "+error);
							//	throw Error(error);
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: error});
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								eventBus.emit(key, false);
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

**File:** storage.js (L1888-1895)
```javascript
		if (objAsset.main_chain_index !== null && objAsset.main_chain_index <= last_ball_mci)
			return addAttestorsIfNecessary();
		// && objAsset.main_chain_index !== null below is for bug compatibility with the old version
		if (!bAcceptUnconfirmedAA || constants.bTestnet && last_ball_mci < testnetAssetsDefinedByAAsAreVisibleImmediatelyUpgradeMci && objAsset.main_chain_index !== null)
			return handleAsset("asset definition must be before last ball");
		readAADefinition(conn, objAsset.definer_address, function (arrDefinition) {
			arrDefinition ? addAttestorsIfNecessary() : handleAsset("asset definition must be before last ball (AA)");
		});
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
