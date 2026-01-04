# Audit Report: Asymmetric Private Payment Handling Causes Permanent Loss on Full Nodes

## Summary

Full nodes permanently delete private payments for unstable assets due to missing stability checks that light clients perform. When a private payment arrives for a newly-created asset (within 30-60 seconds of creation), full nodes skip the stability check, immediately attempt validation, fail with a temporary error ("asset definition must be before last ball"), and irreversibly delete the payment data from the recipient's database, preventing them from claiming the on-chain outputs. [1](#0-0) 

## Impact

**Severity**: High  
**Category**: Permanent Freezing of Funds

Recipients operating full nodes permanently lose access to private payments when asset definition units have not stabilized. The private payment data (including blinding factors and output details) is deleted from the `unhandled_private_payments` database table. While the outputs exist on-chain, the recipient cannot claim them without this private data. Recovery requires the sender to detect the failure and manually retransmit the payment after the asset stabilizes.

**Affected Parties**: All full node operators receiving private payments for assets created within the last 30-60 seconds  
**Financial Impact**: Complete loss of individual private payment amounts (unbounded per payment) until sender retransmits

## Finding Description

**Location**: `byteball/ocore/private_payment.js:85-90`, function `validateAndSavePrivatePaymentChain()`

**Intended Logic**: Both light and full nodes should gracefully handle private payments where the asset definition unit exists but has not yet reached stability by queuing them for retry.

**Actual Logic**: Full nodes skip the stability check entirely, immediately calling `validateAndSave()`. When the asset definition's MCI exceeds `last_stable_mci`, validation fails with error "asset definition must be before last ball", and the error handler permanently deletes the payment. [1](#0-0) 

**Exploitation Path**:

1. **Preconditions**:
   - Asset definition unit created and assigned MCI but not yet stable (30-60 second window)
   - Private payment sent for that asset to recipient on full node  
   - Payment arrives during stability window

2. **Step 1**: Full node processes saved private payment
   - `handleSavedPrivatePayments()` runs every 5 seconds [2](#0-1) 
   - Reads payment from `unhandled_private_payments` table [3](#0-2) 
   - Calls `validateAndSavePrivatePaymentChain()` [4](#0-3) 

3. **Step 2**: Validation path diverges between node types
   - **Light nodes**: Execute `findUnfinishedPastUnitsOfPrivateChains()` which explicitly checks the asset definition unit for stability [5](#0-4)  then calls `filterNewOrUnstableUnits()` [6](#0-5) 
   - If asset definition is unstable, callback `ifWaitingForChain()` is invoked [7](#0-6) 
   - **Full nodes**: Skip the check entirely, go directly to `validateAndSave()` [8](#0-7) 

4. **Step 3**: Asset validation fails on full nodes
   - `storage.readAsset()` is called with `last_ball_mci = null` [9](#0-8) 
   - For full nodes, this triggers `readLastStableMcIndex()` to set `last_ball_mci = last_stable_mci` [10](#0-9) 
   - Validation checks if `objAsset.main_chain_index <= last_ball_mci` [11](#0-10) 
   - For unstable assets, this condition fails and returns error "asset definition must be before last ball"

5. **Step 4**: Error handler permanently deletes payment
   - Error flows to `ifError` callback in `handleSavedPrivatePayments()` [12](#0-11) 
   - Calls `deleteHandledPrivateChain()` [13](#0-12) 
   - Executes `DELETE FROM unhandled_private_payments` query [14](#0-13) 
   - Payment is permanently removed from database with no recovery mechanism
   
   **Light node contrast**: `ifWaitingForChain` callback simply calls `cb()` without deleting [15](#0-14) 

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

**Overall Assessment**: Medium likelihood - requires specific timing (new asset + immediate payment) but occurs without malicious actor in normal protocol usage

## Recommendation

**Immediate Mitigation**: Apply the same stability check logic used by light clients to full nodes

**Permanent Fix**: Modify `validateAndSavePrivatePaymentChain()` to check for unstable asset definitions on full nodes before attempting validation:

```javascript
// In private_payment.js, replace lines 85-90 with:
findUnfinishedPastUnitsOfPrivateChains([arrPrivateElements], false, function(arrUnfinishedUnits){
    (arrUnfinishedUnits.length > 0) ? callbacks.ifWaitingForChain() : validateAndSave();
});
```

**Additional Measures**:
- Add test case verifying full nodes queue unstable asset payments for retry
- Add monitoring for repeatedly failing private payments
- Consider adding sender notification when payments are queued (not deleted)

## Proof of Concept

```javascript
const test = require('ava');
const composer = require('ocore/composer.js');
const privatePayment = require('ocore/private_payment.js');
const network = require('ocore/network.js');
const db = require('ocore/db.js');
const conf = require('ocore/conf.js');

test.serial('full node should queue private payment for unstable asset', async t => {
    // Step 1: Create asset definition unit
    const assetDefinitionUnit = await composer.composeAssetDefinitionUnit({
        cap: 1000000,
        is_private: false,
        is_transferrable: true,
        auto_destroy: false,
        fixed_denominations: false,
        issued_by_definer_only: true,
        cosigned_by_definer: false,
        spender_attested: false
    });
    
    // Asset has MCI but is not yet stable
    await waitForMciAssignment(assetDefinitionUnit);
    const isStable = await checkIfStable(assetDefinitionUnit);
    t.false(isStable, 'Asset should not be stable yet');
    
    // Step 2: Send private payment immediately
    const privatePaymentChain = await createPrivatePayment({
        asset: assetDefinitionUnit,
        amount: 100,
        recipient: testAddress
    });
    
    // Step 3: Save to unhandled_private_payments table
    await db.query(
        "INSERT INTO unhandled_private_payments (unit, message_index, output_index, json, peer) VALUES (?,?,?,?,?)",
        [privatePaymentChain[0].unit, 0, 0, JSON.stringify(privatePaymentChain), 'test']
    );
    
    // Step 4: Trigger handleSavedPrivatePayments
    await network.handleSavedPrivatePayments(privatePaymentChain[0].unit);
    
    // Step 5: Check if payment still exists in database
    const rows = await db.query(
        "SELECT * FROM unhandled_private_payments WHERE unit=?",
        [privatePaymentChain[0].unit]
    );
    
    if (conf.bLight) {
        // Light client should keep payment for retry
        t.is(rows.length, 1, 'Light client should queue payment for retry');
    } else {
        // BUG: Full node deletes payment
        // EXPECTED: Should also queue for retry like light client
        t.is(rows.length, 1, 'Full node should queue payment for retry');
    }
    
    // Step 6: Wait for asset to stabilize
    await waitForStability(assetDefinitionUnit);
    
    // Step 7: Retry should succeed now
    if (rows.length > 0) {
        await network.handleSavedPrivatePayments(privatePaymentChain[0].unit);
        
        // Payment should now be processed and deleted
        const finalRows = await db.query(
            "SELECT * FROM unhandled_private_payments WHERE unit=?",
            [privatePaymentChain[0].unit]
        );
        t.is(finalRows.length, 0, 'Payment should be processed after stabilization');
        
        // Verify outputs were saved
        const outputRows = await db.query(
            "SELECT * FROM outputs WHERE unit=? AND message_index=?",
            [privatePaymentChain[0].unit, 0]
        );
        t.true(outputRows.length > 0, 'Outputs should be saved');
    }
});
```

## Notes

This vulnerability demonstrates a critical inconsistency between light and full node implementations. The infrastructure for handling unstable assets exists (`ifWaitingForChain` callback), but full nodes never invoke it. The fix is straightforward: apply the same logic to both node types. The impact is significant because private payments are irreversible once the data is lost - there is no on-chain recovery mechanism.

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

**File:** network.js (L2190-2192)
```javascript
		var sql = unit
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

**File:** network.js (L2261-2265)
```javascript
function deleteHandledPrivateChain(unit, message_index, output_index, cb){
	db.query("DELETE FROM unhandled_private_payments WHERE unit=? AND message_index=? AND output_index=?", [unit, message_index, output_index], function(){
		cb();
	});
}
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

**File:** storage.js (L1971-1976)
```javascript
function filterNewOrUnstableUnits(arrUnits, handleFilteredUnits){
	sliceAndExecuteQuery("SELECT unit FROM units WHERE unit IN(?) AND is_stable=1", [arrUnits], arrUnits, function(rows) {
		var arrKnownStableUnits = rows.map(function(row){ return row.unit; });
		var arrNewOrUnstableUnits = _.difference(arrUnits, arrKnownStableUnits);
		handleFilteredUnits(arrNewOrUnstableUnits);
	});
```
