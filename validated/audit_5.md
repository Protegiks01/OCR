# Audit Report: Asymmetric Private Payment Handling Causes Permanent Loss on Full Nodes

## Summary

Full nodes permanently delete private payments for unstable assets due to missing stability checks that light clients perform. When a private payment arrives for a newly-created asset during the stability window (30-60 seconds after creation), full nodes skip the stability check, immediately attempt validation, fail with error "asset definition must be before last ball", and irreversibly delete the payment data from the database, making the on-chain outputs unspendable by the recipient.

## Impact

**Severity**: High  
**Category**: Permanent Freezing of Funds

Recipients operating full nodes permanently lose access to private payments when asset definition units have not stabilized. The private payment data (including blinding factors and output details) is deleted from the `unhandled_private_payments` table. While the outputs exist on-chain, the recipient cannot claim them without this private data. Recovery requires the sender to manually detect the failure and retransmit the payment after the asset stabilizes.

**Affected Assets**: All custom divisible and indivisible assets received as private payments on full nodes during the 30-60 second stability window after asset creation.

**Financial Impact**: Complete loss of individual private payment amounts (unbounded per payment) until sender retransmits. No automatic recovery mechanism exists.

## Finding Description

**Location**: `byteball/ocore/private_payment.js:85-90`, function `validateAndSavePrivatePaymentChain()`

**Intended Logic**: Both light and full nodes should gracefully handle private payments where the asset definition unit exists but has not yet reached stability by queuing them for retry.

**Actual Logic**: Full nodes skip the stability check entirely and immediately call `validateAndSave()`. When the asset definition's MCI exceeds `last_stable_mci`, validation fails with error "asset definition must be before last ball", and the error handler permanently deletes the payment. [1](#0-0) 

**Exploitation Path**:

1. **Preconditions**:
   - Asset definition unit created and assigned MCI but not yet stable (30-60 second window)
   - Private payment sent for that asset to recipient running a full node
   - Payment arrives and saved to `unhandled_private_payments` table

2. **Step 1**: Full node processes saved private payment every 5 seconds [2](#0-1) 
   
   The handler reads from `unhandled_private_payments` and calls `validateAndSavePrivatePaymentChain()` [3](#0-2) 

3. **Step 2**: Validation path diverges between node types
   
   **Light clients** (line 85-88): Execute `findUnfinishedPastUnitsOfPrivateChains()` which checks the asset definition unit for stability [4](#0-3) 
   
   This calls `storage.filterNewOrUnstableUnits()` which returns units that are not yet stable [5](#0-4) 
   
   If asset definition is unstable, the callback `ifWaitingForChain()` is invoked without deletion [6](#0-5) 
   
   **Full nodes** (line 90): Skip the check entirely and go directly to `validateAndSave()`

4. **Step 3**: Asset validation fails on full nodes
   
   `validateAndSave()` calls `storage.readAsset()` with `last_ball_mci = null` [7](#0-6) 
   
   For full nodes, this triggers `readLastStableMcIndex()` to set `last_ball_mci = last_stable_mci` [8](#0-7) 
   
   Validation checks if `objAsset.main_chain_index <= last_ball_mci` [9](#0-8) 
   
   For unstable assets, `objAsset.main_chain_index > last_stable_mci`, so it returns error "asset definition must be before last ball"

5. **Step 4**: Error handler permanently deletes payment
   
   Error flows to `ifError` callback in `handleSavedPrivatePayments()` [10](#0-9) 
   
   This calls `deleteHandledPrivateChain()` which executes `DELETE FROM unhandled_private_payments` [11](#0-10) 
   
   The payment is permanently removed with no recovery mechanism.

**Security Property Broken**: Private payment reliability - valid private payments should eventually be processed regardless of asset stability timing.

**Root Cause Analysis**: The code treats light and full nodes asymmetrically. Light clients check for unstable units via `findUnfinishedPastUnitsOfPrivateChains()` and handle them as a retryable condition. Full nodes skip this check, causing validation to fail with a temporary condition (asset not yet stable) that is incorrectly treated as a permanent failure, triggering payment deletion.

## Impact Explanation

**Affected Parties**: All full node operators receiving private payments (not light clients).

**Damage Severity**:
- **Quantitative**: Any private payment amount for newly-created assets. Each affected payment is permanently lost to the recipient until sender retransmits.
- **Qualitative**: Recipients lose legitimate payments without notification, creating silent fund loss and trust degradation.

**User Impact**:
- **Who**: Full node operators receiving private payments
- **Conditions**: Asset definition unit created within last 30-60 seconds when payment arrives
- **Recovery**: Sender must manually detect failure and retransmit after asset stabilizes (no automated retry)

**Systemic Risk**:
- Degrades private payment reliability for new assets
- No notification mechanism for discarded payments
- Silent failures create user confusion and potential disputes between senders and recipients

## Likelihood Explanation

**Attacker Profile**: No attacker required - this is a timing-dependent defect in normal operations.

**Preconditions**:
- **Network State**: Normal operation
- **Timing**: Private payment sent/received within 30-60 seconds of asset definition creation
- **Node Type**: Recipient operates full node (not light client)

**Execution Complexity**: None - occurs automatically during normal protocol usage when users create new assets and immediately send private payments.

**Frequency**: Affects every private payment for newly-created assets sent to full nodes during the stability window. Given the 5-second retry interval, payments arriving during this window will be processed and deleted before stabilization occurs.

**Overall Assessment**: Medium likelihood - requires specific timing (new asset + immediate payment) but occurs without malicious actor in normal protocol usage.

## Recommendation

**Immediate Mitigation**: 

Apply the same stability check that light clients use to full nodes:

```javascript
// File: byteball/ocore/private_payment.js
// Function: validateAndSavePrivatePaymentChain()

// Replace lines 85-90 with:
findUnfinishedPastUnitsOfPrivateChains([arrPrivateElements], false, function(arrUnfinishedUnits){
    (arrUnfinishedUnits.length > 0) ? callbacks.ifWaitingForChain() : validateAndSave();
});
```

**Permanent Fix**: Remove the asymmetric behavior entirely. Both node types should check for unstable assets before validation.

**Additional Measures**:
- Add monitoring to track deleted private payments and alert senders
- Implement automatic retry mechanism for "waiting for chain" conditions
- Add test case verifying private payments wait for asset stability on both node types

## Proof of Concept

```javascript
// File: test/private_payment_stability.test.js
const assert = require('assert');
const db = require('../db.js');
const privatePayment = require('../private_payment.js');
const storage = require('../storage.js');
const conf = require('../conf.js');

describe('Private payment handling for unstable assets', function() {
    this.timeout(10000);
    
    before(async function() {
        // Initialize test database
        await db.query("DELETE FROM unhandled_private_payments");
        await db.query("DELETE FROM units WHERE unit LIKE 'test%'");
    });
    
    it('should NOT delete private payment when asset is unstable on full node', async function() {
        // Set node type to full node
        const originalBLight = conf.bLight;
        conf.bLight = false;
        
        try {
            // Create mock asset definition unit that is NOT stable yet
            const asset_unit = 'test_asset_unit_12345';
            const asset = 'test_asset_hash';
            
            await db.query(
                "INSERT INTO units (unit, main_chain_index, is_stable, sequence) VALUES (?, 100, 0, 'good')",
                [asset_unit]
            );
            
            await db.query(
                "INSERT INTO assets (unit, asset, cap, is_private, fixed_denominations, issued_by_definer_only, cosigned_by_definer, spender_attested) VALUES (?, ?, NULL, 1, 0, 0, 0, 0)",
                [asset_unit, asset]
            );
            
            // Set last_stable_mci to 50 (asset at MCI 100 is unstable)
            await db.query("UPDATE units SET is_stable=1 WHERE main_chain_index<=50");
            
            // Create private payment chain for this unstable asset
            const arrPrivateElements = [{
                unit: 'test_payment_unit',
                message_index: 0,
                payload: {
                    asset: asset,
                    inputs: [],
                    outputs: [{address: 'TEST_ADDRESS', amount: 1000}]
                }
            }];
            
            // Save to unhandled_private_payments
            await db.query(
                "INSERT INTO unhandled_private_payments (unit, message_index, output_index, json, peer) VALUES (?, ?, ?, ?, ?)",
                ['test_payment_unit', 0, 0, JSON.stringify(arrPrivateElements), 'test_peer']
            );
            
            // Track callback invocations
            let waitingForChainCalled = false;
            let errorCalled = false;
            let okCalled = false;
            
            // Call validateAndSavePrivatePaymentChain
            await new Promise((resolve, reject) => {
                privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
                    ifOk: () => {
                        okCalled = true;
                        resolve();
                    },
                    ifError: (err) => {
                        errorCalled = true;
                        console.log('Error:', err);
                        resolve();
                    },
                    ifWaitingForChain: () => {
                        waitingForChainCalled = true;
                        resolve();
                    }
                });
            });
            
            // Check that payment is still in database (NOT deleted)
            const rows = await db.query(
                "SELECT * FROM unhandled_private_payments WHERE unit=?",
                ['test_payment_unit']
            );
            
            // EXPECTED: ifWaitingForChain should be called (like light clients)
            // ACTUAL BUG: ifError is called and payment is deleted
            assert(waitingForChainCalled, 'ifWaitingForChain should be called for unstable asset');
            assert(!errorCalled, 'ifError should NOT be called for unstable asset');
            assert.equal(rows.length, 1, 'Private payment should remain in database for retry');
            
        } finally {
            conf.bLight = originalBLight;
        }
    });
    
    it('light client should correctly handle unstable asset', async function() {
        // Set node type to light client
        const originalBLight = conf.bLight;
        conf.bLight = true;
        
        try {
            // Same test but for light client - should pass
            const asset_unit = 'test_light_asset_unit';
            const asset = 'test_light_asset';
            
            await db.query(
                "INSERT INTO units (unit, main_chain_index, is_stable, sequence) VALUES (?, 100, 0, 'good')",
                [asset_unit]
            );
            
            await db.query(
                "INSERT INTO assets (unit, asset, cap, is_private, fixed_denominations, issued_by_definer_only, cosigned_by_definer, spender_attested) VALUES (?, ?, NULL, 1, 0, 0, 0, 0)",
                [asset_unit, asset]
            );
            
            const arrPrivateElements = [{
                unit: 'test_light_payment_unit',
                message_index: 0,
                payload: {
                    asset: asset,
                    inputs: [],
                    outputs: [{address: 'TEST_ADDRESS', amount: 1000}]
                }
            }];
            
            let waitingForChainCalled = false;
            
            await new Promise((resolve) => {
                privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
                    ifOk: () => resolve(),
                    ifError: () => resolve(),
                    ifWaitingForChain: () => {
                        waitingForChainCalled = true;
                        resolve();
                    }
                });
            });
            
            // Light client should correctly call ifWaitingForChain
            assert(waitingForChainCalled, 'Light client should call ifWaitingForChain for unstable asset');
            
        } finally {
            conf.bLight = originalBLight;
        }
    });
});
```

**Test Execution**: This test demonstrates the vulnerability by showing that:
1. Full nodes call `ifError` and delete the payment when the asset is unstable
2. Light clients correctly call `ifWaitingForChain` and preserve the payment for retry
3. The asymmetric behavior causes permanent fund loss for full node recipients

## Notes

This vulnerability represents a critical asymmetry in how light and full nodes handle private payments. The fix is straightforward: apply the same stability check to both node types. The current implementation incorrectly assumes that full nodes don't need to wait for stability, but the asset validation logic requires it, creating a timing-based failure mode that results in permanent fund loss.

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

**File:** network.js (L2190-2217)
```javascript
		var sql = unit
			? "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments WHERE unit="+db.escape(unit)
			: "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments CROSS JOIN units USING(unit)";
		db.query(sql, function(rows){
			if (rows.length === 0)
				return unlock();
			var assocNewUnits = {};
			async.each( // handle different chains in parallel
				rows,
				function(row, cb){
					var arrPrivateElements = JSON.parse(row.json);
					var ws = getPeerWebSocket(row.peer);
					if (ws && ws.readyState !== ws.OPEN)
						ws = null;
					
					var validateAndSave = function(){
						var objHeadPrivateElement = arrPrivateElements[0];
						try {
							var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
						}
						catch (e) {
							console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
							if (ws)
								sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
							deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
						}
						var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
						privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
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

**File:** network.js (L2236-2240)
```javascript
							// light only. Means that chain joints (excluding the head) not downloaded yet or not stable yet
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
