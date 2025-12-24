# Audit Report: Missing Error Check in Divisible Asset Save Callback

## Summary
The `getSavingCallbacks()` function in `divisible_asset.js` contains a critical flaw where the `onDone` callback unconditionally signals success to the caller even when `writer.saveJoint` fails and rolls back the database transaction. This causes wallet state divergence from the blockchain state, potentially leading to double-payments when users retry what they believe are failed transactions.

## Impact
**Severity**: High  
**Category**: Unintended Behavior with Direct Fund Risk

This vulnerability affects all users sending divisible asset payments (both bytes and custom assets). When database save operations fail, the transaction is properly rolled back but the application receives a success signal, causing the wallet to update its state (mark outputs as spent, update balances) while the blockchain has no record of the transaction. Users may then retry the payment, resulting in double-payment and direct fund loss.

## Finding Description

**Location**: `byteball/ocore/divisible_asset.js:381-386`, function `getSavingCallbacks().ifOk()`

**Intended Logic**: When `writer.saveJoint` completes, the callback should check if an error occurred. If `err` is not null (indicating save failure and rollback), the code must call `callbacks.ifError(err)` to notify the caller of the failure. Only on successful save should `callbacks.ifOk()` be invoked.

**Actual Logic**: The `onDone` callback unconditionally calls `callbacks.ifOk()` regardless of whether `err` is null or not.

**Code Evidence**: [1](#0-0) 

The problematic callback at lines 381-386 never checks the `err` parameter before calling `callbacks.ifOk()` at line 386.

For comparison, the correct pattern exists in `composer.js`: [2](#0-1) 

Lines 777-778 properly check `if (err) return callbacks.ifError(err);` before proceeding to `callbacks.ifOk()`.

**Exploitation Path**:

1. **Preconditions**: User initiates a divisible asset payment (particularly private payments where validation can fail).

2. **Step 1**: User calls `composeAndSaveDivisibleAssetPaymentJoint` which invokes `getSavingCallbacks().ifOk()` [3](#0-2) 

3. **Step 2**: During `writer.saveJoint` execution, an error occurs. For private payments, the `preCommitCallback` [4](#0-3)  calls `validateAndSaveDivisiblePrivatePayment` which can fail with database errors, constraint violations, or validation failures [5](#0-4) 

4. **Step 3**: The error propagates to `writer.saveJoint` which rolls back the transaction [6](#0-5)  and calls `onDone(err)` with the error [7](#0-6) 

5. **Step 4**: In `divisible_asset.js`, the `onDone` callback releases locks and unconditionally calls `callbacks.ifOk()` at line 386, signaling SUCCESS despite the database rollback.

6. **Step 5**: The wallet broadcasts the joint and reports success [8](#0-7) . The wallet state shows the payment succeeded (outputs marked as spent, balance reduced), but the local database has no record. If the user retries thinking something went wrong, they may send the payment twice.

**Security Property Broken**: 
- **Transaction Atomicity**: The save operation failed and was rolled back, but application state was updated as if it succeeded
- **Balance Conservation**: Wallet shows reduced balance but blockchain has not recorded the transfer

**Root Cause Analysis**: The error handling pattern was implemented without proper error checking in the callback. The developer likely copied code without including the necessary `if (err)` check that exists in the correct implementation in `composer.js`.

## Impact Explanation

**Affected Assets**: All divisible assets (bytes and custom divisible assets), particularly private payments where `preCommitCallback` can fail.

**Damage Severity**:
- **Quantitative**: Every failed divisible asset payment results in state inconsistency. Users who retry can double-pay arbitrary amounts. Affects all wallet implementations using this code.
- **Qualitative**: Loss of trust in wallet balance reporting and transaction status. Silent failures with false success reporting undermine system reliability.

**User Impact**:
- **Who**: All users sending divisible asset payments. Particularly affects private asset transfers and payments during database stress.
- **Conditions**: Triggered whenever `writer.saveJoint` encounters errors (database failures, validation failures in preCommit, resource exhaustion, constraint violations).
- **Recovery**: Requires manual reconciliation. Users must check blockchain directly to verify actual payment status. Double-payments require customer support intervention.

**Systemic Risk**: 
- Wallet state inconsistencies accumulate across the user base
- Users lose confidence when payments show success but don't appear on chain
- All applications using this library inherit the vulnerability

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user during normal operations (unintentional trigger) or malicious actor who understands the validation rules
- **Resources Required**: Ability to send divisible asset payments
- **Technical Skill**: Low for unintentional trigger (happens naturally during database issues); Medium for intentional exploitation

**Preconditions**:
- **Network State**: Any state; more likely during high load or database stress
- **Attacker State**: Has divisible assets to send
- **Timing**: Can occur anytime; no special timing required

**Execution Complexity**:
- **Transaction Count**: Single transaction
- **Coordination**: None required
- **Detection Risk**: Low - appears as normal failed transaction in logs, but user receives success signal

**Frequency**:
- **Repeatability**: Triggers every time a save error occurs
- **Scale**: Affects every divisible asset payment encountering save errors

**Overall Assessment**: High likelihood - This will trigger naturally during database errors, network issues, or constraint violations. The bug activates automatically when any error condition occurs during the save operation.

## Recommendation

**Immediate Mitigation**:
Add error check before calling success callback in `divisible_asset.js`:

```javascript
function onDone(err){
    console.log("saved unit "+unit+", err="+err, objPrivateElement);
    validation_unlock();
    combined_unlock();
    if (err)
        return callbacks.ifError(err);
    var arrChains = objPrivateElement ? [[objPrivateElement]] : null;
    callbacks.ifOk(objJoint, arrChains, arrChains);
}
```

**Additional Measures**:
- Apply same fix to `indivisible_asset.js` which has a similar issue with only partial mitigation
- Add integration tests that verify error handling when `preCommitCallback` fails
- Add monitoring to detect when save operations fail but success is reported

## Proof of Concept

```javascript
// Test case demonstrating the bug
// File: test/test_divisible_error_handling.js

const divisible_asset = require('../divisible_asset.js');
const db = require('../db.js');

describe('Divisible Asset Error Handling', function() {
    it('should call ifError when saveJoint fails', function(done) {
        let errorCallbackCalled = false;
        let okCallbackCalled = false;
        
        const params = {
            asset: 'test_asset',
            paying_addresses: ['TEST_ADDRESS'],
            fee_paying_addresses: ['TEST_FEE_ADDRESS'],
            change_address: 'TEST_CHANGE',
            to_address: 'TEST_RECIPIENT',
            amount: 1000,
            signer: mockSigner,
            callbacks: {
                ifError: function(err) {
                    errorCallbackCalled = true;
                    console.log('Error callback called correctly:', err);
                },
                ifNotEnoughFunds: function(err) {
                    done(new Error('Should not call ifNotEnoughFunds'));
                },
                ifOk: function(objJoint) {
                    okCallbackCalled = true;
                    console.log('OK callback called (BUG!)');
                }
            }
        };
        
        // Mock database error during save
        const originalQuery = db.query;
        db.query = function(sql, params, callback) {
            if (sql.includes('INSERT INTO outputs')) {
                // Simulate constraint violation or other DB error
                return callback('Database constraint violation');
            }
            return originalQuery.apply(this, arguments);
        };
        
        divisible_asset.composeAndSaveDivisibleAssetPaymentJoint(params);
        
        setTimeout(function() {
            db.query = originalQuery; // Restore
            
            // BUG: okCallbackCalled should be false but will be true
            if (okCallbackCalled && !errorCallbackCalled) {
                console.log('BUG CONFIRMED: ifOk called despite error!');
                done();
            } else if (errorCallbackCalled && !okCallbackCalled) {
                done(new Error('Bug is fixed - error handled correctly'));
            } else {
                done(new Error('Unexpected callback state'));
            }
        }, 2000);
    });
});
```

## Notes

This is a clear implementation bug where error handling was omitted. The comparison with `composer.js` confirms this is not intentional design. While the severity is HIGH rather than CRITICAL (as it requires specific error conditions and user retry for fund loss), it's a serious reliability issue that undermines user trust and can result in direct financial loss through double-payments. The fix is straightforward: add the missing error check before calling the success callback.

### Citations

**File:** divisible_asset.js (L306-307)
```javascript
		ifOk: async function(objJoint, private_payload, composer_unlock){
			var objUnit = objJoint.unit;
```

**File:** divisible_asset.js (L343-360)
```javascript
					if (bPrivate){
						preCommitCallback = function(conn, cb){
							var payload_hash = objectHash.getBase64Hash(private_payload, objUnit.version !== constants.versionWithoutTimestamp);
							var message_index = composer.getMessageIndexByPayloadHash(objUnit, payload_hash);
							objPrivateElement = {
								unit: unit,
								message_index: message_index,
								payload: private_payload
							};
							validateAndSaveDivisiblePrivatePayment(conn, objPrivateElement, {
								ifError: function(err){
									cb(err);
								},
								ifOk: function(){
									cb();
								}
							});
						};
```

**File:** divisible_asset.js (L381-386)
```javascript
								function onDone(err){
									console.log("saved unit "+unit+", err="+err, objPrivateElement);
									validation_unlock();
									combined_unlock();
									var arrChains = objPrivateElement ? [[objPrivateElement]] : null; // only one chain that consists of one element
									callbacks.ifOk(objJoint, arrChains, arrChains);
```

**File:** composer.js (L774-781)
```javascript
								function onDone(err){
									validation_unlock();
									combined_unlock();
									if (err)
										return callbacks.ifError(err);
									console.log("composer saved unit "+unit);
									callbacks.ifOk(objJoint, assocPrivatePayloads);
								}
```

**File:** writer.js (L693-693)
```javascript
							commit_fn(err ? "ROLLBACK" : "COMMIT", async function(){
```

**File:** writer.js (L724-725)
```javascript
								if (onDone)
									onDone(err);
```

**File:** wallet.js (L2494-2497)
```javascript
		ifOk: function(objJoint, arrChainsOfRecipientPrivateElements, arrChainsOfCosignerPrivateElements){
			network.broadcastJoint(objJoint);
			cb(null, objJoint.unit.unit, asset);
		}
```
