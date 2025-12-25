# Audit Report: Missing Device Address Validation Enables Node Crash via Malicious Shared Address Messages

## Summary

The `handleNewSharedAddress()` function in `wallet_defined_by_addresses.js` fails to validate `device_address` fields in shared address signer information, allowing malicious peers to inject empty strings. When signing requests are later processed, the code attempts to route messages to the invalid device address, triggering an uncaught synchronous exception in `sendMessageToDevice()` that crashes the node.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay / Node Crash DoS

Any correspondent peer can crash victim nodes using shared addresses through a two-message attack sequence. Affected nodes require manual restart, and corrupted database entries persist indefinitely, enabling repeated crashes until manual cleanup. This disrupts shared address signing coordination and transaction processing capability.

## Finding Description

**Location**: `byteball/ocore/wallet_defined_by_addresses.js:339-360`, function `handleNewSharedAddress()`

**Intended Logic**: The system should validate all signer information fields, including `device_address`, before storing them in the database. Device addresses must conform to the 33-character format starting with '0'.

**Actual Logic**: The validation loop only checks the `address` field, completely ignoring `device_address` validation: [1](#0-0) 

A proper validation function exists in the codebase: [2](#0-1) 

However, this validation function is never called for `device_address` fields in `handleNewSharedAddress()`.

**Exploitation Path**:

1. **Preconditions**: 
   - Victim node uses shared addresses
   - Attacker establishes correspondent relationship (via pairing)
   - Attacker knows one of victim's payment addresses

2. **Step 1 - Inject Malicious Data**:
   - Attacker sends "new_shared_address" message to victim
   - Message contains signer entry with victim's payment address but empty string `""` for `device_address`
   - Includes decoy entry with victim's actual device address to bypass protective rewrite logic at: [3](#0-2) 

3. **Step 2 - Database Storage**:
   - Validation passes because only `address` field is checked
   - Empty string device_address is stored via: [4](#0-3) 

   - Database schema has NOT NULL constraint but accepts empty strings: [5](#0-4) 

4. **Step 3 - Trigger Crash**:
   - When a "sign" message arrives for this shared address, `findAddress()` queries the database and retrieves the empty device_address: [6](#0-5) 

   - The code forwards the signing request via `ifRemote` callback: [7](#0-6) 

   - `sendMessageToDevice()` throws synchronously when device_address is empty: [8](#0-7) 

   - The event handler chain lacks try-catch blocks: [9](#0-8) [10](#0-9) 

**Security Property Broken**: Node availability and message routing integrity - the system must validate all routing parameters before storage and never attempt to send messages to invalid device addresses.

**Root Cause Analysis**:
- Missing input validation on `device_address` field despite available validation function (`ValidationUtils.isValidDeviceAddress`)
- Protective rewrite logic at lines 305-311 can be bypassed via attacker-controlled decoy entries
- Synchronous exception thrown in callback context without error handling
- No validation during database insertion

## Impact Explanation

**Affected Assets**: Node availability, shared address signing operations, transaction processing capability

**Damage Severity**:
- **Quantitative**: Single malicious message pair crashes any node. Corrupted database entry persists indefinitely requiring manual database cleanup.
- **Qualitative**: Complete denial of service for targeted nodes. Disrupts multi-signature address coordination.

**User Impact**:
- **Who**: Any node accepting peer connections and using shared addresses
- **Conditions**: Node receives malicious "new_shared_address" message followed by any signing request for that address
- **Recovery**: Requires node restart plus manual database query to delete corrupted `shared_address_signing_paths` entries

**Systemic Risk**: If multiple cosigners of a multi-signature address are targeted simultaneously, all signing coordination becomes impossible until all affected nodes are manually cleaned.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any peer on network (requires only correspondent relationship via pairing)
- **Resources Required**: Ability to send P2P messages; knowledge of victim's device address (obtained during pairing) and at least one payment address (potentially observable via shared address usage or prior transactions)
- **Technical Skill**: Low - requires crafting two simple JSON messages

**Preconditions**:
- **Network State**: Normal operation with peer connections enabled
- **Attacker State**: Paired as correspondent with victim node
- **Timing**: No timing constraints - messages can be sent at any time

**Execution Complexity**:
- **Transaction Count**: Two messages (new_shared_address, then sign)
- **Coordination**: None - single attacker fully controls attack sequence
- **Detection Risk**: Low - appears as normal shared address creation until crash occurs

**Frequency**:
- **Repeatability**: Unlimited - corrupted data persists in database
- **Scale**: Can target multiple nodes simultaneously with identical attack

**Overall Assessment**: High likelihood - trivially exploitable with no economic barrier and minimal technical requirements.

## Recommendation

**Immediate Mitigation**:
Add device_address validation in `handleNewSharedAddress()`:

```javascript
// In wallet_defined_by_addresses.js, function handleNewSharedAddress()
// After line 349, add:
if (signerInfo.device_address && !ValidationUtils.isValidDeviceAddress(signerInfo.device_address))
    return callbacks.ifError("invalid device address: "+signerInfo.device_address);
```

**Permanent Fix**:
1. Add comprehensive validation of all signerInfo fields
2. Add error handling around `sendMessageToDevice()` calls to prevent uncaught exceptions
3. Add database constraint validation to prevent empty device addresses

**Additional Measures**:
- Add test case verifying device_address validation
- Add monitoring for invalid device_address entries in database
- Consider adding CHECK constraint in database schema: `CHECK(length(device_address) = 33 AND substr(device_address, 1, 1) = '0')`

## Proof of Concept

```javascript
const test = require('ava');
const device = require('../device.js');
const walletDefinedByAddresses = require('../wallet_defined_by_addresses.js');
const db = require('../db.js');

test('handleNewSharedAddress should reject empty device_address', async t => {
    // Setup: Create malicious shared address message with empty device_address
    const maliciousBody = {
        address: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        definition: ["sig", {pubkey: "A".repeat(44)}],
        signers: {
            "r.0": {
                address: "VALID_VICTIM_ADDRESS_HERE_32CHAR",
                device_address: "",  // Empty device_address
                member_signing_path: "r"
            },
            "r.1": {
                address: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                device_address: "0" + "C".repeat(32),  // Decoy with valid device address
                member_signing_path: "r"
            }
        }
    };
    
    let errorReceived = false;
    let errorMessage = "";
    
    // Attempt to handle the malicious message
    walletDefinedByAddresses.handleNewSharedAddress(maliciousBody, {
        ifError: function(err) {
            errorReceived = true;
            errorMessage = err;
        },
        ifOk: function() {
            // If this succeeds, the vulnerability exists
            // Later, calling device.sendMessageToDevice("", "sign", {}) would crash
            t.fail("Empty device_address was accepted - vulnerability confirmed");
        }
    });
    
    // The test expects an error to be received
    // If no error, the vulnerability exists
    t.true(errorReceived, "Should reject empty device_address");
    t.true(errorMessage.includes("device"), "Error message should mention device address");
});

test('sendMessageToDevice throws on empty device_address', t => {
    // Verify that sendMessageToDevice throws synchronously on empty string
    t.throws(() => {
        device.sendMessageToDevice("", "sign", {});
    }, {
        message: /empty device address/i
    });
});
```

## Notes

This vulnerability affects nodes using the shared address feature (multi-signature addresses). The attack requires the attacker to:
1. Be paired as a correspondent with the victim
2. Know at least one of the victim's payment addresses that exists in their `my_addresses` table

The protective rewrite logic at lines 305-311 is designed to automatically correct device addresses for the user's own payment addresses, but this protection is bypassable when the attacker includes a decoy entry with the victim's device address, causing `bHasMyDeviceAddress` to be true and skipping the rewrite.

The vulnerability demonstrates a common pattern: validation function exists but is not called in the critical code path. The fix is straightforward: add the validation check that already exists elsewhere in the codebase.

### Citations

**File:** wallet_defined_by_addresses.js (L249-251)
```javascript
					"INSERT "+db.getIgnore()+" INTO shared_address_signing_paths \n\
					(shared_address, address, signing_path, member_signing_path, device_address) VALUES (?,?,?,?,?)", 
					[address, signerInfo.address, signing_path, signerInfo.member_signing_path, signerInfo.device_address]);
```

**File:** wallet_defined_by_addresses.js (L305-311)
```javascript
			if (!bHasMyDeviceAddress){
				for (var signing_path in assocSignersByPath){
					var signerInfo = assocSignersByPath[signing_path];
					if (signerInfo.address && arrMyMemberAddresses.indexOf(signerInfo.address) >= 0)
						signerInfo.device_address = device.getMyDeviceAddress();
				}
			}
```

**File:** wallet_defined_by_addresses.js (L346-350)
```javascript
	for (var signing_path in body.signers){
		var signerInfo = body.signers[signing_path];
		if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
			return callbacks.ifError("invalid member address: "+signerInfo.address);
	}
```

**File:** validation_utils.js (L64-66)
```javascript
function isValidDeviceAddress(address){
	return ( isStringOfLength(address, 33) && address[0] === '0' && isValidAddress(address.substr(1)) );
}
```

**File:** initial-db/byteball-sqlite.sql (L633-633)
```sql
	device_address CHAR(33) NOT NULL, -- where this signing key lives or is reachable through
```

**File:** wallet.js (L62-67)
```javascript
	mutex.lock(["from_hub"], function(unlock){
		var oldcb = callbacks;
		callbacks = {
			ifOk: function(){oldcb.ifOk(); unlock();},
			ifError: function(err){oldcb.ifError(err); unlock();}
		};
```

**File:** wallet.js (L337-353)
```javascript
					ifRemote: function(device_address){
						if (device_address === from_address){
							callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
							throw Error("looping signing request for address "+body.address+", path "+body.signing_path);
						}
						try {
							var text_to_sign = objectHash.getUnitHashToSign(body.unsigned_unit).toString("base64");
						}
						catch (e) {
							return callbacks.ifError("unit hash failed: " + e.toString());
						}
						// I'm a proxy, wait for response from the actual signer and forward to the requestor
						eventBus.once("signature-"+device_address+"-"+body.address+"-"+body.signing_path+"-"+text_to_sign, function(sig){
							sendSignature(from_address, text_to_sign, sig, body.signing_path, body.address);
						});
						// forward the offer to the actual signer
						device.sendMessageToDevice(device_address, subject, body);
```

**File:** wallet.js (L1055-1062)
```javascript
				"SELECT address, device_address, signing_path FROM shared_address_signing_paths \n\
				WHERE shared_address=? AND signing_path=SUBSTR(?, 1, LENGTH(signing_path))", 
				[address, signing_path],
				function(sa_rows){
					if (sa_rows.length > 1)
						throw Error("more than 1 member address found for shared address "+address+" and signing path "+signing_path);
					if (sa_rows.length === 1) {
						var objSharedAddress = sa_rows[0];
```

**File:** device.js (L176-184)
```javascript
			var handleMessage = function(bIndirectCorrespondent){
				eventBus.emit("handle_message_from_hub", ws, json, objDeviceMessage.pubkey, bIndirectCorrespondent, {
					ifError: function(err){
						respondWithError(err);
					},
					ifOk: function(){
						network.sendJustsaying(ws, 'hub/delete', message_hash);
					}
				});
```

**File:** device.js (L702-704)
```javascript
function sendMessageToDevice(device_address, subject, body, callbacks, conn){
	if (!device_address)
		throw Error("empty device address");
```
