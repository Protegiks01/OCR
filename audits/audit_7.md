# Audit Report: Unvalidated Device Address in Shared Address Messages Enables Node Crash

## Summary

The `handleNewSharedAddress()` function in `wallet_defined_by_addresses.js` fails to validate `device_address` fields in received shared address signer information, allowing malicious peers to inject empty strings or invalid device addresses. When signing requests are later processed for these addresses, the code attempts to route messages to the invalid device address, triggering an uncaught synchronous exception in `sendMessageToDevice()` that crashes the node.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay / Node Crash DoS

Any untrusted peer can crash victim nodes using shared addresses through a two-message sequence. Affected nodes require manual restart, and corrupted data persists in the database allowing repeated crashes. This disrupts shared address operations and transaction processing capability for targeted nodes.

## Finding Description

**Location**: `byteball/ocore/wallet_defined_by_addresses.js:339-360`, function `handleNewSharedAddress()`

**Intended Logic**: When receiving a "new_shared_address" message from a peer, the system should validate all signer information including device addresses before storing them in the database.

**Actual Logic**: The validation loop only checks the `address` field but completely ignores `device_address` validation: [1](#0-0) 

A proper validation function exists in the codebase: [2](#0-1) 

But it is never used to validate device_address fields in handleNewSharedAddress.

**Exploitation Path**:

1. **Preconditions**: 
   - Victim node accepts peer connections and uses shared addresses
   - Attacker knows victim's device address and payment address (publicly observable)

2. **Step 1 - Inject Malicious Data**: 
   - Attacker sends "new_shared_address" message to victim node
   - Message contains signer entry with victim's payment address but empty string `""` for device_address
   - Includes decoy entry with victim's device address to bypass protective rewrite logic: [3](#0-2) 

3. **Step 2 - Database Storage**: 
   - Validation passes because only address field is checked
   - Empty string device_address is stored in database (passes NOT NULL constraint): [4](#0-3) 

   Database schema has NOT NULL constraint but accepts empty strings: [5](#0-4) 

4. **Step 3 - Trigger Crash**:
   - When a "sign" message arrives for this shared address, `findAddress()` queries the database and retrieves the empty device_address: [6](#0-5) 

   - The code forwards the signing request via `ifRemote` callback: [7](#0-6) 

   - `sendMessageToDevice()` throws synchronously when device_address is empty: [8](#0-7) 

   - No try-catch exists in the message handler, causing process crash: [9](#0-8) [10](#0-9) 

**Security Property Broken**: Node availability and message routing integrity - the system should never attempt to send messages to invalid device addresses.

**Root Cause Analysis**:
- Missing input validation on device_address field despite available validation function
- Bypassable protective rewrite logic through attacker-controlled decoy entries
- Synchronous exception in async callback context with no error handling

## Impact Explanation

**Affected Assets**: Node availability, shared address operations, transaction processing capability

**Damage Severity**:
- **Quantitative**: Single malicious message pair crashes any node. Corrupted database entry persists indefinitely requiring manual cleanup.
- **Qualitative**: Complete denial of service for targeted nodes. Disrupts multi-signature coordination.

**User Impact**:
- **Who**: Any node accepting peer connections and using shared addresses
- **Conditions**: Node receives malicious "new_shared_address" message; later receives signing request for corrupted path
- **Recovery**: Requires node restart plus manual database cleanup

**Systemic Risk**: If multiple nodes in a multi-signature configuration are targeted, coordination becomes impossible.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any untrusted peer on network
- **Resources Required**: Ability to send P2P messages; knowledge of victim's device and payment addresses (publicly observable)
- **Technical Skill**: Low - requires crafting two simple JSON messages

**Preconditions**:
- **Network State**: Normal operation with peer connections enabled
- **Attacker State**: Connected as correspondent
- **Timing**: No timing constraints

**Execution Complexity**:
- **Transaction Count**: Two messages (new_shared_address, then sign)
- **Coordination**: None - single attacker controls entire sequence
- **Detection Risk**: Low - appears as normal shared address creation until crash

**Frequency**:
- **Repeatability**: Unlimited - corrupted data persists
- **Scale**: Can target multiple nodes simultaneously

**Overall Assessment**: High likelihood - trivially exploitable with no economic barrier.

## Recommendation

**Immediate Mitigation**:
Add device_address validation in `handleNewSharedAddress()`:

```javascript
for (var signing_path in body.signers){
    var signerInfo = body.signers[signing_path];
    if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
        return callbacks.ifError("invalid member address: "+signerInfo.address);
    // ADD THIS:
    if (signerInfo.device_address && !ValidationUtils.isValidDeviceAddress(signerInfo.device_address))
        return callbacks.ifError("invalid device address: "+signerInfo.device_address);
}
```

**Additional Measures**:
- Add database CHECK constraint: `CHECK(LENGTH(device_address) = 33 AND device_address LIKE '0%')`
- Add test case verifying invalid device_addresses are rejected
- Add try-catch in message handler for robustness

## Proof of Concept

```javascript
// Test: test/shared_address_device_validation.test.js
const device = require('../device.js');
const walletDefinedByAddresses = require('../wallet_defined_by_addresses.js');

describe('Shared Address Device Validation', function() {
    it('should reject empty device_address in new_shared_address message', function(done) {
        const maliciousMessage = {
            address: 'VALID_SHARED_ADDRESS_HASH_HERE_32CH',
            definition: ['sig', {pubkey: 'validpubkey'}],
            signers: {
                'r.0': {
                    address: 'VICTIM_PAYMENT_ADDRESS_32_CHARS',
                    device_address: '', // EMPTY STRING
                    member_signing_path: 'r'
                }
            }
        };
        
        walletDefinedByAddresses.handleNewSharedAddress(maliciousMessage, {
            ifError: function(err) {
                assert(err.includes('device'), 'Should reject empty device_address');
                done();
            },
            ifOk: function() {
                done(new Error('Should not accept empty device_address'));
            }
        });
    });
});
```

## Notes

The vulnerability exists because `ValidationUtils.isValidDeviceAddress()` is defined and exported but never used to validate device_address fields in incoming shared address messages. The attack works with empty strings `""` rather than null values, as empty strings pass the database NOT NULL constraint but are still falsy in JavaScript, triggering the crash condition.

### Citations

**File:** wallet_defined_by_addresses.js (L246-252)
```javascript
			for (var signing_path in assocSignersByPath){
				var signerInfo = assocSignersByPath[signing_path];
				db.addQuery(arrQueries, 
					"INSERT "+db.getIgnore()+" INTO shared_address_signing_paths \n\
					(shared_address, address, signing_path, member_signing_path, device_address) VALUES (?,?,?,?,?)", 
					[address, signerInfo.address, signing_path, signerInfo.member_signing_path, signerInfo.device_address]);
			}
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

**File:** initial-db/byteball-sqlite.sql (L628-639)
```sql
CREATE TABLE shared_address_signing_paths (
	shared_address CHAR(32) NOT NULL,
	signing_path VARCHAR(255) NULL, -- full path to signing key which is a member of the member address
	address CHAR(32) NOT NULL, -- member address
	member_signing_path VARCHAR(255) NULL, -- path to signing key from root of the member address
	device_address CHAR(33) NOT NULL, -- where this signing key lives or is reachable through
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (shared_address, signing_path),
	FOREIGN KEY (shared_address) REFERENCES shared_addresses(shared_address)
	-- own address is not present in correspondents
--    FOREIGN KEY byDeviceAddress(device_address) REFERENCES correspondent_devices(device_address)
);
```

**File:** wallet.js (L60-77)
```javascript
function handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, callbacks){
	// serialize all messages from hub
	mutex.lock(["from_hub"], function(unlock){
		var oldcb = callbacks;
		callbacks = {
			ifOk: function(){oldcb.ifOk(); unlock();},
			ifError: function(err){oldcb.ifError(err); unlock();}
		};

		var subject = json.subject;
		var body = json.body;
		if (!subject || typeof body == "undefined")
			return callbacks.ifError("no subject or body");
		//if (bIndirectCorrespondent && ["cancel_new_wallet", "my_xpubkey", "new_wallet_address"].indexOf(subject) === -1)
		//    return callbacks.ifError("you're indirect correspondent, cannot trust "+subject+" from you");
		var from_address = objectHash.getDeviceAddress(device_pubkey);
		
		switch (subject){
```

**File:** wallet.js (L337-354)
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
						callbacks.ifOk();
```

**File:** wallet.js (L1052-1070)
```javascript
			db.query(
			//	"SELECT address, device_address, member_signing_path FROM shared_address_signing_paths WHERE shared_address=? AND signing_path=?", 
				// look for a prefix of the requested signing_path
				"SELECT address, device_address, signing_path FROM shared_address_signing_paths \n\
				WHERE shared_address=? AND signing_path=SUBSTR(?, 1, LENGTH(signing_path))", 
				[address, signing_path],
				function(sa_rows){
					if (sa_rows.length > 1)
						throw Error("more than 1 member address found for shared address "+address+" and signing path "+signing_path);
					if (sa_rows.length === 1) {
						var objSharedAddress = sa_rows[0];
						var relative_signing_path = 'r' + signing_path.substr(objSharedAddress.signing_path.length);
						var bLocal = (objSharedAddress.device_address === device.getMyDeviceAddress()); // local keys
						if (objSharedAddress.address === '') {
							return callbacks.ifMerkle(bLocal);
						} else if(objSharedAddress.address === 'secret') {
							return callbacks.ifSecret();
						}
						return findAddress(objSharedAddress.address, relative_signing_path, callbacks, bLocal ? null : objSharedAddress.device_address);
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
