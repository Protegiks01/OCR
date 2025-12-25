Based on my comprehensive code analysis of the byteball/ocore repository, I have validated this security claim and found it to be **VALID**.

# Validation Report: Missing Device Address Validation in Shared Address Handling

## Summary

The `handleNewSharedAddress()` function fails to validate `device_address` fields before database storage, allowing malicious peers to inject empty strings. When signing requests are processed, the code attempts to route messages to invalid device addresses, triggering an uncaught exception that crashes the node. [1](#0-0) 

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay / Node Crash DoS

Single-node denial of service affecting any node using shared addresses. Requires manual restart and database cleanup. Corrupted entries persist indefinitely enabling repeated crashes.

## Finding Description

**Location**: [2](#0-1) 

**Intended Logic**: All signer fields including `device_address` should be validated before storage. Device addresses must be 33 characters starting with '0'.

**Actual Logic**: Validation loop only checks the `address` field: [1](#0-0) 

The system provides a validation function: [3](#0-2) 

However, this function is never invoked for `device_address` fields in the handler.

**Exploitation Path**:

1. **Message Injection**: Attacker (paired correspondent) sends "new_shared_address" message with empty `device_address` field
   - Message handled at: [4](#0-3) 

2. **Validation Bypass**: Protective rewrite logic can be bypassed by including decoy entry with victim's device address: [5](#0-4) 

3. **Database Storage**: Empty device_address stored without validation: [6](#0-5) 
   
   Database schema: [7](#0-6) 

4. **Crash Trigger**: When "sign" message arrives:
   - findAddress queries database: [8](#0-7) 
   - ifRemote callback invoked: [9](#0-8) 
   - sendMessageToDevice called with empty device_address: [10](#0-9) 
   - Synchronous exception thrown: [11](#0-10) 
   - No try-catch in handler chain: [12](#0-11) 

**Security Property Broken**: Node availability - system must validate all message routing parameters before storage.

**Root Cause**: Missing input validation for `device_address` field despite available validation function; synchronous exception in callback context without error handling.

## Impact Explanation

**Affected Assets**: Node availability, shared address signing coordination, transaction processing

**Damage Severity**: Any correspondent can crash victim nodes. Persistent database corruption requires manual SQL cleanup.

**User Impact**: Nodes using shared addresses vulnerable to DoS. Requires manual restart and database query: `DELETE FROM shared_address_signing_paths WHERE device_address = ''`

**Systemic Risk**: Simultaneous attacks on multiple cosigners prevent all shared address operations.

## Likelihood Explanation

**Attacker Profile**: Any correspondent peer with minimal technical skill

**Resources Required**: 
- Correspondent pairing (normal operation)
- Knowledge of victim's payment address (observable)
- Two simple JSON messages

**Execution Complexity**: Low - send malicious "new_shared_address" message, then trigger any "sign" message

**Overall Assessment**: High likelihood - trivially exploitable with no economic barrier

## Recommendation

**Immediate Fix**: Add device_address validation in handleNewSharedAddress:

```javascript
// wallet_defined_by_addresses.js line 349 (after address validation)
if (signerInfo.device_address && !ValidationUtils.isValidDeviceAddress(signerInfo.device_address))
    return callbacks.ifError("invalid device address: "+signerInfo.device_address);
```

**Additional Measures**:
- Add try-catch around sendMessageToDevice calls
- Database migration to clean existing empty device_address entries
- Add test case validating device_address rejection

## Notes

**Validation Status**: ✓ All code paths verified through source analysis  
**Missing Element**: Report lacks complete runnable PoC, though exploit is clearly implementable  
**Severity Justification**: Single-node DoS requiring manual recovery meets Immunefi "Medium" criteria for Temporary Transaction Delay ≥1 Hour

The vulnerability is confirmed valid despite the absence of a complete proof-of-concept, as the code analysis definitively demonstrates the exploitable conditions exist in the codebase.

### Citations

**File:** wallet_defined_by_addresses.js (L248-251)
```javascript
				db.addQuery(arrQueries, 
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

**File:** wallet_defined_by_addresses.js (L339-360)
```javascript
function handleNewSharedAddress(body, callbacks){
	if (!ValidationUtils.isArrayOfLength(body.definition, 2))
		return callbacks.ifError("invalid definition");
	if (typeof body.signers !== "object" || Object.keys(body.signers).length === 0)
		return callbacks.ifError("invalid signers");
	if (body.address !== objectHash.getChash160(body.definition))
		return callbacks.ifError("definition doesn't match its c-hash");
	for (var signing_path in body.signers){
		var signerInfo = body.signers[signing_path];
		if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
			return callbacks.ifError("invalid member address: "+signerInfo.address);
	}
	determineIfIncludesMeAndRewriteDeviceAddress(body.signers, function(err){
		if (err)
			return callbacks.ifError(err);
		validateAddressDefinition(body.definition, function(err){
			if (err)
				return callbacks.ifError(err);
			addNewSharedAddress(body.address, body.definition, body.signers, body.forwarded, callbacks.ifOk);
		});
	});
}
```

**File:** validation_utils.js (L64-66)
```javascript
function isValidDeviceAddress(address){
	return ( isStringOfLength(address, 33) && address[0] === '0' && isValidAddress(address.substr(1)) );
}
```

**File:** wallet.js (L60-67)
```javascript
function handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, callbacks){
	// serialize all messages from hub
	mutex.lock(["from_hub"], function(unlock){
		var oldcb = callbacks;
		callbacks = {
			ifOk: function(){oldcb.ifOk(); unlock();},
			ifError: function(err){oldcb.ifError(err); unlock();}
		};
```

**File:** wallet.js (L212-220)
```javascript
			case "new_shared_address":
				// {address: "BASE32", definition: [...], signers: {...}}
				walletDefinedByAddresses.handleNewSharedAddress(body, {
					ifError: callbacks.ifError,
					ifOk: function(){
						callbacks.ifOk();
						eventBus.emit('maybe_new_transactions');
					}
				});
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

**File:** wallet.js (L1055-1070)
```javascript
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

**File:** initial-db/byteball-sqlite.sql (L628-634)
```sql
CREATE TABLE shared_address_signing_paths (
	shared_address CHAR(32) NOT NULL,
	signing_path VARCHAR(255) NULL, -- full path to signing key which is a member of the member address
	address CHAR(32) NOT NULL, -- member address
	member_signing_path VARCHAR(255) NULL, -- path to signing key from root of the member address
	device_address CHAR(33) NOT NULL, -- where this signing key lives or is reachable through
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
```

**File:** device.js (L703-704)
```javascript
	if (!device_address)
		throw Error("empty device address");
```
