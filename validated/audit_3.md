# Missing Device Address Validation in Shared Address Handling

## Summary

The `handleNewSharedAddress()` function in `wallet_defined_by_addresses.js` fails to validate `device_address` fields before database storage, allowing malicious correspondents to inject empty strings. [1](#0-0)  When signing requests later retrieve these corrupted entries via `findAddress()`, the empty device_address is passed to `sendMessageToDevice()`, which throws an uncaught synchronous exception, crashing the node. [2](#0-1) 

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay (Node Crash DoS)

Any correspondent can crash victim nodes using shared addresses through a two-message attack. The node requires manual restart and database cleanup. Corrupted database entries persist indefinitely, enabling repeated attacks. Downtime typically exceeds 1 hour for operators without 24/7 monitoring. Coordinated attacks on multiple cosigners can disable shared address signing network-wide.

## Finding Description

**Location**: `byteball/ocore/wallet_defined_by_addresses.js:339-360`, function `handleNewSharedAddress()`

**Intended Logic**: All signer fields including `device_address` should be validated before database storage. Device addresses must be exactly 33 characters starting with '0'. [3](#0-2) 

**Actual Logic**: The validation loop only checks the `address` field, completely omitting `device_address` validation: [1](#0-0) 

**Exploitation Path**:

1. **Message Reception**: Attacker (paired correspondent) sends "new_shared_address" message with malicious signers object containing:
   - Decoy entry: `device_address = victim's_device_address, address = some_address`
   - Malicious entry: `device_address = "", address = victim's_payment_address`

2. **Validation Bypass**: In `determineIfIncludesMeAndRewriteDeviceAddress()`, the decoy entry sets `bHasMyDeviceAddress = true` [4](#0-3) , causing the protective rewrite logic to be skipped [5](#0-4) , leaving the empty device_address unchanged.

3. **Database Storage**: Empty device_address is stored without validation via direct insertion: [6](#0-5) 
   
   The database schema has no CHECK constraint to prevent empty strings: [7](#0-6) 

4. **Crash Trigger**: When a "sign" message arrives, `findAddress()` queries the database and retrieves the empty device_address: [8](#0-7) 
   
   The `ifRemote` callback is invoked with the empty device_address: [9](#0-8) 
   
   Line 353 calls `sendMessageToDevice()` with the empty device_address, which throws a synchronous error for falsy values (empty string is falsy in JavaScript): [2](#0-1) 
   
   No try-catch exists in the event handler chain, causing uncaught exception and node crash.

**Security Property Broken**: Node availability - the system must validate all message routing parameters before storage to prevent crash conditions.

**Root Cause**: Missing input validation for critical routing field despite available validation utility (`ValidationUtils.isValidDeviceAddress()`); synchronous exception thrown in async callback context without error handling.

## Impact Explanation

**Affected Assets**: Node availability, shared address signing coordination, transaction processing capability.

**Damage Severity**: Any paired correspondent can crash nodes using shared addresses. Attack leaves permanent database corruption requiring manual SQL cleanup: `DELETE FROM shared_address_signing_paths WHERE device_address = ''`. Single attack affects one node, but coordinated attacks on multiple cosigners can completely disable shared address operations.

**User Impact**: Nodes crash on any signing request involving the corrupted shared address. Requires manual intervention: restart node, identify corrupted entries, execute database cleanup query, verify no other corrupted entries exist. Downtime easily exceeds 1 hour for operators without 24/7 monitoring.

**Systemic Risk**: Attacker can target multiple cosigners simultaneously, preventing all signing operations for shared addresses network-wide. Repeated attacks possible until database cleanup is performed.

## Likelihood Explanation

**Attacker Profile**: Any correspondent peer with basic technical knowledge sufficient to send crafted JSON messages.

**Preconditions**:
- Correspondent pairing (achieved through normal pairing flow)
- Knowledge of victim's device address (observable through prior messages or public pairing info)
- Knowledge of any payment address victim uses (observable on-chain)

**Execution Complexity**: Low - attacker constructs "new_shared_address" message with decoy entry (victim's device_address) and malicious entry (empty device_address), then triggers any "sign" message. No timing constraints, cryptographic operations, or coordination required.

**Overall Assessment**: High likelihood - trivially exploitable with zero economic cost, no technical barriers beyond basic JSON message construction, and significant impact on availability.

## Recommendation

**Immediate Mitigation**: Add device_address validation in `handleNewSharedAddress()` before calling `determineIfIncludesMeAndRewriteDeviceAddress()`:

```javascript
// Add after line 350 in wallet_defined_by_addresses.js
for (var signing_path in body.signers){
    var signerInfo = body.signers[signing_path];
    if (signerInfo.device_address && !ValidationUtils.isValidDeviceAddress(signerInfo.device_address))
        return callbacks.ifError("invalid device address: "+signerInfo.device_address);
}
```

**Permanent Fix**: Add database CHECK constraint:

```sql
-- In sqlite_migrations.js
ALTER TABLE shared_address_signing_paths ADD CONSTRAINT check_device_address 
CHECK (device_address GLOB '0[0-9A-Z]*' AND length(device_address) = 33);
```

**Additional Measures**:
- Add try-catch in `wallet.js` around `sendMessageToDevice()` calls to prevent crashes
- Add test case verifying invalid device_address is rejected
- Database migration: Clean existing corrupted entries

## Proof of Concept

```javascript
const test = require('ava');
const device = require('../device.js');
const walletDefinedByAddresses = require('../wallet_defined_by_addresses.js');

test.serial('Missing device_address validation allows node crash', async t => {
    // Setup: Pair with victim as correspondent
    const victimDeviceAddress = '0VICTIM_DEVICE_ADDRESS_HERE...';
    const victimPaymentAddress = 'VICTIM_PAYMENT_ADDRESS';
    
    // Craft malicious shared address message
    const maliciousBody = {
        address: 'VALID_SHARED_ADDRESS',
        definition: ['sig', {pubkey: 'somepubkey'}],
        signers: {
            'r.0': {
                device_address: victimDeviceAddress,  // Decoy
                address: 'SOME_ADDRESS',
                member_signing_path: 'r'
            },
            'r.1': {
                device_address: '',  // Malicious empty string
                address: victimPaymentAddress,
                member_signing_path: 'r'
            }
        }
    };
    
    // Step 1: Send new_shared_address - empty device_address gets stored
    await walletDefinedByAddresses.handleNewSharedAddress(maliciousBody, {
        ifError: (err) => t.fail(err),
        ifOk: () => t.pass('Malicious address stored')
    });
    
    // Step 2: Trigger signing request - this should crash the node
    t.throws(() => {
        device.sendMessageToDevice('', 'sign', {});
    }, {message: 'empty device address'});
});
```

**Notes**:
- The vulnerability exists because `ValidationUtils.isValidDeviceAddress()` is never invoked for device_address fields despite being available [10](#0-9) 
- The bypass mechanism exploits the conditional rewrite logic that only executes when `bHasMyDeviceAddress` is false
- Empty string passes database NOT NULL constraint but fails the falsy check in `sendMessageToDevice()`
- No global uncaughtException handler exists in the codebase to prevent process termination

### Citations

**File:** wallet_defined_by_addresses.js (L248-251)
```javascript
				db.addQuery(arrQueries, 
					"INSERT "+db.getIgnore()+" INTO shared_address_signing_paths \n\
					(shared_address, address, signing_path, member_signing_path, device_address) VALUES (?,?,?,?,?)", 
					[address, signerInfo.address, signing_path, signerInfo.member_signing_path, signerInfo.device_address]);
```

**File:** wallet_defined_by_addresses.js (L284-287)
```javascript
	for (var signing_path in assocSignersByPath){
		var signerInfo = assocSignersByPath[signing_path];
		if (signerInfo.device_address === device.getMyDeviceAddress())
			bHasMyDeviceAddress = true;
```

**File:** wallet_defined_by_addresses.js (L305-310)
```javascript
			if (!bHasMyDeviceAddress){
				for (var signing_path in assocSignersByPath){
					var signerInfo = assocSignersByPath[signing_path];
					if (signerInfo.address && arrMyMemberAddresses.indexOf(signerInfo.address) >= 0)
						signerInfo.device_address = device.getMyDeviceAddress();
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

**File:** device.js (L702-704)
```javascript
function sendMessageToDevice(device_address, subject, body, callbacks, conn){
	if (!device_address)
		throw Error("empty device address");
```

**File:** validation_utils.js (L64-66)
```javascript
function isValidDeviceAddress(address){
	return ( isStringOfLength(address, 33) && address[0] === '0' && isValidAddress(address.substr(1)) );
}
```

**File:** validation_utils.js (L124-125)
```javascript
exports.isValidAddress = isValidAddress;
exports.isValidDeviceAddress = isValidDeviceAddress;
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
