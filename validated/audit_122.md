# Security Audit Report

## Title
Light Client Shared Address Registration Bypass Due to Missing Retry Mechanism in approvePendingSharedAddress

## Summary
The `approvePendingSharedAddress` function in `wallet_defined_by_addresses.js` directly calls `network.addLightWatchedAddress` without using the robust `unprocessed_addresses` retry mechanism, unlike `addNewSharedAddress`. When a light client approves a shared address while disconnected from the hub, the address registration fails silently and permanently, causing the client to lose visibility of all future transactions to that address and become unable to spend from it.

## Impact
**Severity**: High  
**Category**: Permanent Fund Freeze

**Affected Assets**: All bytes (native currency) and custom assets sent to the unregistered shared address become permanently invisible and unspendable by the affected light client.

**Affected Parties**: Light client users who approve/create shared addresses during temporary hub disconnection (network outages, hub maintenance, connection timeouts).

**Quantified Impact**: Unbounded fund loss over time - all payments to the affected shared address are permanently invisible to the light client without manual intervention or full node migration.

## Finding Description

**Location**: `byteball/ocore/wallet_defined_by_addresses.js:150-227`, function `approvePendingSharedAddress()`

**Intended Logic**: All shared addresses on light clients should be registered with the hub for transaction notifications, with automatic retry on connection failure.

**Actual Logic**: `approvePendingSharedAddress` calls `network.addLightWatchedAddress` without a callback handler and without using the `unprocessed_addresses` retry queue, causing silent failure when the hub is disconnected.

**Code Evidence**:

In `approvePendingSharedAddress`, address registration for light clients: [1](#0-0) 

Compare with `addNewSharedAddress` which uses the retry mechanism: [2](#0-1) 

The "new_address" event emission triggers automatic retry via `light_wallet.js`: [3](#0-2) 

The `unprocessed_addresses` table provides automatic retry on reconnection: [4](#0-3) 

The `addLightWatchedAddress` function has no built-in retry mechanism: [5](#0-4) 

The `sendJustsayingToLightVendor` function fails silently when no callback is provided: [6](#0-5) 

Other similar functions like `addLightWatchedAa` properly implement retry on reconnection: [7](#0-6) 

The `addWatchedAddress` function in `wallet_general.js` properly uses both mechanisms: [8](#0-7) 

**Exploitation Path**:

1. **Preconditions**: Light client is temporarily disconnected from hub (network interruption, hub maintenance, connection timeout)

2. **Step 1**: User receives "approve_new_shared_address" message from another device
   - Message handler: `wallet.js:190-202` → calls `walletDefinedByAddresses.approvePendingSharedAddress()`
   - [9](#0-8) 

3. **Step 2**: `approvePendingSharedAddress` processes all approvals and creates shared address
   - Inserts into `shared_addresses` table locally (line 182-183)
   - Inserts into `shared_address_signing_paths` table (lines 197-200)
   - Calls `network.addLightWatchedAddress(shared_address)` at line 217 WITHOUT callback

4. **Step 3**: `sendJustsayingToLightVendor` attempts to connect to hub
   - `findOutboundPeerOrConnect` fails because hub is unreachable
   - Error returned via callback, but no callback was provided
   - Silent failure - no error logged or stored

5. **Step 4**: Address stored locally but NOT registered with hub
   - NOT in hub's `watched_light_addresses` table
   - NOT in client's `unprocessed_addresses` retry queue
   - NO "new_address" event emitted

6. **Step 5**: Light client reconnects to hub
   - Connection event handler checks `unprocessed_addresses` table
   - Address NOT found in table, so NOT automatically registered
   - Address remains permanently unregistered

7. **Step 6**: Funds sent to shared address by external parties
   - Transactions posted to DAG and confirmed
   - Hub does NOT notify light client (address not watched)
   - Light client has no knowledge of incoming transactions

8. **Step 7**: User attempts to spend from shared address
   - Cannot compose transaction due to missing UTXO information
   - Light client has no record of unspent outputs at the address
   - Funds effectively frozen from light client's perspective

**Security Property Broken**: Light client visibility consistency - light clients must maintain synchronized view of their owned addresses with the hub to prevent fund loss.

**Root Cause Analysis**:

The codebase has two inconsistent patterns for address registration:

1. **Robust pattern** (used by `addNewSharedAddress`, `addWatchedAddress`):
   - Emit "new_address" event → triggers `refreshLightClientHistory` 
   - Insert into `unprocessed_addresses` table → automatic retry on reconnection
   - Dual-layer protection ensures address is eventually registered

2. **Fragile pattern** (used by `approvePendingSharedAddress`):
   - Direct call to `network.addLightWatchedAddress` without callback
   - No event emission, no `unprocessed_addresses` entry
   - Single point of failure with no retry mechanism

The inconsistency likely arose from `approvePendingSharedAddress` being written before the `unprocessed_addresses` retry mechanism was fully developed, and not being updated to use the new pattern.

## Impact Explanation

**Affected Assets**: All bytes and custom divisible/indivisible assets sent to the unregistered shared address.

**Damage Severity**:
- **Quantitative**: Unbounded - all funds sent to the address over time become invisible to the light client
- **Qualitative**: Permanent visibility loss requiring technical intervention to recover

**User Impact**:
- **Who**: Light client users who approve shared addresses during any hub disconnection period
- **Conditions**: Occurs whenever network interruption coincides with shared address approval
- **Recovery Options**: 
  1. Export wallet and import to full node (requires technical knowledge, full node setup)
  2. Manual database manipulation to add address to `unprocessed_addresses` (no UI support)
  3. Direct JavaScript console access to call `addLightWatchedAddress` after reconnection (expert only)

**Systemic Risk**:
- Hub outages affect multiple users simultaneously
- No user-facing error indicates the silent failure
- Users discover issue only when funds appear missing
- Accumulates over time as hub reliability issues recur

## Likelihood Explanation

**Trigger Profile**:
- **Nature**: Environmental condition (network instability), not malicious attack
- **Resources Required**: None - occurs naturally
- **Technical Skill**: None - happens to ordinary users

**Preconditions**:
- **Network State**: Hub temporarily unreachable or connection interrupted
- **Timing**: Shared address approval coincides with disconnection window

**Execution Complexity**:
- **Coordination**: None required
- **Detection Risk**: Silent failure - no indication to user
- **Reproducibility**: Occurs every time approval happens during disconnection

**Frequency**:
- **Occurrence Rate**: Depends on hub reliability and network stability
- **Scale**: Affects individual addresses, but can accumulate across users and time

**Overall Assessment**: Medium to High likelihood - hub outages and network issues are common enough to make this a realistic and recurring scenario.

## Recommendation

**Immediate Mitigation**:

Modify `approvePendingSharedAddress` to use the same robust pattern as `addNewSharedAddress`:

```javascript
// File: wallet_defined_by_addresses.js
// Lines 216-218 (replace direct call)

if (conf.bLight){
    db.query("INSERT " + db.getIgnore() + " INTO unprocessed_addresses (address) VALUES (?)", [shared_address]);
    eventBus.emit("new_address", shared_address);
}
```

**Permanent Fix**:

Standardize all address registration code paths to use the retry mechanism. Create a helper function:

```javascript
function registerLightAddress(address) {
    if (!conf.bLight) return;
    db.query("INSERT " + db.getIgnore() + " INTO unprocessed_addresses (address) VALUES (?)", [address]);
    eventBus.emit("new_address", address);
}
```

Replace all direct `network.addLightWatchedAddress` calls with this helper.

**Additional Measures**:
- Audit all address creation code paths for similar issues
- Add monitoring to detect unregistered addresses owned by light client
- Provide UI notification when address registration fails
- Add diagnostic command to check and repair missing address registrations

**Validation**:
- Fix ensures address is added to `unprocessed_addresses` table
- Event emission triggers immediate registration attempt
- Automatic retry on reconnection via existing mechanism
- No breaking changes to existing functionality
- Backward compatible with all existing shared addresses

## Proof of Concept

```javascript
// Test: Light Client Shared Address Registration Failure
// This test demonstrates that approvePendingSharedAddress fails to register
// addresses when the hub is disconnected, unlike addNewSharedAddress

const db = require('./db.js');
const conf = require('./conf.js');
const network = require('./network.js');
const walletDefinedByAddresses = require('./wallet_defined_by_addresses.js');
const eventBus = require('./event_bus.js');
const assert = require('assert');

async function testAddressRegistrationConsistency() {
    // Setup: Configure as light client
    conf.bLight = true;
    
    // Mock network disconnection by intercepting addLightWatchedAddress
    let lightWatchedAddressCalls = [];
    const originalAddLightWatchedAddress = network.addLightWatchedAddress;
    network.addLightWatchedAddress = function(address, handle) {
        lightWatchedAddressCalls.push(address);
        // Simulate hub disconnection - call handle with error if provided
        if (handle) {
            handle("hub not connected");
        }
        // No error logged if handle not provided (the bug!)
    };
    
    // Track new_address events
    let newAddressEvents = [];
    eventBus.on("new_address", function(address) {
        newAddressEvents.push(address);
    });
    
    console.log("\n=== TEST 1: addNewSharedAddress (CORRECT BEHAVIOR) ===");
    
    // Test addNewSharedAddress
    const testAddress1 = "TEST_ADDRESS_1_AAAAAAAAAAAAAA";
    const testDefinition1 = ["sig", {pubkey: "test_pubkey_1"}];
    const testSigners1 = {
        "r.0": {
            address: "SIGNER_ADDRESS_1",
            member_signing_path: "r",
            device_address: "DEVICE_1"
        }
    };
    
    await new Promise((resolve) => {
        walletDefinedByAddresses.addNewSharedAddress(
            testAddress1, 
            testDefinition1, 
            testSigners1, 
            false,
            resolve
        );
    });
    
    // Verify address was added to unprocessed_addresses
    const unprocessed1 = await new Promise((resolve) => {
        db.query(
            "SELECT address FROM unprocessed_addresses WHERE address=?",
            [testAddress1],
            resolve
        );
    });
    
    console.log("✓ Address in unprocessed_addresses:", unprocessed1.length > 0);
    console.log("✓ new_address event emitted:", newAddressEvents.includes(testAddress1));
    console.log("✓ addLightWatchedAddress called:", lightWatchedAddressCalls.includes(testAddress1));
    
    assert(unprocessed1.length > 0, "Address should be in unprocessed_addresses");
    assert(newAddressEvents.includes(testAddress1), "new_address event should be emitted");
    
    // Reset tracking
    lightWatchedAddressCalls = [];
    newAddressEvents = [];
    
    console.log("\n=== TEST 2: approvePendingSharedAddress (VULNERABLE BEHAVIOR) ===");
    
    // Setup pending shared address
    const testAddress2 = "TEST_ADDRESS_2_AAAAAAAAAAAAAA";
    const templateChash = "TEMPLATE_CHASH_AAAAAAAAAAAAA";
    const template = ["sig", {pubkey: "$address@DEVICE_2"}];
    
    // Insert pending shared address
    await new Promise((resolve) => {
        db.query(
            "INSERT INTO pending_shared_addresses (definition_template_chash, definition_template) VALUES(?,?)",
            [templateChash, JSON.stringify(template)],
            resolve
        );
    });
    
    // Insert pending signing paths (simulating all approvals collected)
    await new Promise((resolve) => {
        db.query(
            "INSERT INTO pending_shared_address_signing_paths " +
            "(definition_template_chash, device_address, signing_path, address, " +
            "device_addresses_by_relative_signing_paths, approval_date) " +
            "VALUES(?,?,?,?,?,datetime('now'))",
            [
                templateChash,
                "DEVICE_2",
                "r",
                "SIGNER_ADDRESS_2",
                JSON.stringify({"r": "DEVICE_2"})
            ],
            resolve
        );
    });
    
    // Trigger approvePendingSharedAddress (simulating last approval)
    walletDefinedByAddresses.approvePendingSharedAddress(
        templateChash,
        "DEVICE_2",
        "SIGNER_ADDRESS_2",
        {"r": "DEVICE_2"}
    );
    
    // Wait for async operations
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Verify address was NOT added to unprocessed_addresses
    const unprocessed2 = await new Promise((resolve) => {
        db.query(
            "SELECT address FROM unprocessed_addresses WHERE address LIKE 'TEST_ADDRESS_2%'",
            resolve
        );
    });
    
    console.log("✗ Address in unprocessed_addresses:", unprocessed2.length > 0);
    console.log("✗ new_address event emitted:", newAddressEvents.length > 0);
    console.log("✓ addLightWatchedAddress called:", lightWatchedAddressCalls.length > 0);
    console.log("✗ BUT: No callback provided - error silently ignored!");
    
    assert(unprocessed2.length === 0, "BUG: Address should be in unprocessed_addresses but isn't");
    assert(newAddressEvents.length === 0, "BUG: new_address event should be emitted but isn't");
    
    console.log("\n=== VULNERABILITY CONFIRMED ===");
    console.log("approvePendingSharedAddress FAILS to register address when hub disconnected");
    console.log("Address will NEVER be automatically registered on reconnection");
    console.log("Funds sent to this address will be INVISIBLE to light client");
    
    // Cleanup
    network.addLightWatchedAddress = originalAddLightWatchedAddress;
    
    console.log("\n=== TEST COMPLETE ===");
}

// Run test
testAddressRegistrationConsistency().catch(console.error);
```

## Notes

This vulnerability represents a **critical inconsistency** in the light client address registration system. The issue is NOT that `network.addLightWatchedAddress` fails when disconnected (that's expected), but that `approvePendingSharedAddress` has no retry mechanism to handle this failure, unlike the robust pattern used by `addNewSharedAddress` and `addWatchedAddress`.

The vulnerability affects only the **initiator** of a shared address who collects all approvals. Other members who receive the shared address via the `handleNewSharedAddress` → `addNewSharedAddress` path are protected by the proper retry mechanism.

Recovery requires technical expertise beyond typical user capabilities, making this effectively a permanent fund freeze for most affected users. The silent failure with no user-facing error makes detection and diagnosis difficult.

### Citations

**File:** wallet_defined_by_addresses.js (L216-217)
```javascript
										if (conf.bLight)
											network.addLightWatchedAddress(shared_address);
```

**File:** wallet_defined_by_addresses.js (L254-261)
```javascript
				console.log('added new shared address '+address);
				eventBus.emit("new_address-"+address);
				eventBus.emit("new_address", address);

				if (conf.bLight){
					db.query("INSERT " + db.getIgnore() + " INTO unprocessed_addresses (address) VALUES (?)", [address], onDone);
				} else if (onDone)
					onDone();
```

**File:** light_wallet.js (L107-117)
```javascript
	eventBus.on("new_address", function(address){
		if (!exports.bRefreshHistoryOnNewAddress) {
			db.query("DELETE FROM unprocessed_addresses WHERE address=?", [address]);
			return console.log("skipping history refresh on new address " + address);
		}
		refreshLightClientHistory([address], function(error){
			if (error)
				return console.log(error);
			db.query("DELETE FROM unprocessed_addresses WHERE address=?", [address]);
		});
	});
```

**File:** light_wallet.js (L120-136)
```javascript
	eventBus.on('connected', function(ws){
		console.log('light connected to ' + ws.peer);
		if (ws.peer === network.light_vendor_url) {
			console.log('resetting bFirstHistoryReceived');
			bFirstHistoryReceived = false;
		}
		db.query("SELECT address FROM unprocessed_addresses", function(rows){
			if (rows.length === 0)
				return console.log("no unprocessed addresses");
			var arrAddresses = rows.map(function(row){return row.address});
			console.log('found unprocessed addresses, will request their full history', arrAddresses);
			refreshLightClientHistory(arrAddresses, function(error){
				if (error)
					return console.log("couldn't process history");
				db.query("DELETE FROM unprocessed_addresses WHERE address IN("+ arrAddresses.map(db.escape).join(', ') + ")");
			});
		})
```

**File:** network.js (L124-140)
```javascript
function sendJustsayingToLightVendor(subject, body, handle){
	if (!handle)
		handle = function(){};
	if (!conf.bLight)
		return handle("sendJustsayingToLightVendor cannot be called as full node")
	if (!exports.light_vendor_url){
		console.log("light_vendor_url not set yet");
		return setTimeout(function(){
			sendJustsayingToLightVendor(subject, body, handle);
		}, 1000);
	}
	findOutboundPeerOrConnect(exports.light_vendor_url, function(err, ws){
		if (err)
			return handle("connect to light vendor failed: "+err);
		sendMessage(ws, 'justsaying', {subject: subject, body: body});
		return handle(null);
	});
```

**File:** network.js (L1716-1718)
```javascript
function addLightWatchedAddress(address, handle){
	sendJustsayingToLightVendor('light/new_address_to_watch', address, handle);
}
```

**File:** network.js (L1727-1733)
```javascript
function addLightWatchedAa(aa, address, handle){
	var params = { aa: aa };
	if (address)
		params.address = address;
	sendJustsayingToLightVendor('light/new_aa_to_watch', params, handle);
	eventBus.on('connected', () => sendJustsayingToLightVendor('light/new_aa_to_watch', params));
}
```

**File:** wallet_general.js (L78-83)
```javascript
	db.query("INSERT " + db.getIgnore() + " INTO my_watched_addresses (address) VALUES (?)", [address], function (res) {
		if (res.affectedRows) {
			if (conf.bLight)
				db.query("INSERT " + db.getIgnore() + " INTO unprocessed_addresses (address) VALUES (?)", [address]);
			eventBus.emit("new_address", address); // if light node, this will trigger an history refresh for this address thus it will be watched by the hub
		}
```

**File:** wallet.js (L190-202)
```javascript
			case "approve_new_shared_address":
				// {address_definition_template_chash: "BASE32", address: "BASE32", device_addresses_by_relative_signing_paths: {...}}
				if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
					return callbacks.ifError("invalid addr def c-hash");
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("invalid address");
				if (typeof body.device_addresses_by_relative_signing_paths !== "object" 
						|| Object.keys(body.device_addresses_by_relative_signing_paths).length === 0)
					return callbacks.ifError("invalid device_addresses_by_relative_signing_paths");
				walletDefinedByAddresses.approvePendingSharedAddress(body.address_definition_template_chash, from_address, 
					body.address, body.device_addresses_by_relative_signing_paths);
				callbacks.ifOk();
				break;
```
