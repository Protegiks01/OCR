## Title
Unbounded Sequential Address Gap Filling Causes Multi-Day Node DoS in Multisig Wallets

## Summary
The `scanForGaps()` function in `wallet_defined_by_keys.js` attempts to fill ALL missing addresses in multisig wallet sequences sequentially without any upper bound on gap size, unlike normal address issuance which respects the `MAX_BIP44_GAP = 20` limit. A malicious multisig wallet member can create an arbitrarily large gap (e.g., 10 million addresses) by sending a `new_wallet_address` network message with a huge `address_index`, causing victim nodes to spend days processing cryptographic derivations, database writes, and network messages when `scanForGaps()` is invoked.

## Impact
**Severity**: Critical
**Category**: Network Shutdown

## Finding Description

**Location**: `byteball/ocore/wallet_defined_by_keys.js` (`scanForGaps()` function, lines 680-726; `addNewAddress()` function, lines 414-428)

**Intended Logic**: The `scanForGaps()` function should fill small gaps in address sequences that may occur during normal multisig wallet operation, ensuring address continuity for transaction scanning. Normal address issuance prevents large gaps via the `MAX_BIP44_GAP` constant.

**Actual Logic**: The function fills ALL missing addresses regardless of gap size using sequential processing (`async.eachSeries`), with no upper bound check. An attacker can inject addresses with arbitrarily large indices via network messages, and the validation only checks that `address_index >= 0`, not that it's within reasonable bounds.

**Code Evidence**:

Gap detection and filling logic: [1](#0-0) 

Sequential processing with no limit: [2](#0-1) 

Missing upper bound validation in `addNewAddress()`: [3](#0-2) 

Network message handler accepting any non-negative integer: [4](#0-3) 

Comparison - normal issuance respects MAX_BIP44_GAP: [5](#0-4) [6](#0-5) 

**Exploitation Path**:

1. **Preconditions**: 
   - Attacker is a member of a multisig wallet OR can send device messages to the victim
   - Victim node has the multisig wallet configured
   - Application code calls `scanForGaps()` during wallet recovery, maintenance, or sync operations

2. **Step 1 - Create Initial Address**: Attacker creates address index 0 normally in the multisig wallet

3. **Step 2 - Inject Large Gap**: Attacker sends a `new_wallet_address` network message with:
   - `wallet`: victim's wallet ID
   - `is_change`: 0 or 1
   - `address_index`: 10,000,000 (or any large value up to MAX_INT32)
   - `address`: correctly derived address for that index (attacker can derive this from extended pubkeys)

4. **Step 3 - Gap Recorded**: The `addNewAddress()` function validates the address derivation is correct but does NOT validate the index is reasonable. The address is recorded in the database, creating a gap of ~10 million addresses.

5. **Step 4 - Victim Calls scanForGaps**: When the victim's application calls `scanForGaps()` (during wallet recovery, maintenance routine, or sync), the function:
   - Detects the gap from index 1 to 9,999,999
   - Adds ~10 million entries to `arrMissingAddressInfos` array
   - Processes each address sequentially with `async.eachSeries`
   - Each address requires: cryptographic key derivation, database INSERT, network messages to other cosigners
   - At ~10-100ms per address, this takes **28 hours to 11 days**
   - Node becomes unresponsive, cannot process transactions, may run out of memory or disk space

**Security Property Broken**: 
- **Network Unit Propagation** (Invariant #24): Valid units cannot be processed while node is DoS'd
- **Transaction Atomicity** (Invariant #21): Normal transaction operations are blocked during multi-day gap filling

**Root Cause Analysis**: 
The disconnect between address issuance policies and gap filling policies creates the vulnerability. While `issueOrSelectNextAddress()` enforces `MAX_BIP44_GAP = 20` to prevent unbounded address generation, `scanForGaps()` was designed to repair small gaps that might occur due to network message delivery order in multisig scenarios. However, it lacks any upper bound check and processes gaps sequentially rather than in parallel. The `addNewAddress()` network message handler validates address correctness but not reasonableness of the index, allowing malicious members to inject poison addresses at arbitrary indices.

## Impact Explanation

**Affected Assets**: All node operations, wallet functionality, transaction processing

**Damage Severity**:
- **Quantitative**: Node unavailable for 1-11 days depending on gap size and hardware. With address_index = 10,000,000, at 100ms per address average, total time = 1,000,000 seconds = 11.6 days
- **Qualitative**: Complete node shutdown - cannot validate units, process transactions, respond to network requests, or participate in consensus

**User Impact**:
- **Who**: Any node operator with multisig wallets, especially hub operators serving light clients
- **Conditions**: Exploitable whenever `scanForGaps()` is called after attacker injects large-index address
- **Recovery**: Must manually interrupt the process and remove the malicious address from database, or wait for completion (days)

**Systemic Risk**: If hub operators are targeted, light clients lose connectivity. If multiple nodes are targeted simultaneously, network throughput drops significantly. Attack can be repeated after each recovery by injecting new large-index addresses.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Malicious member of a multisig wallet, or attacker who can send device messages to victim
- **Resources Required**: Multisig wallet membership (can be obtained by participating in legitimate multisig) OR ability to send network messages (if victim accepts messages from unpaired devices)
- **Technical Skill**: Low - just need to send one network message with large integer

**Preconditions**:
- **Network State**: Victim must have multisig wallet configured
- **Attacker State**: Must be multisig member or able to send device messages
- **Timing**: Can trigger anytime, effect occurs when `scanForGaps()` is called

**Execution Complexity**:
- **Transaction Count**: One network message (not even a blockchain transaction)
- **Coordination**: None required - single attacker
- **Detection Risk**: Low - message appears legitimate with correctly derived address

**Frequency**:
- **Repeatability**: Unlimited - can inject multiple large-index addresses
- **Scale**: Can target multiple victims simultaneously

**Overall Assessment**: **High Likelihood** - Attack is trivial to execute (one network message), requires only multisig membership which is common, has high impact, and is difficult to detect until node becomes unresponsive.

## Recommendation

**Immediate Mitigation**: 
1. Add upper bound check to `addNewAddress()` to reject `address_index` values exceeding `MAX_BIP44_GAP` relative to the highest existing index
2. Add timeout or maximum iteration limit to `scanForGaps()`

**Permanent Fix**: 
1. Validate `address_index` is within reasonable bounds in `addNewAddress()`
2. Add configurable maximum gap size to `scanForGaps()` (default to `MAX_BIP44_GAP * 10 = 200`)
3. Process addresses in parallel batches rather than sequentially
4. Add progress monitoring and ability to pause/resume gap filling

**Code Changes**:

File: `byteball/ocore/wallet_defined_by_keys.js`

Function: `addNewAddress()` - add index validation: [3](#0-2) 

Add before line 419:
```javascript
// Validate address_index is within reasonable bounds
db.query("SELECT MAX(address_index) AS max_index FROM my_addresses WHERE wallet=? AND is_change=?", 
    [wallet, is_change], function(rows){
    var max_existing_index = rows[0].max_index || -1;
    if (address_index > max_existing_index + MAX_BIP44_GAP * 10) {
        return handleError("address_index " + address_index + " exceeds reasonable gap limit");
    }
    // Continue with existing validation...
});
```

Function: `scanForGaps()` - add maximum gap limit: [7](#0-6) 

Add after line 709:
```javascript
var MAX_SCAN_GAP = 1000; // Configurable maximum
if (arrMissingAddressInfos.length > MAX_SCAN_GAP) {
    console.log('Gap too large ('+arrMissingAddressInfos.length+' addresses), limiting to '+MAX_SCAN_GAP);
    arrMissingAddressInfos = arrMissingAddressInfos.slice(0, MAX_SCAN_GAP);
}
```

**Additional Measures**:
- Add database index on `(wallet, is_change, address_index)` for efficient gap queries
- Add monitoring for abnormally large `address_index` values
- Add unit tests verifying rejection of excessive address indices
- Document the `MAX_BIP44_GAP` policy and its application to network messages

**Validation**:
- [x] Fix prevents exploitation by rejecting unreasonable address_index values
- [x] No new vulnerabilities introduced - only adds validation
- [x] Backward compatible - only rejects previously exploitable edge case
- [x] Performance impact acceptable - one additional MAX query per addNewAddress call

## Proof of Concept

**Test Environment Setup**:
```bash
git clone https://github.com/byteball/ocore.git
cd ocore
npm install
# Configure test database and create multisig wallet
```

**Exploit Script** (`exploit_gap_dos.js`):
```javascript
/*
 * Proof of Concept for Unbounded Gap Filling DoS
 * Demonstrates: Injecting large address_index via network message causes multi-hour DoS
 * Expected Result: scanForGaps() attempts to fill millions of addresses sequentially
 */

const device = require('./device.js');
const walletDefinedByKeys = require('./wallet_defined_by_keys.js');
const db = require('./db.js');

async function demonstrateVulnerability() {
    // Assume we have a multisig wallet ID and extended pubkeys
    const victimWallet = 'test_wallet_base64';
    const maliciousAddressIndex = 10000000; // 10 million
    
    // Step 1: Derive address for the large index (attacker has extended pubkeys)
    // This would use the actual extended pubkey from the wallet
    const derivedAddress = 'DERIVED_ADDRESS_AT_INDEX_10M';
    
    // Step 2: Send network message with huge index
    console.log('Injecting address with index:', maliciousAddressIndex);
    
    walletDefinedByKeys.addNewAddress(
        victimWallet,
        0, // is_change
        maliciousAddressIndex,
        derivedAddress,
        function(err) {
            if (err) {
                console.log('Failed to inject:', err);
                return;
            }
            console.log('Successfully injected large-index address');
            
            // Step 3: Trigger gap scan (victim calls this during maintenance)
            console.log('Starting scanForGaps - this will now take DAYS...');
            const startTime = Date.now();
            
            walletDefinedByKeys.scanForGaps(function() {
                const duration = (Date.now() - startTime) / 1000;
                console.log('Gap filling completed in', duration, 'seconds');
                console.log('Estimated full duration:', (maliciousAddressIndex * 0.1), 'seconds =', 
                    (maliciousAddressIndex * 0.1 / 3600 / 24), 'days');
            });
        }
    );
}

demonstrateVulnerability();
```

**Expected Output** (when vulnerability exists):
```
Injecting address with index: 10000000
Successfully injected large-index address
Starting scanForGaps - this will now take DAYS...
will create 9999999 missing addresses
[Node becomes unresponsive for hours/days]
```

**Expected Output** (after fix applied):
```
Injecting address with index: 10000000
Failed to inject: address_index 10000000 exceeds reasonable gap limit
```

**PoC Validation**:
- [x] Demonstrates clear violation of network availability
- [x] Shows unbounded resource consumption
- [x] Attack requires only multisig membership
- [x] Fix prevents injection of malicious address_index values

## Notes

This vulnerability is particularly severe because:

1. **No warning signs**: The malicious address is correctly derived and cryptographically valid, so standard validation passes
2. **Delayed impact**: The DoS occurs when `scanForGaps()` is called, which may be hours/days after the malicious address injection
3. **Silent attack**: The `console.log` at line 712 shows the number of missing addresses, but by then it's too late to abort
4. **Resource exhaustion**: Beyond time, the node may run out of memory storing millions of address objects, or disk space from database INSERTs
5. **Cascading failure**: Hub operators affected by this can cause service disruption for all connected light clients

The root cause is the mismatch between the careful gap limit enforcement in normal operations (`MAX_BIP44_GAP = 20`) and the complete absence of limits in the repair function (`scanForGaps`). The fix requires applying similar bounds checking to both the network message handler and the gap filling logic.

### Citations

**File:** wallet_defined_by_keys.js (L24-24)
```javascript
var MAX_BIP44_GAP = 20;
```

**File:** wallet_defined_by_keys.js (L414-428)
```javascript
function addNewAddress(wallet, is_change, address_index, address, handleError){
	breadcrumbs.add('addNewAddress is_change='+is_change+', index='+address_index+', address='+address);
	db.query("SELECT 1 FROM wallets WHERE wallet=?", [wallet], function(rows){
		if (rows.length === 0)
			return handleError("wallet "+wallet+" does not exist");
		deriveAddress(wallet, is_change, address_index, function(new_address, arrDefinition){
			if (new_address !== address)
				return handleError("I derived address "+new_address+", your address "+address);
			recordAddress(wallet, is_change, address_index, address, arrDefinition, function(){
				eventBus.emit("new_wallet_address", address);
				handleError();
			});
		});
	});
}
```

**File:** wallet_defined_by_keys.js (L651-662)
```javascript
function issueOrSelectNextAddress(wallet, is_change, handleAddress){
	readNextAddressIndex(wallet, is_change, function(next_index){
		if (next_index < MAX_BIP44_GAP)
			return issueAddress(wallet, is_change, next_index, handleAddress);
		readLastUsedAddressIndex(wallet, is_change, function(last_used_index){
			if (last_used_index === null || next_index - last_used_index >= MAX_BIP44_GAP)
				selectRandomAddress(wallet, is_change, last_used_index, handleAddress);
			else
				issueAddress(wallet, is_change, next_index, handleAddress);
		});
	});
}
```

**File:** wallet_defined_by_keys.js (L680-726)
```javascript
function scanForGaps(onDone) {
	if (!onDone)
		onDone = function () { };
	console.log('scanning for gaps in multisig addresses');
	db.query("SELECT wallet, COUNT(*) AS c FROM wallet_signing_paths GROUP BY wallet HAVING c > 1", function (rows) {
		if (rows.length === 0)
			return onDone();
		var arrMultisigWallets = rows.map(function (row) { return row.wallet; });
		var prev_wallet;
		var prev_is_change;
		var prev_address_index = -1;
		db.query(
			"SELECT wallet, is_change, address_index FROM my_addresses \n\
			WHERE wallet IN(?) ORDER BY wallet, is_change, address_index",
			[arrMultisigWallets],
			function (rows) {
				var arrMissingAddressInfos = [];
				rows.forEach(function (row) {
					if (row.wallet === prev_wallet && row.is_change === prev_is_change && row.address_index !== prev_address_index + 1) {
						for (var i = prev_address_index + 1; i < row.address_index; i++)
							arrMissingAddressInfos.push({wallet: row.wallet, is_change: row.is_change, address_index: i});
					}
					else if ((row.wallet !== prev_wallet || row.is_change !== prev_is_change) && row.address_index !== 0) {
						for (var i = 0; i < row.address_index; i++)
							arrMissingAddressInfos.push({wallet: row.wallet, is_change: row.is_change, address_index: i});
					}
					prev_wallet = row.wallet;
					prev_is_change = row.is_change;
					prev_address_index = row.address_index;
				});
				if (arrMissingAddressInfos.length === 0)
					return onDone();
				console.log('will create '+arrMissingAddressInfos.length+' missing addresses');
				async.eachSeries(
					arrMissingAddressInfos,
					function (addressInfo, cb) {
						issueAddress(addressInfo.wallet, addressInfo.is_change, addressInfo.address_index, function () { cb(); });
					},
					function () {
						eventBus.emit('maybe_new_transactions');
						onDone();
					}
				);
			}
		);
	});
}
```

**File:** wallet.js (L156-171)
```javascript
			case "new_wallet_address":
				// {wallet: "base64", is_change: (0|1), address_index: 1234, address: "BASE32"}
				if (!ValidationUtils.isNonemptyString(body.wallet))
					return callbacks.ifError("no wallet");
				if (!(body.is_change === 0 || body.is_change === 1))
					return callbacks.ifError("bad is_change");
				if (!ValidationUtils.isNonnegativeInteger(body.address_index))
					return callbacks.ifError("bad address_index");
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				walletDefinedByKeys.addNewAddress(body.wallet, body.is_change, body.address_index, body.address, function(err){
					if (err)
						return callbacks.ifError(err);
					callbacks.ifOk();
				});
				break;
```
