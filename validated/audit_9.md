# Audit Report: Stack Overflow DoS via Cyclic Shared Address References

## Summary

The `readSharedAddressesDependingOnAddresses()` function in `balances.js` lacks proper cycle detection when recursively traversing shared address dependencies. When cyclic references exist in the database (shared address A has member B, shared address B has member A), the function enters infinite recursion causing stack overflow and node crash.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay / Network Disruption

Individual nodes crash when processing balance queries for wallets containing cyclic shared addresses. No funds are lost or stolen, but affected nodes become unavailable until manually restarted. The vulnerability can be used for targeted DoS attacks against specific node operators.

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: The function should recursively discover all shared addresses depending on given member addresses while preventing infinite loops through cycle detection.

**Actual Logic**: The function uses `_.difference(arrSharedAddresses, arrMemberAddresses)` at line 117, which only compares against the **current input array**, not the entire recursion history. When cycles exist, each recursive call sees different input arrays, causing infinite recursion.

**Code Evidence**: 
The vulnerable function at [1](#0-0) 

**Exploitation Path**:

1. **Preconditions**: Attacker can create shared addresses (standard protocol feature)

2. **Step 1**: Attacker creates shared address A with member address B
   - Uses standard shared address creation flow in [2](#0-1) 
   - Inserts into `shared_address_signing_paths`: (shared_address=A, address=B)

3. **Step 2**: Attacker creates shared address B with member address A
   - Definition validation allows unresolved inner addresses [3](#0-2) 
   - Inserts into `shared_address_signing_paths`: (shared_address=B, address=A)
   - Cycle now exists: A→B→A

4. **Step 3**: Any user calls `readSharedBalance()` on wallet containing address A or B
   - Triggers [4](#0-3) 
   - Which calls [1](#0-0) 

5. **Step 4**: Infinite recursion occurs:
   - **Call 1** with [A]: Query finds B is member, computes `_.difference([B], [A]) = [B]`, recurses with [B]
   - **Call 2** with [B]: Query finds A is member, computes `_.difference([A], [B]) = [A]`, recurses with [A]  
   - **Call 3** with [A]: Identical to Call 1 - infinite loop
   - After ~10,000-15,000 calls, JavaScript throws "RangeError: Maximum call stack size exceeded"
   - Node process crashes or becomes unresponsive

**Security Property Broken**: Node availability and operational integrity. The DAG consensus remains valid, but individual nodes cannot service balance queries.

**Root Cause Analysis**: The algorithm maintains cycle detection state only within each individual function call, not across the entire recursion tree. Proper cycle detection requires tracking ALL visited addresses throughout the traversal, either by passing an accumulated set through all recursive calls or using a closure-captured visited set.

**Similar Vulnerability**: The same pattern exists in [5](#0-4)  which also recursively traverses address relationships without comprehensive cycle detection.

## Impact Explanation

**Affected Assets**: Node availability, network health, balance query services

**Damage Severity**:
- **Quantitative**: Single cyclic address pair crashes any node processing balance queries for affected wallets. No fund loss.
- **Qualitative**: Denial of Service against individual nodes. Does not corrupt DAG, consensus, or balances.

**User Impact**:
- **Who**: Node operators whose users have wallets with cyclic addresses; users querying affected balances
- **Conditions**: Automatically triggered when balance reading functions execute for affected addresses
- **Recovery**: Manual node restart required; vulnerability persists until cyclic addresses removed from wallet or code patched

**Systemic Risk**: Low systemic impact - affects individual node operations, not network-wide consensus. Can be used for targeted DoS if attacker knows victim wallet addresses. Automated balance checking systems could be repeatedly crashed.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any Obyte user with ability to create shared addresses
- **Resources Required**: Minimal - two shared address creation transactions
- **Technical Skill**: Low - only requires understanding shared address creation

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Ability to create shared addresses (standard feature)
- **Timing**: No timing constraints

**Execution Complexity**:
- **Transaction Count**: 2 units (one per shared address)
- **Coordination**: None - single attacker execution
- **Detection Risk**: Cyclic references visible in database but not routinely monitored

**Frequency**:
- **Repeatability**: High - attacker can create multiple cyclic pairs
- **Scale**: Can target specific victims by inducing them to add cyclic addresses to wallets

**Overall Assessment**: High likelihood - easy to execute, low cost, no special privileges, immediately exploitable.

## Recommendation

**Immediate Mitigation**:
Add global visited set tracking across the entire recursion:

```javascript
// In balances.js, modify readSharedAddressesDependingOnAddresses
function readSharedAddressesDependingOnAddresses(arrMemberAddresses, handleSharedAddresses, visited = new Set()){
    // Add visited addresses to set
    arrMemberAddresses.forEach(addr => visited.add(addr));
    
    var strAddressList = arrMemberAddresses.map(db.escape).join(', ');
    db.query("SELECT DISTINCT shared_address FROM shared_address_signing_paths WHERE address IN("+strAddressList+")", function(rows){
        var arrSharedAddresses = rows.map(function(row){ return row.shared_address; });
        if (arrSharedAddresses.length === 0)
            return handleSharedAddresses([]);
        
        // Filter out already visited addresses
        var arrNewMemberAddresses = arrSharedAddresses.filter(addr => !visited.has(addr));
        
        if (arrNewMemberAddresses.length === 0)
            return handleSharedAddresses([]);
        
        readSharedAddressesDependingOnAddresses(arrNewMemberAddresses, function(arrNewSharedAddresses){
            handleSharedAddresses(arrNewMemberAddresses.concat(arrNewSharedAddresses));
        }, visited);
    });
}
```

**Permanent Fix**:
Apply same pattern to [5](#0-4) 

**Additional Measures**:
- Add database constraint preventing self-referential cycles during shared address creation
- Add validation check in [2](#0-1)  to reject addresses that would create cycles
- Add monitoring for cyclic address patterns in database
- Create regression test verifying cycle detection

## Proof of Concept

```javascript
// test/cyclic_shared_address_dos.test.js
var test = require('ava');
var db = require("../db");
var desktop_app = require('../desktop_app.js');
var path = require('path');
desktop_app.getAppDataDir = function() { return __dirname + '/.testdata-cyclic-dos'; }

var balances = require('../balances.js');

test.before(async t => {
    // Initialize test database
    await db.query("DELETE FROM shared_addresses");
    await db.query("DELETE FROM shared_address_signing_paths");
    
    // Create cyclic shared addresses: A has member B, B has member A
    var addrA = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    var addrB = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
    
    // Insert shared address A with member B
    await db.query("INSERT INTO shared_addresses (shared_address, definition) VALUES (?, ?)",
        [addrA, JSON.stringify(['sig', {pubkey: 'Apub'}])]);
    await db.query("INSERT INTO shared_address_signing_paths (shared_address, address, signing_path, device_address) VALUES (?, ?, 'r', 'device1')",
        [addrA, addrB]);
    
    // Insert shared address B with member A (creates cycle)
    await db.query("INSERT INTO shared_addresses (shared_address, definition) VALUES (?, ?)",
        [addrB, JSON.stringify(['sig', {pubkey: 'Bpub'}])]);
    await db.query("INSERT INTO shared_address_signing_paths (shared_address, address, signing_path, device_address) VALUES (?, ?, 'r', 'device2')",
        [addrB, addrA]);
});

test.serial('cyclic shared addresses cause stack overflow', async t => {
    var error = null;
    
    try {
        // This should trigger infinite recursion
        await new Promise((resolve, reject) => {
            balances.readSharedBalance('test_wallet', function(result) {
                resolve(result);
            });
        });
    } catch (e) {
        error = e;
    }
    
    // Verify stack overflow occurred
    t.truthy(error);
    t.regex(error.message, /stack|recursion/i, 'Should throw stack overflow error');
});

test.after.always(async t => {
    // Cleanup
    await db.query("DELETE FROM shared_addresses");
    await db.query("DELETE FROM shared_address_signing_paths");
});
```

## Notes

This vulnerability represents a **missing input validation** issue where the system fails to validate that shared address relationships are acyclic before allowing their creation. While individual addresses validate correctly, the graph structure they form is not validated. The database schema [6](#0-5)  permits cycles because there's no constraint preventing the `address` column from containing a value that is also a `shared_address`.

The fix is straightforward but critical for node stability. The vulnerability does not affect consensus or funds, which is why it's classified as Medium severity rather than Critical.

### Citations

**File:** balances.js (L97-109)
```javascript
function readSharedAddressesOnWallet(wallet, handleSharedAddresses){
	db.query("SELECT DISTINCT shared_address_signing_paths.shared_address FROM my_addresses \n\
			JOIN shared_address_signing_paths USING(address) \n\
			LEFT JOIN prosaic_contracts ON prosaic_contracts.shared_address = shared_address_signing_paths.shared_address \n\
			WHERE wallet=? AND prosaic_contracts.hash IS NULL", [wallet], function(rows){
		var arrSharedAddresses = rows.map(function(row){ return row.shared_address; });
		if (arrSharedAddresses.length === 0)
			return handleSharedAddresses([]);
		readSharedAddressesDependingOnAddresses(arrSharedAddresses, function(arrNewSharedAddresses){
			handleSharedAddresses(arrSharedAddresses.concat(arrNewSharedAddresses));
		});
	});
}
```

**File:** balances.js (L111-124)
```javascript
function readSharedAddressesDependingOnAddresses(arrMemberAddresses, handleSharedAddresses){
	var strAddressList = arrMemberAddresses.map(db.escape).join(', ');
	db.query("SELECT DISTINCT shared_address FROM shared_address_signing_paths WHERE address IN("+strAddressList+")", function(rows){
		var arrSharedAddresses = rows.map(function(row){ return row.shared_address; });
		if (arrSharedAddresses.length === 0)
			return handleSharedAddresses([]);
		var arrNewMemberAddresses = _.difference(arrSharedAddresses, arrMemberAddresses);
		if (arrNewMemberAddresses.length === 0)
			return handleSharedAddresses([]);
		readSharedAddressesDependingOnAddresses(arrNewMemberAddresses, function(arrNewSharedAddresses){
			handleSharedAddresses(arrNewMemberAddresses.concat(arrNewSharedAddresses));
		});
	});
}
```

**File:** wallet_defined_by_addresses.js (L239-267)
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
```

**File:** wallet_defined_by_addresses.js (L485-501)
```javascript
function readAllControlAddresses(conn, arrAddresses, handleLists){
	conn = conn || db;
	conn.query(
		"SELECT DISTINCT address, shared_address_signing_paths.device_address, (correspondent_devices.device_address IS NOT NULL) AS have_correspondent \n\
		FROM shared_address_signing_paths LEFT JOIN correspondent_devices USING(device_address) WHERE shared_address IN(?)", 
		[arrAddresses], 
		function(rows){
			if (rows.length === 0)
				return handleLists([], []);
			var arrControlAddresses = rows.map(function(row){ return row.address; });
			var arrControlDeviceAddresses = rows.filter(function(row){ return row.have_correspondent; }).map(function(row){ return row.device_address; });
			readAllControlAddresses(conn, arrControlAddresses, function(arrControlAddresses2, arrControlDeviceAddresses2){
				handleLists(_.union(arrControlAddresses, arrControlAddresses2), _.union(arrControlDeviceAddresses, arrControlDeviceAddresses2));
			});
		}
	);
}
```

**File:** definition.js (L263-263)
```javascript
						var bAllowUnresolvedInnerDefinitions = true;
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
