# Stack Overflow DoS via Cyclic Shared Address References in Balance Reading

## Summary

The `readSharedAddressesDependingOnAddresses()` function in `balances.js` lacks cycle detection when recursively traversing shared address dependency chains. When shared addresses form cycles (A has member B, B has member A), the function enters infinite recursion causing stack overflow and node crash, preventing balance queries for affected wallets.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay / Network Disruption

**Affected Assets**: Node availability, user ability to read balances for wallets containing cyclic shared addresses

**Damage Severity**:
- Node crashes when attempting to read balances for affected wallets
- Does not corrupt DAG, consensus, or actual balances
- Affects individual node operations, not network-wide consensus
- Recovery requires node restart; vulnerability persists until cyclic addresses removed or code patched

**User Impact**:
- **Who**: Node operators and users with wallets containing cyclic shared addresses
- **Conditions**: Automatically triggered when balance reading functions are called
- **Recovery**: Node restart required; issue persists until addressed

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: Recursively discover all shared addresses depending on given member addresses, traversing the dependency chain while avoiding infinite loops.

**Actual Logic**: Uses `_.difference(arrSharedAddresses, arrMemberAddresses)` at line 117, which only compares against the immediate input array, not the entire recursion history. With cycles (A→B→A), each recursive call sees different input arrays, causing infinite recursion until JavaScript stack overflow.

**Code Evidence**: [1](#0-0) 

**Exploitation Path**:

1. **Preconditions**: Attacker creates two shared addresses that reference each other as members

2. **Step 1**: Create shared address A with definition including member address B
   - Database insert: `shared_address_signing_paths(shared_address=A, address=B)`
   - Validation passes because `bAllowUnresolvedInnerDefinitions = true` [2](#0-1) 

3. **Step 2**: Create shared address B with definition including member address A  
   - Database insert: `shared_address_signing_paths(shared_address=B, address=A)`
   - Cycle now exists: A→B→A
   - No database constraints prevent this: [3](#0-2) 

4. **Step 3**: Any user calls `readSharedBalance()` on wallet containing A or B
   - Triggers: [4](#0-3) 
   - Which calls: [5](#0-4) 
   - Which calls: [1](#0-0) 

5. **Step 4**: Infinite recursion occurs:
   - Call 1 with [A]: Queries `WHERE address IN(A)`, finds B, computes `_.difference([B], [A]) = [B]`, recurses with [B]
   - Call 2 with [B]: Queries `WHERE address IN(B)`, finds A, computes `_.difference([A], [B]) = [A]`, recurses with [A]  
   - Call 3: Same as Call 1 - infinite loop continues
   - Hits JavaScript stack limit (~10,000-15,000 calls), throws `RangeError: Maximum call stack size exceeded`
   - Node crashes or becomes unresponsive

**Security Property Broken**: Node availability - stack overflow prevents balance reading operations, causing DoS against individual nodes.

**Root Cause Analysis**: Algorithm uses `_.difference()` for deduplication but only maintains state within each individual recursive call, not across the entire recursion tree. Proper cycle detection requires tracking ALL addresses visited throughout the entire traversal (e.g., accumulator set passed through all recursive calls or closure-captured visited set).

**Additional Vulnerability**: The same pattern exists in `readAllControlAddresses()`: [6](#0-5) , which also recursively traverses member addresses without cycle detection.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any Obyte user with ability to create shared addresses (standard protocol feature)
- **Resources**: Minimal - ability to create two shared address definitions  
- **Technical Skill**: Low - only requires understanding shared address creation

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Standard shared address creation capability
- **Timing**: No timing requirements

**Execution Complexity**:
- **Transaction Count**: 2 units (one per shared address)
- **Coordination**: None required
- **Detection Risk**: Cyclic references visible in database but not routinely monitored

**Overall Assessment**: High likelihood - easy to execute, low cost, immediately exploitable once created.

## Recommendation

**Immediate Mitigation**:
Implement visited address tracking in recursive functions:

```javascript
// File: byteball/ocore/balances.js
// Function: readSharedAddressesDependingOnAddresses

function readSharedAddressesDependingOnAddresses(arrMemberAddresses, handleSharedAddresses){
	readSharedAddressesDependingOnAddressesWithHistory(arrMemberAddresses, [], handleSharedAddresses);
}

function readSharedAddressesDependingOnAddressesWithHistory(arrMemberAddresses, arrVisited, handleSharedAddresses){
	var strAddressList = arrMemberAddresses.map(db.escape).join(', ');
	db.query("SELECT DISTINCT shared_address FROM shared_address_signing_paths WHERE address IN("+strAddressList+")", function(rows){
		var arrSharedAddresses = rows.map(function(row){ return row.shared_address; });
		if (arrSharedAddresses.length === 0)
			return handleSharedAddresses([]);
		var arrNewMemberAddresses = _.difference(arrSharedAddresses, arrMemberAddresses, arrVisited);
		if (arrNewMemberAddresses.length === 0)
			return handleSharedAddresses([]);
		readSharedAddressesDependingOnAddressesWithHistory(
			arrNewMemberAddresses, 
			arrVisited.concat(arrMemberAddresses), 
			function(arrNewSharedAddresses){
				handleSharedAddresses(arrNewMemberAddresses.concat(arrNewSharedAddresses));
			}
		);
	});
}
```

**Permanent Fix**: Apply same pattern to `readAllControlAddresses()` in `wallet_defined_by_addresses.js`

**Additional Measures**:
- Add database-level cycle detection during shared address creation
- Add test case verifying cyclic references are handled gracefully
- Add monitoring for cyclic address patterns in database

**Validation**:
- Fix prevents infinite recursion with cyclic references
- Performance impact minimal (additional array comparison overhead)
- Backward compatible with existing non-cyclic shared addresses

## Proof of Concept

```javascript
// Test: test/cyclic_shared_addresses.test.js
const db = require('../db.js');
const balances = require('../balances.js');

describe('Cyclic shared address handling', function() {
	before(async function() {
		// Setup test database
		await db.query("DELETE FROM shared_address_signing_paths");
		await db.query("DELETE FROM shared_addresses");
		
		// Create cyclic references
		await db.query(
			"INSERT INTO shared_addresses (shared_address, definition) VALUES (?, ?)",
			['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', JSON.stringify(['sig', {pubkey: 'A'.repeat(44)}])]
		);
		await db.query(
			"INSERT INTO shared_addresses (shared_address, definition) VALUES (?, ?)",
			['BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', JSON.stringify(['sig', {pubkey: 'B'.repeat(44)}])]
		);
		await db.query(
			"INSERT INTO shared_address_signing_paths (shared_address, signing_path, address, member_signing_path, device_address) VALUES (?, ?, ?, ?, ?)",
			['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'r.0', 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'r', '0'.repeat(33)]
		);
		await db.query(
			"INSERT INTO shared_address_signing_paths (shared_address, signing_path, address, member_signing_path, device_address) VALUES (?, ?, ?, ?, ?)",
			['BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'r.0', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'r', '0'.repeat(33)]
		);
	});

	it('should not crash with cyclic shared address references', function(done) {
		this.timeout(5000); // Should complete quickly or timeout
		
		let crashed = false;
		const originalExit = process.exit;
		process.exit = () => { crashed = true; };
		
		try {
			// This will cause infinite recursion with current code
			balances.readSharedBalance('test_wallet', function(result) {
				process.exit = originalExit;
				if (crashed) {
					done(new Error('Node crashed due to stack overflow'));
				} else {
					done();
				}
			});
		} catch (e) {
			process.exit = originalExit;
			if (e.message && e.message.includes('Maximum call stack size exceeded')) {
				done(new Error('Stack overflow occurred: ' + e.message));
			} else {
				done(e);
			}
		}
	});
});
```

**Notes**:
- Both `balances.js` and `wallet_defined_by_addresses.js` contain functions vulnerable to cyclic reference DoS
- Database schema permits cyclic shared address member relationships
- Definition validation allows unresolved inner definitions, enabling separate creation of mutually-referencing addresses
- No existing cycle detection in balance reading code paths
- Impact limited to node availability; does not affect funds or consensus

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

**File:** balances.js (L126-160)
```javascript
function readSharedBalance(wallet, handleBalance){
	var assocBalances = {};
	readSharedAddressesOnWallet(wallet, function(arrSharedAddresses){
		if (arrSharedAddresses.length === 0)
			return handleBalance(assocBalances);
		var strAddressList = arrSharedAddresses.map(db.escape).join(', ');
		db.query(
			"SELECT asset, address, is_stable, SUM(amount) AS balance \n\
			FROM outputs CROSS JOIN units USING(unit) \n\
			WHERE is_spent=0 AND sequence='good' AND address IN("+strAddressList+") \n\
			GROUP BY asset, address, is_stable \n\
			UNION ALL \n\
			SELECT NULL AS asset, address, 1 AS is_stable, SUM(amount) AS balance FROM witnessing_outputs \n\
			WHERE is_spent=0 AND address IN("+strAddressList+") GROUP BY address \n\
			UNION ALL \n\
			SELECT NULL AS asset, address, 1 AS is_stable, SUM(amount) AS balance FROM headers_commission_outputs \n\
			WHERE is_spent=0 AND address IN("+strAddressList+") GROUP BY address",
			function(rows){
				for (var i=0; i<rows.length; i++){
					var row = rows[i];
					var asset = row.asset || "base";
					if (!assocBalances[asset])
						assocBalances[asset] = {};
					if (!assocBalances[asset][row.address])
						assocBalances[asset][row.address] = {stable: 0, pending: 0};
					assocBalances[asset][row.address][row.is_stable ? 'stable' : 'pending'] += row.balance;
				}
				for (var asset in assocBalances)
					for (var address in assocBalances[asset])
						assocBalances[asset][address].total = assocBalances[asset][address].stable + assocBalances[asset][address].pending;
				handleBalance(assocBalances);
			}
		);
	});
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
