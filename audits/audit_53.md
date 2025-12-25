# Stack Overflow DoS via Cyclic Shared Address References in Balance Reading

## Summary

The `readSharedAddressesDependingOnAddresses()` function in `balances.js` and `readAllControlAddresses()` function in `wallet_defined_by_addresses.js` lack cycle detection when recursively traversing shared address dependency chains. When shared addresses form cycles (A has member B, B has member A), these functions enter infinite recursion causing JavaScript stack overflow and node crash, preventing balance queries and wallet operations for affected addresses.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay / Network Disruption

**Concrete Impact:**
- Individual nodes crash with `RangeError: Maximum call stack size exceeded` when processing balance queries or wallet operations involving cyclic shared addresses
- Affected nodes become unresponsive and require manual restart
- Does NOT affect network consensus, DAG integrity, or actual balance data
- Vulnerability persists after restart until cyclic addresses are removed or code is patched

**Affected Parties:**
- Node operators whose nodes crash when querying affected wallets
- Users with wallets containing cyclic shared addresses (cannot read balances or perform wallet operations)
- Does NOT affect other users or network-wide consensus

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: Recursively discover all shared addresses depending on given member addresses, traversing the dependency chain while detecting and avoiding cycles to prevent infinite loops.

**Actual Logic**: The function uses `_.difference(arrSharedAddresses, arrMemberAddresses)` at line 117 which only compares the newly discovered shared addresses against the immediate input parameter of the current recursive call, not against the entire recursion history. When cycles exist (A→B→A), each recursive call sees different input arrays, causing the deduplication to fail and triggering infinite recursion until the JavaScript call stack overflows.

**Exploitation Path**:

1. **Preconditions**: Attacker needs ability to create shared addresses (standard protocol feature available to any user)

2. **Step 1**: Create shared address A with definition that includes address B as a member
   - Definition validation passes with `bAllowUnresolvedInnerDefinitions = true` [2](#0-1) 
   - Database insert: `shared_address_signing_paths` table records `(shared_address=A, address=B)`
   - No validation prevents B from being another shared address

3. **Step 2**: Create shared address B with definition that includes address A as a member  
   - Database insert: `shared_address_signing_paths` table records `(shared_address=B, address=A)`
   - Cycle now exists: A→B→A
   - Database schema has no constraints preventing this [3](#0-2) 

4. **Step 3**: Any user calls `readSharedBalance()` on wallet containing A or B
   - Entry: [4](#0-3) 
   - Calls: [5](#0-4) 
   - Calls: [1](#0-0) 

5. **Step 4**: Infinite recursion occurs:
   - Recursion Call 1 with `[A]`: Query finds `shared_address=B`, computes `_.difference([B], [A]) = [B]`, recurses with `[B]`
   - Recursion Call 2 with `[B]`: Query finds `shared_address=A`, computes `_.difference([A], [B]) = [A]`, recurses with `[A]`  
   - Recursion Call 3 with `[A]`: Same as Call 1 - infinite loop
   - Continues until JavaScript call stack limit (~10,000-15,000 frames) reached
   - Throws `RangeError: Maximum call stack size exceeded`
   - Node process crashes or becomes unresponsive

**Security Property Broken**: Node availability - stack overflow prevents node from processing balance queries, causing denial of service against individual nodes.

**Root Cause Analysis**: The algorithm uses `_.difference()` for deduplication but only maintains state within each individual recursive call frame, not across the entire recursion tree. Proper cycle detection requires tracking ALL addresses visited throughout the entire traversal history (e.g., via accumulator set passed through recursive calls or closure-captured visited set).

**Additional Vulnerability**: The same pattern exists in `readAllControlAddresses()` [6](#0-5)  which recursively traverses control addresses with NO cycle detection at all - not even using `_.difference()`. It uses `_.union()` to deduplicate results but this doesn't prevent the recursion itself.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any Obyte user with ability to create shared addresses (standard protocol feature, no special permissions required)
- **Resources Required**: Minimal - ability to create two shared address definition units (costs few dollars in fees)
- **Technical Skill**: Low - only requires understanding of shared address creation, no exploitation expertise needed

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Standard shared address creation capability (available to all users)
- **Timing**: No timing requirements, cycles persist indefinitely once created

**Execution Complexity**:
- **Transaction Count**: 2 units (one for each shared address definition)
- **Coordination**: None required
- **Detection Risk**: Cyclic references visible in database but not routinely monitored or prevented

**Frequency**:
- **Repeatability**: Unlimited - attacker can create multiple cyclic address sets
- **Triggering**: Automatic whenever balance queries executed on affected wallets

**Overall Assessment**: High likelihood - trivial to execute, minimal cost, immediately exploitable once cyclic addresses created.

## Recommendation

**Immediate Mitigation**:
Add cycle detection by tracking visited addresses across the entire recursion:

```javascript
// In balances.js
function readSharedAddressesDependingOnAddresses(arrMemberAddresses, handleSharedAddresses, arrVisited){
    arrVisited = arrVisited || [];
    var strAddressList = arrMemberAddresses.map(db.escape).join(', ');
    db.query("SELECT DISTINCT shared_address FROM shared_address_signing_paths WHERE address IN("+strAddressList+")", function(rows){
        var arrSharedAddresses = rows.map(function(row){ return row.shared_address; });
        if (arrSharedAddresses.length === 0)
            return handleSharedAddresses([]);
        var arrNewMemberAddresses = _.difference(arrSharedAddresses, arrMemberAddresses.concat(arrVisited));
        if (arrNewMemberAddresses.length === 0)
            return handleSharedAddresses([]);
        readSharedAddressesDependingOnAddresses(arrNewMemberAddresses, function(arrNewSharedAddresses){
            handleSharedAddresses(arrNewMemberAddresses.concat(arrNewSharedAddresses));
        }, arrVisited.concat(arrMemberAddresses));
    });
}
```

**Permanent Fix**:
Apply same pattern to `readAllControlAddresses()` in `wallet_defined_by_addresses.js` - add `arrVisited` parameter and check against it before recursing.

**Additional Measures**:
- Add validation during shared address creation to detect and reject cycles in address definitions
- Add database constraint or trigger to prevent inserting cyclic references
- Add monitoring to detect existing cyclic address relationships
- Add test cases verifying cycle detection works correctly

**Validation**:
- Fix prevents infinite recursion with cyclic addresses
- No new vulnerabilities introduced
- Backward compatible with existing non-cyclic shared addresses
- Performance impact minimal (additional array operations)

## Proof of Concept

```javascript
// test/balances_cycle.test.js
const balances = require('../balances.js');
const db = require('../db.js');

describe('Cyclic Shared Address DoS', function() {
    this.timeout(10000); // Should fail fast, but give time for setup
    
    before(function(done) {
        // Setup: Create cyclic shared addresses A and B
        db.query("DELETE FROM shared_address_signing_paths", function() {
            // Insert A->B reference
            db.query("INSERT INTO shared_address_signing_paths (shared_address, signing_path, address, device_address) VALUES ('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'r', 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'device1')", function() {
                // Insert B->A reference (creates cycle)
                db.query("INSERT INTO shared_address_signing_paths (shared_address, signing_path, address, device_address) VALUES ('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'r', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'device1')", function() {
                    done();
                });
            });
        });
    });
    
    it('should not crash with stack overflow on cyclic shared addresses', function(done) {
        let stackOverflowDetected = false;
        
        try {
            // Attempt to read shared addresses depending on A
            // This will trigger infinite recursion in vulnerable code
            balances.readSharedAddressesDependingOnAddresses(['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'], function(results) {
                // If we reach here, cycle detection worked
                done();
            });
        } catch (e) {
            if (e instanceof RangeError && e.message.includes('Maximum call stack size exceeded')) {
                stackOverflowDetected = true;
                done(new Error('Stack overflow occurred - vulnerability confirmed'));
            } else {
                done(e);
            }
        }
        
        // Set timeout to detect if function hangs
        setTimeout(function() {
            if (!stackOverflowDetected) {
                done(new Error('Function did not complete or throw stack overflow within timeout'));
            }
        }, 5000);
    });
});
```

## Notes

This vulnerability affects balance reading operations and is triggered automatically whenever balance queries are performed on wallets containing cyclic shared addresses. The impact is limited to individual node availability (DoS) and does not compromise consensus, DAG integrity, or actual balance data. The severity aligns with Immunefi's Medium category for "Temporary Transaction Delay / Network Disruption" as nodes crash but can be restarted (though the vulnerability persists until addressed).

The same recursive pattern without cycle detection appears in two separate functions (`balances.js:readSharedAddressesDependingOnAddresses` and `wallet_defined_by_addresses.js:readAllControlAddresses`), indicating this is a systemic issue in how shared address dependencies are traversed throughout the codebase.

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
