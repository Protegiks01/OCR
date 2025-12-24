# Race Condition in Indivisible Asset Serial Number Assignment Causes Node Crashes

## Summary

A race condition in `indivisible_asset.js` function `issueNextCoin()` allows concurrent issuance from separate nodes to assign duplicate serial numbers to indivisible assets. The non-atomic read-modify-write pattern, combined with validation logic that accepts conflicting units with `is_unique=NULL`, enables both units to be stored. When both units stabilize, the attempt to set `is_unique=1` violates the database UNIQUE constraint, causing all affected nodes to crash with an unhandled exception.

## Impact

**Severity**: High  
**Category**: Network Disruption / Permanent Ledger Inconsistency

All nodes that receive both conflicting units will crash during stabilization with no error handling. The duplicate serial numbers permanently violate the uniqueness invariant for indivisible assets. Affected nodes enter a crash loop on restart when attempting to process the duplicate stabilization. Manual database intervention or a protocol hard fork is required to resolve the inconsistency.

## Finding Description

**Location**: Multiple files - `byteball/ocore/indivisible_asset.js:500-572`, `byteball/ocore/main_chain.js:1260-1264`, `byteball/ocore/validation.js:2042-2063`

### Intended Logic

Each indivisible asset issuance should receive a unique serial number by atomically reading and incrementing `max_issued_serial_number` in the `asset_denominations` table. Serial numbers must never be reused to maintain the uniqueness guarantee.

### Actual Logic

**Non-Atomic Serial Number Assignment:**
The `issueNextCoin()` function performs a non-atomic three-step process:
1. Read `max_issued_serial_number` from database [1](#0-0) 
2. Calculate new `serial_number` in JavaScript memory [2](#0-1) 
3. Update counter in database [3](#0-2) 

**Node-Local Counter State:**
The `max_issued_serial_number` counter is only updated during local issuance and is never synchronized from incoming network units, meaning each node maintains an independent counter.

**Cross-Node Mutex Limitation:**
The mutex lock only serializes operations on the same node [4](#0-3) . Different nodes have separate mutex instances, allowing concurrent execution.

### Exploitation Path

**Preconditions:**
- Indivisible asset with `issued_by_definer_only=true` exists
- Definer controls wallet on two separate nodes (Node A and Node B)
- Current `max_issued_serial_number` = 5

**Step 1-2: Concurrent Issuance with Duplicate Serial Numbers**

Both nodes independently execute the issuance flow, reading the same counter value and assigning `serial_number = 6` [5](#0-4) 

**Step 3: Validation Accepts Conflicting Units**

When a third node receives both units, the validation detects them as conflicting based on matching serial numbers [6](#0-5) . The `checkForDoublespends()` function intentionally accepts conflicts on different DAG branches by setting `is_unique=NULL` for both inputs [7](#0-6) 

**Step 4: Database UNIQUE Constraint Allows NULL Values**

The database schema defines: `UNIQUE (asset, denomination, serial_number, address, is_unique)` [8](#0-7) 

Since SQL treats `NULL != NULL` in UNIQUE constraints, both rows with `is_unique=NULL` can coexist despite having identical (asset, denomination, serial_number, address) values.

**Step 5: Node Crash During Stabilization**

When both units stabilize, the main chain stabilization process executes:
```
UPDATE inputs SET is_unique=1 WHERE unit=?
``` [9](#0-8) 

The first unit's UPDATE succeeds. The second unit's UPDATE violates the UNIQUE constraint because now two rows would have `is_unique=1` with identical (asset, denomination, serial_number, address). **Critically, the callback has no error parameter**, causing the database exception to propagate unhandled, crashing the node.

### Security Property Broken

- **Invariant: Indivisible Serial Uniqueness** - Each serial number must be issued exactly once
- **Invariant: Transaction Atomicity** - Serial number read-modify-write sequence must be atomic

### Root Cause Analysis

1. **Local Counter State**: `max_issued_serial_number` is per-node, not network-synchronized
2. **Non-Atomic Operations**: Read-calculate-write operations are separated, creating race window  
3. **Cross-Node Mutex Limitation**: Mutex only protects single-node operations
4. **Validation Design**: Intentionally accepts conflicts with `is_unique=NULL` for unstable units
5. **Missing Error Handling**: Stabilization UPDATE lacks error parameter in callback

## Likelihood Explanation

**Attacker Profile:**
- Asset definer who controls the definer address
- Resources: Two nodes running simultaneously with same wallet
- Technical skill: Moderate - requires triggering concurrent compositions

**Preconditions:**
- Normal network operation
- Definer operates multiple nodes (common for redundancy)
- Concurrent issuance attempts within overlapping time window

**Execution Complexity:**
- Two concurrent issuance transactions
- No special network position required
- Appears as normal activity until stabilization fails

**Overall Assessment**: Medium likelihood - requires infrastructure setup but straightforward execution. Impact severity (node crashes + permanent inconsistency) justifies High severity classification.

## Recommendation

**Immediate Mitigation:**

Modify the stabilization UPDATE to include error handling:
```javascript
// File: byteball/ocore/main_chain.js
// Line: 1261
conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], function(err){
    if (err) {
        console.error("Failed to set is_unique=1 for unit "+row.unit+": "+err);
        // Mark unit as final-bad instead of crashing
        return conn.query("UPDATE units SET sequence='final-bad' WHERE unit=?", [row.unit], cb);
    }
    storage.assocStableUnits[row.unit].sequence = 'good';
    cb();
});
```

**Permanent Fix:**

Implement network-wide serial number coordination or add validation to reject units with duplicate serial numbers before storage:

```javascript
// File: byteball/ocore/validation.js
// In checkInputDoubleSpend function, reject duplicate issue inputs immediately:
if (rows.length > 0 && type === 'issue') {
    return cb("Duplicate serial number detected for indivisible asset issuance");
}
```

**Additional Measures:**
- Add database migration to detect and mark existing duplicates as final-bad
- Add monitoring for duplicate serial number detection
- Add test case for concurrent issuance scenario

## Notes

This vulnerability affects indivisible assets where the definer can control multiple nodes. While the precondition requires the definer to operate multiple nodes simultaneously, this is a realistic scenario for high-availability setups. The crash occurs during normal stabilization operations, making recovery difficult without manual database intervention or a coordinated network upgrade.

The vulnerability arises from the combination of: (1) per-node counter state, (2) validation design that accepts conflicts on different DAG branches, and (3) missing error handling in the stabilization process. Any one of these could be addressed to prevent the node crash, though fixing the root atomicity issue would be the most comprehensive solution.

### Citations

**File:** indivisible_asset.js (L500-572)
```javascript
		function issueNextCoin(remaining_amount){
			console.log("issuing a new coin");
			if (remaining_amount <= 0)
				throw Error("remaining amount is "+remaining_amount);
			var issuer_address = objAsset.issued_by_definer_only ? objAsset.definer_address : arrAddresses[0];
			var can_issue_condition = objAsset.cap ? "max_issued_serial_number=0" : "1";
			conn.query(
				"SELECT denomination, count_coins, max_issued_serial_number FROM asset_denominations \n\
				WHERE asset=? AND "+can_issue_condition+" AND denomination<=? \n\
				ORDER BY denomination DESC LIMIT 1", 
				[asset, remaining_amount+tolerance_plus], 
				function(rows){
					if (rows.length === 0)
						return onDone(NOT_ENOUGH_FUNDS_ERROR_MESSAGE);
					var row = rows[0];
					if (!!row.count_coins !== !!objAsset.cap)
						throw Error("invalid asset cap and count_coins");
					var denomination = row.denomination;
					var serial_number = row.max_issued_serial_number+1;
					var count_coins_to_issue = row.count_coins || Math.floor((remaining_amount+tolerance_plus)/denomination);
					var issue_amount = count_coins_to_issue * denomination;
					conn.query(
						"UPDATE asset_denominations SET max_issued_serial_number=max_issued_serial_number+1 WHERE denomination=? AND asset=?", 
						[denomination, asset], 
						function(){
							var input = {
								type: 'issue',
								serial_number: serial_number,
								amount: issue_amount
							};
							if (bMultiAuthored)
								input.address = issuer_address;
							var amount_to_use;
							var change_amount;
							if (issue_amount > remaining_amount + tolerance_plus){
								amount_to_use = Math.floor((remaining_amount + tolerance_plus)/denomination) * denomination;
								change_amount = issue_amount - amount_to_use;
							}
							else
								amount_to_use = issue_amount;
							var payload = {
								asset: asset,
								denomination: denomination,
								inputs: [input],
								outputs: createOutputs(amount_to_use, change_amount)
							};
							var objPayloadWithProof = {payload: payload, input_address: issuer_address};
							if (objAsset.is_private){
								var spend_proof = objectHash.getBase64Hash({
									asset: asset,
									address: issuer_address,
									serial_number: serial_number, // need to avoid duplicate spend proofs when issuing uncapped coins
									denomination: denomination,
									amount: input.amount
								});
								var objSpendProof = {
									spend_proof: spend_proof
								};
								if (bMultiAuthored)
									objSpendProof.address = issuer_address;
								objPayloadWithProof.spend_proof = objSpendProof;
							}
							arrPayloadsWithProofs.push(objPayloadWithProof);
							accumulated_amount += amount_to_use;
							console.log("payloads with proofs: "+JSON.stringify(arrPayloadsWithProofs));
							if (accumulated_amount >= amount - tolerance_minus && accumulated_amount <= amount + tolerance_plus)
								return onDone(null, arrPayloadsWithProofs);
							pickNextCoin(amount - accumulated_amount);
						}
					);
				}
			);
		}
```

**File:** composer.js (L289-289)
```javascript
			mutex.lock(arrFromAddresses.map(function(from_address){ return 'c-'+from_address; }), function(unlock){
```

**File:** validation.js (L2042-2050)
```javascript
					function acceptDoublespends(cb3){
						console.log("--- accepting doublespend on unit "+objUnit.unit);
						var sql = "UPDATE inputs SET is_unique=NULL WHERE "+doubleSpendWhere+
							" AND (SELECT is_stable FROM units WHERE units.unit=inputs.unit)=0";
						if (!(objAsset && objAsset.is_private)){
							objValidationState.arrAdditionalQueries.push({sql: sql, params: doubleSpendVars});
							objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
							return cb3();
						}
```

**File:** validation.js (L2134-2136)
```javascript
					if (objAsset){
						doubleSpendWhere += " AND serial_number=?";
						doubleSpendVars.push(input.serial_number);
```

**File:** initial-db/byteball-sqlite.sql (L307-307)
```sql
	UNIQUE  (asset, denomination, serial_number, address, is_unique), -- UNIQUE guarantees there'll be no double issue
```

**File:** main_chain.js (L1260-1264)
```javascript
								if (sequence === 'good')
									conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], function(){
										storage.assocStableUnits[row.unit].sequence = 'good';
										cb();
									});
```
