# Audit Report: Uncaught Exception in Divisible Asset Private Payment Duplicate Check

## Summary

The `validateAndSavePrivatePaymentChain()` function in `private_payment.js` throws an uncaught exception when reprocessing divisible asset private payments with multiple outputs. The duplicate check query omits `output_index` for divisible assets, returning all outputs. The code incorrectly interprets multiple rows as database corruption and throws inside an async callback, causing immediate Node.js process termination.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay / Node Availability

Individual nodes crash when processing resent divisible asset private payments. Each crash requires manual restart. While affected nodes are down, their users' private payments are delayed. Persistent attacks targeting multiple nodes could delay private payment processing network-wide for ≥1 hour, meeting Medium severity criteria.

## Finding Description

**Location**: `byteball/ocore/private_payment.js:70-71`, function `validateAndSavePrivatePaymentChain()`

**Intended Logic**: Duplicate check should detect already-processed private payments and return early via `ifOk()` callback.

**Actual Logic**: For divisible assets, the duplicate check query omits `output_index` from WHERE clause. When multiple outputs exist (standard for payment + change), the query returns multiple rows. Line 70 checks if `rows.length > 1`, and line 71 throws before proper duplicate handling at line 72 executes.

**Code Evidence**:

The duplicate check for divisible assets (NOT fixed_denominations) omits `output_index`: [1](#0-0) 

The throw occurs in async callback before proper duplicate handling: [2](#0-1) 

Divisible assets save multiple outputs with same `unit` and `message_index` but different `output_index`: [3](#0-2) 

**Exploitation Path**:

1. **Preconditions**: Node has processed a divisible asset private payment with 2+ outputs (payment + change)

2. **Step 1 - Initial Processing**:
   - Divisible asset private payment processed normally
   - Multiple outputs saved: output_index=0 (payment), output_index=1 (change)
   - All have same (unit, message_index) pair

3. **Step 2 - Resend Attack**:
   - Attacker resends identical private payment
   - Entry point: [4](#0-3) 
   - Unit existence check: [5](#0-4) 
   - Returns `ifKnown` callback, calls `validateAndSavePrivatePaymentChain()`: [6](#0-5) 

4. **Step 3 - Crash**:
   - Duplicate check query: `SELECT address FROM outputs WHERE unit=? AND message_index=?`
   - Returns 2 rows (both outputs from step 1)
   - Line 70: `if (rows.length > 1)` evaluates to true
   - Line 71: `throw Error(...)` executes inside async database callback
   - Database query callbacks call user callback directly without try-catch: [7](#0-6) 
   - Exception becomes uncaught (no global handlers in production code)
   - Node.js process terminates

5. **Step 4 - Impact**:
   - Node crashes, stops processing all transactions
   - Requires manual restart
   - Attacker can repeat after restart

**Security Property Broken**: Process availability and proper async error handling

**Root Cause Analysis**:
- Divisible assets inherently create multiple outputs per message (payment + change)
- Duplicate check incorrectly omits `output_index` for divisible assets, unlike indivisible assets which include it
- Code assumes `rows.length > 1` indicates database corruption
- Using synchronous `throw` in async callback bypasses error callback mechanism
- Line 70 check executes BEFORE line 72's proper duplicate handling

## Impact Explanation

**Affected Assets**: All divisible asset private payments (bytes and custom divisible assets)

**Damage Severity**:
- **Quantitative**: Single resend crashes one node in <1 second. No automatic recovery. Attacker can target multiple nodes.
- **Qualitative**: DoS against individual nodes' private payment processing. Node operators must manually monitor and restart.

**User Impact**:
- **Who**: Users running nodes that have processed divisible asset private payments with 2+ outputs
- **Conditions**: Exploitable immediately after any such private payment is processed
- **Recovery**: Manual node restart required per incident

**Systemic Risk**: Limited to private payment functionality. Main DAG consensus and public transactions continue normally. If attackers persistently target multiple nodes, aggregate private payment processing could be delayed ≥1 hour.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any network participant with P2P connectivity
- **Resources**: One divisible asset private payment (few dollars), ability to resend messages
- **Technical Skill**: Low - basic understanding of private payment protocol

**Preconditions**:
- **Network State**: Target node has processed divisible asset private payment with 2+ outputs (common scenario)
- **Attacker State**: One legitimate private payment (easily created)
- **Timing**: No special timing required

**Execution Complexity**: Single legitimate transaction, then resend the private payload

**Frequency**: Unlimited repeatability, per-node targeting

**Overall Assessment**: High likelihood - trivially exploitable with minimal resources

## Recommendation

**Immediate Mitigation**: Add `output_index` to duplicate check for divisible assets OR change line 70-71 to handle multiple rows gracefully as duplicates.

**Permanent Fix**:
```javascript
// File: byteball/ocore/private_payment.js
// Lines 70-71: Replace throw with proper duplicate handling

if (rows.length > 0 && rows[0].address){ 
    console.log("duplicate private payment "+params.join(', '));
    return transaction_callbacks.ifOk();
}
```

**Alternative Fix**: Include `output_index` in query for divisible assets (requires passing output_index from caller).

**Additional Measures**:
- Add try-catch wrapper around database query callbacks
- Add test case verifying resent private payments are handled gracefully
- Add monitoring for repeated private payment processing attempts

## Proof of Concept

```javascript
const test = require('ava');
const db = require('../db.js');
const network = require('../network.js');
const privatePayment = require('../private_payment.js');

test.serial('resending divisible asset private payment should not crash', async t => {
    // Setup: Create and process initial divisible asset private payment with 2 outputs
    const arrPrivateElements = [{
        unit: 'test_unit_hash',
        message_index: 0,
        payload: {
            asset: 'test_asset_hash',
            inputs: [/* valid inputs */],
            outputs: [
                { address: 'ADDR1', amount: 1000, blinding: 'blind1' },
                { address: 'ADDR2', amount: 500, blinding: 'blind2' } // change output
            ]
        }
    }];
    
    // Step 1: Process initial private payment (saves 2 outputs)
    await insertTestData(); // Inserts unit and 2 outputs into database
    
    // Step 2: Resend same private payment - should NOT crash
    await t.notThrowsAsync(async () => {
        return new Promise((resolve, reject) => {
            privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
                ifOk: resolve,
                ifError: reject
            });
        });
    });
});
```

## Notes

This vulnerability affects **divisible asset private payments only**. Indivisible assets (fixed_denominations) correctly include `output_index` in the duplicate check query and are not affected. The issue occurs because divisible assets commonly have multiple outputs per message (recipient + change), but the duplicate detection logic wasn't designed for this scenario.

The fix is straightforward: either handle multiple rows as duplicates (since all rows from the query represent the same private payment being reprocessed), or include `output_index` in the query to check each output individually.

### Citations

**File:** private_payment.js (L58-65)
```javascript
					var sql = "SELECT address FROM outputs WHERE unit=? AND message_index=?";
					var params = [headElement.unit, headElement.message_index];
					if (objAsset.fixed_denominations){
						if (!ValidationUtils.isNonnegativeInteger(headElement.output_index))
							return transaction_callbacks.ifError("no output index in head private element");
						sql += " AND output_index=?";
						params.push(headElement.output_index);
					}
```

**File:** private_payment.js (L66-79)
```javascript
					conn.query(
						sql, 
						params, 
						function(rows){
							if (rows.length > 1)
								throw Error("more than one output "+sql+' '+params.join(', '));
							if (rows.length > 0 && rows[0].address){ // we could have this output already but the address is still hidden
								console.log("duplicate private payment "+params.join(', '));
								return transaction_callbacks.ifOk();
							}
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
						}
					);
```

**File:** divisible_asset.js (L32-38)
```javascript
			for (var j=0; j<payload.outputs.length; j++){
				var output = payload.outputs[j];
				conn.addQuery(arrQueries, 
					"INSERT INTO outputs (unit, message_index, output_index, address, amount, blinding, asset) VALUES (?,?,?,?,?,?,?)",
					[unit, message_index, j, output.address, parseInt(output.amount), output.blinding, payload.asset]
				);
			}
```

**File:** network.js (L2114-2120)
```javascript
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
```

**File:** network.js (L2151-2153)
```javascript
		ifKnown: function(){
			//assocUnitsInWork[unit] = true;
			privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
```

**File:** joint_storage.js (L29-35)
```javascript
	db.query("SELECT sequence, main_chain_index FROM units WHERE unit=?", [unit], function(rows){
		if (rows.length > 0){
			var row = rows[0];
			if (row.sequence === 'final-bad' && row.main_chain_index !== null && row.main_chain_index < storage.getMinRetrievableMci()) // already stripped
				return callbacks.ifNew();
			storage.setUnitIsKnown(unit);
			return callbacks.ifKnown();
```

**File:** sqlite_pool.js (L111-133)
```javascript
				new_args.push(function(err, result){
					//console.log("query done: "+sql);
					if (err){
						console.error("\nfailed query:", new_args);
						throw Error(err+"\n"+sql+"\n"+new_args[1].map(function(param){ if (param === null) return 'null'; if (param === undefined) return 'undefined'; return param;}).join(', '));
					}
					// note that sqlite3 sets nonzero this.changes even when rows were matched but nothing actually changed (new values are same as old)
					// this.changes appears to be correct for INSERTs despite the documentation states the opposite
					if (!bSelect && !bCordova)
						result = {affectedRows: this.changes, insertId: this.lastID};
					if (bSelect && bCordova) // note that on android, result.affectedRows is 1 even when inserted many rows
						result = result.rows || [];
					//console.log("changes="+this.changes+", affected="+result.affectedRows);
					var consumed_time = Date.now() - start_ts;
				//	var profiler = require('./profiler.js');
				//	if (!bLoading)
				//		profiler.add_result(sql.substr(0, 40).replace(/\n/, '\\n'), consumed_time);
					if (consumed_time > 25)
						console.log("long query took "+consumed_time+"ms:\n"+new_args.filter(function(a, i){ return (i<new_args.length-1); }).join(", ")+"\nload avg: "+require('os').loadavg().join(', '));
					self.start_ts = 0;
					self.currentQuery = null;
					last_arg(result);
				});
```
