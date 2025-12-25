# Audit Report: Uncaught Exception in Divisible Asset Private Payment Duplicate Check

## Summary

The `validateAndSavePrivatePaymentChain()` function in `private_payment.js` throws an uncaught exception when reprocessing divisible asset private payments with multiple outputs. The duplicate check query omits `output_index` for divisible assets, causing it to return all outputs for the same unit and message. The code incorrectly interprets multiple rows as database corruption and throws inside an async callback, terminating the Node.js process.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay / Node Availability

Individual nodes crash when processing resent divisible asset private payments. Each crash requires manual restart, causing downtime that delays private payment processing for that node's users. Persistent attacks targeting multiple nodes could delay private payment processing network-wide for ≥1 hour, meeting Immunefi's Medium severity criteria.

## Finding Description

**Location**: `byteball/ocore/private_payment.js:70-71`, function `validateAndSavePrivatePaymentChain()`

**Intended Logic**: The duplicate check should detect already-processed private payments and return early via the `ifOk()` callback at line 74.

**Actual Logic**: For divisible assets, the duplicate check query omits `output_index` from the WHERE clause. When multiple outputs exist (standard for payment + change), the query returns multiple rows. Line 70 checks `if (rows.length > 1)`, and line 71 throws an exception before the proper duplicate handling at line 72 executes.

**Code Evidence**:

The duplicate check for divisible assets (NOT `fixed_denominations`) omits `output_index`: [1](#0-0) 

The throw occurs in async callback before proper duplicate handling: [2](#0-1) 

Divisible assets save multiple outputs with same `unit` and `message_index` but different `output_index`: [3](#0-2) 

**Exploitation Path**:

1. **Preconditions**: Node has processed a divisible asset private payment with 2+ outputs (e.g., payment to recipient + change back to sender).

2. **Step 1 - Initial Processing**:
   - Divisible asset private payment processed normally
   - Multiple outputs saved: `output_index=0` (payment), `output_index=1` (change)
   - All share the same `(unit, message_index)` pair

3. **Step 2 - Resend Attack**:
   - Attacker resends identical private payment message
   - Entry point: [4](#0-3) 
   - Unit existence check: [5](#0-4) 
   - Returns `ifKnown` callback, calls `validateAndSavePrivatePaymentChain()`: [6](#0-5) 

4. **Step 3 - Crash**:
   - Duplicate check query executes: `SELECT address FROM outputs WHERE unit=? AND message_index=?`
   - Returns 2 rows (both outputs from step 1)
   - Line 70: `if (rows.length > 1)` evaluates to `true`
   - Line 71: `throw Error(...)` executes inside async database callback
   - Database wrapper calls user callback without try-catch: [7](#0-6) 
   - Exception becomes uncaught (no global handlers exist)
   - Node.js process terminates immediately

5. **Step 4 - Impact**:
   - Node crashes, stops processing all transactions
   - Requires manual restart
   - Attacker can repeat after restart, causing repeated downtime

**Security Property Broken**: Process availability and proper async error handling. The code violates the expectation that duplicate private payments are handled gracefully without process termination.

**Root Cause Analysis**:
- Divisible assets inherently create multiple outputs per message (payment + change)
- Duplicate check incorrectly omits `output_index` for divisible assets, unlike indivisible assets which include it conditionally
- Code assumes `rows.length > 1` indicates database corruption rather than expected multiple outputs
- Using synchronous `throw` in async callback bypasses the error callback mechanism
- Line 70 check executes BEFORE line 72's proper duplicate handling can run

## Impact Explanation

**Affected Assets**: All divisible asset private payments (native bytes and custom divisible assets)

**Damage Severity**:
- **Quantitative**: Single resend crashes one node in <1 second with no automatic recovery. Attacker can target multiple nodes sequentially or concurrently.
- **Qualitative**: DoS against individual nodes' private payment processing capability. Node operators must manually monitor and restart affected nodes.

**User Impact**:
- **Who**: Users running nodes that have processed divisible asset private payments with 2+ outputs
- **Conditions**: Exploitable immediately after any such private payment is processed (common scenario)
- **Recovery**: Manual node restart required per incident

**Systemic Risk**: Limited to private payment functionality. Main DAG consensus and public transactions continue normally on the affected node until process termination. If attackers persistently target multiple nodes, aggregate private payment processing could be delayed ≥1 hour network-wide.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any network participant with P2P connectivity
- **Resources**: One divisible asset private payment (minimal cost), ability to resend P2P messages
- **Technical Skill**: Low - basic understanding of private payment protocol and message resending

**Preconditions**:
- **Network State**: Target node has processed divisible asset private payment with 2+ outputs (common scenario for any payment with change)
- **Attacker State**: One legitimate private payment (easily obtainable)
- **Timing**: No special timing required

**Execution Complexity**:
- **Transaction Count**: One legitimate transaction, then resend the private payload
- **Coordination**: None required
- **Detection Risk**: Low - appears as normal duplicate message initially

**Frequency**:
- **Repeatability**: Unlimited (attacker can repeat after each node restart)
- **Scale**: Per-node targeting (each node with relevant history is vulnerable)

**Overall Assessment**: High likelihood - trivially exploitable with minimal resources and no special timing requirements.

## Recommendation

**Immediate Mitigation**:

Replace the throw with proper error callback to prevent process termination and allow the duplicate handling logic at line 72 to execute.

**Permanent Fix**:

Add `output_index` to the duplicate check query for divisible assets, consistent with indivisible asset handling. Modify the query construction to include output_index for both asset types when available.

**Additional Measures**:
- Add test case verifying resent divisible asset private payments with multiple outputs don't crash the process
- Add monitoring to detect repeated duplicate private payment processing attempts
- Consider logging duplicate attempts for security analysis

**Validation**:
- Fix prevents process crashes on legitimate duplicate private payments
- No performance degradation (query remains efficient with additional WHERE clause parameter)
- Backward compatible (existing valid private payments continue processing correctly)

## Proof of Concept

```javascript
const test = require('ava');
const db = require('../db.js');
const privatePayment = require('../private_payment.js');
const divisibleAsset = require('../divisible_asset.js');

test.serial('resending divisible asset private payment with multiple outputs should not crash', async t => {
    // Setup: Create and process initial divisible asset private payment with 2 outputs
    const arrPrivateElements = [{
        unit: 'test_unit_hash_12345678901234567890123456789012345678901234',
        message_index: 0,
        payload: {
            asset: 'test_asset_hash_1234567890123456789012345678901234567890',
            inputs: [{
                unit: 'input_unit_hash_123456789012345678901234567890123456789',
                message_index: 0,
                output_index: 0,
                amount: 200,
                serial_number: 1
            }],
            outputs: [
                { address: 'RECIPIENT_ADDRESS', amount: 100, blinding: 'blinding1' },
                { address: 'CHANGE_ADDRESS', amount: 100, blinding: 'blinding2' }
            ]
        }
    }];

    // First processing - should succeed
    await new Promise((resolve, reject) => {
        privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
            ifOk: resolve,
            ifError: reject,
            ifWaitingForChain: () => reject(new Error('Should not wait for chain'))
        });
    });

    // Resend same private payment - should handle gracefully without crashing
    const processExited = await new Promise((resolve) => {
        const originalExit = process.exit;
        let exited = false;
        
        process.exit = () => {
            exited = true;
            process.exit = originalExit;
            resolve(true);
        };

        privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
            ifOk: () => {
                process.exit = originalExit;
                resolve(false);
            },
            ifError: (err) => {
                process.exit = originalExit;
                resolve(false);
            },
            ifWaitingForChain: () => {
                process.exit = originalExit;
                resolve(false);
            }
        });

        // Timeout after 1 second
        setTimeout(() => {
            process.exit = originalExit;
            if (!exited) resolve(false);
        }, 1000);
    });

    t.false(processExited, 'Process should not exit when reprocessing divisible asset private payment with multiple outputs');
});
```

## Notes

This vulnerability specifically affects divisible asset private payments because:

1. **Divisible assets naturally have multiple outputs** - A typical payment includes both the payment amount to the recipient and change back to the sender, creating 2+ outputs with the same `(unit, message_index)` but different `output_index` values.

2. **Query inconsistency** - The duplicate check for indivisible assets (`fixed_denominations`) correctly includes `output_index` in the WHERE clause, but divisible assets omit it. This inconsistency suggests the logic was not designed to handle divisible asset multi-output scenarios.

3. **Proper duplicate handling exists but is unreachable** - Line 72 contains the correct logic to handle duplicates gracefully by checking if the address is already populated and calling `ifOk()`. However, the throw at line 71 prevents this code from ever executing when multiple outputs exist.

4. **Database wrapper propagation** - The SQLite connection wrapper doesn't catch exceptions thrown in user callbacks, allowing them to propagate as uncaught exceptions that terminate the process.

The fix is straightforward: either remove the `rows.length > 1` check (allowing line 72's proper handling to execute) or add `output_index` to the query for divisible assets to ensure only one row is ever returned.

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

**File:** private_payment.js (L69-75)
```javascript
						function(rows){
							if (rows.length > 1)
								throw Error("more than one output "+sql+' '+params.join(', '));
							if (rows.length > 0 && rows[0].address){ // we could have this output already but the address is still hidden
								console.log("duplicate private payment "+params.join(', '));
								return transaction_callbacks.ifOk();
							}
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

**File:** network.js (L2113-2114)
```javascript
// handles one private payload and its chain
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
```

**File:** network.js (L2150-2152)
```javascript
	joint_storage.checkIfNewUnit(unit, {
		ifKnown: function(){
			//assocUnitsInWork[unit] = true;
```

**File:** network.js (L2153-2166)
```javascript
			privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
				ifOk: function(){
					//delete assocUnitsInWork[unit];
					callbacks.ifAccepted(unit);
					eventBus.emit("new_my_transactions", [unit]);
				},
				ifError: function(error){
					//delete assocUnitsInWork[unit];
					callbacks.ifValidationError(unit, error);
				},
				ifWaitingForChain: function(){
					savePrivatePayment();
				}
			});
```

**File:** sqlite_pool.js (L111-116)
```javascript
				new_args.push(function(err, result){
					//console.log("query done: "+sql);
					if (err){
						console.error("\nfailed query:", new_args);
						throw Error(err+"\n"+sql+"\n"+new_args[1].map(function(param){ if (param === null) return 'null'; if (param === undefined) return 'undefined'; return param;}).join(', '));
					}
```
