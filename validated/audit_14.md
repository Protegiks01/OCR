# AUDIT REPORT

## Title
Uncaught Exception in Divisible Asset Private Payment Duplicate Check Causes Node Crash

## Summary
The `validateAndSavePrivatePaymentChain()` function in `private_payment.js` throws an uncaught exception when reprocessing divisible asset private payments with multiple outputs. The duplicate check query omits `output_index` for divisible assets, returning all outputs instead of one. The code incorrectly interprets multiple rows as database corruption and throws synchronously inside an async database callback, causing immediate Node.js process termination.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay

Any network participant can crash individual nodes by resending legitimate divisible asset private payments. Each crashed node requires manual restart. While public DAG transactions continue processing normally, private payment functionality is disrupted on affected nodes. Persistent attacks targeting multiple nodes can delay private payment processing for extended periods (≥1 hour).

## Finding Description

**Location**: `byteball/ocore/private_payment.js:58-79`, function `validateAndSavePrivatePaymentChain()`

**Intended Logic**: The duplicate check should detect already-processed private payments and gracefully return via the `ifOk()` callback to prevent reprocessing.

**Actual Logic**: For divisible assets (`!objAsset.fixed_denominations`), the duplicate check query omits `output_index` from the WHERE clause. [1](#0-0)  When multiple outputs exist (normal for divisible assets with payment + change), the query returns multiple rows. The code then throws an uncaught exception before the duplicate-handling logic can execute. [2](#0-1) 

**Code Evidence**:

The vulnerability spans multiple components:

1. **Duplicate check query construction**: For divisible assets, `output_index` is not included in the WHERE clause [1](#0-0) 

2. **Exception thrown before duplicate handling**: The throw at line 70 executes BEFORE the graceful duplicate check at line 72 [3](#0-2) 

3. **Multiple outputs saved per divisible payment**: Each output gets a unique `output_index` (0, 1, 2...) [4](#0-3) 

4. **Entry point when unit already known**: When a unit is recognized as known, `validateAndSavePrivatePaymentChain()` is called directly [5](#0-4) 

5. **No try-catch in database callback invocation**: The user callback is invoked without exception handling [6](#0-5) 

6. **Unit known check**: Returns `ifKnown` when unit exists in database [7](#0-6) 

**Exploitation Path**:

1. **Preconditions**: Attacker creates legitimate divisible asset private payment with 2+ outputs (e.g., payment + change to self)

2. **Step 1 - Initial Processing**: 
   - Attacker sends private payment to victim node via P2P network
   - Node processes via `network.handleOnlinePrivatePayment()`
   - `checkIfNewUnit()` returns `ifNew` (first time seeing this unit)
   - Duplicate check query returns 0 rows
   - All outputs saved successfully with different `output_index` values (0, 1, 2...)

3. **Step 2 - Resend Attack**:
   - Attacker resends identical private payment message
   - `checkIfNewUnit()` recognizes unit as known (exists in database)
   - Calls `privatePayment.validateAndSavePrivatePaymentChain()` directly
   - Duplicate check query: `SELECT address FROM outputs WHERE unit=? AND message_index=?`
   - Query returns multiple rows (all outputs from Step 1)

4. **Step 3 - Crash**:
   - Condition `if (rows.length > 1)` evaluates to true
   - `throw Error("more than one output...")` executes inside database callback
   - Exception is uncaught (callback invoked at `sqlite_pool.js:132` with no try-catch wrapper)
   - No global `uncaughtException` handler exists in codebase
   - Node.js process terminates with unhandled exception

5. **Step 4 - Impact**:
   - Victim node stops processing all transactions
   - Requires manual operator intervention to restart
   - Attacker can repeat indefinitely against same node or target multiple nodes

**Security Property Broken**: Process availability and proper async error handling. Errors in async callbacks must be returned via the callback mechanism (`transaction_callbacks.ifError()`), not thrown where they become uncaught exceptions.

**Root Cause Analysis**:
- Divisible assets naturally have multiple outputs with different `output_index` values
- Duplicate check for divisible assets omits `output_index`, causing query to return ALL outputs for that unit+message_index pair
- Code assumes `rows.length > 1` indicates database corruption, but this is normal behavior after first save
- Using `throw` in an async callback bypasses Node.js error handling and crashes the process
- The throw executes BEFORE the duplicate handling logic at line 72, preventing graceful recovery

## Impact Explanation

**Affected Assets**: All divisible asset private payments (bytes and custom divisible assets)

**Damage Severity**:
- **Quantitative**: Single attack crashes one node in <1 second. Attacker can target multiple nodes. Each node requires manual restart with no automatic recovery mechanism.
- **Qualitative**: Denial of service against private payment functionality. Node operators must manually monitor and restart affected nodes. Repeated attacks can cause sustained disruption.

**User Impact**:
- **Who**: Users attempting to send/receive divisible asset private payments through affected nodes
- **Conditions**: Exploitable whenever a node has processed any divisible asset private payment with multiple outputs (common scenario with change outputs)
- **Recovery**: Manual node restart per incident

**Systemic Risk**: If attackers persistently target multiple nodes, private payment functionality could be unavailable for extended periods (≥1 hour, potentially ≥1 day). However, public (non-private) transaction processing continues normally on the main DAG network.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any network participant with P2P connectivity to target nodes
- **Resources Required**: One legitimate divisible asset private payment transaction with 2+ outputs, ability to resend P2P messages
- **Technical Skill**: Low - requires only basic understanding of private payment message structure and ability to resend network messages

**Preconditions**:
- **Network State**: Target node must have previously processed a divisible asset private payment with multiple outputs (common occurrence in normal operation)
- **Attacker State**: Needs access to one divisible asset private payment payload with 2+ outputs
- **Timing**: No timing constraints - attack succeeds at any point after initial processing

**Execution Complexity**:
- **Transaction Count**: One legitimate transaction initially, then resend the private payload
- **Coordination**: Single attacker, no coordination needed
- **Detection Risk**: Low - resends appear as legitimate network message retries

**Frequency**:
- **Repeatability**: Unlimited - attacker can crash same node repeatedly after each restart
- **Scale**: Per-node - each node must be targeted individually, but can be done in parallel

**Overall Assessment**: High likelihood - trivially exploitable with minimal resources and no special access required.

## Recommendation

**Immediate Mitigation**:
Include `output_index` in the duplicate check query for divisible assets, or handle multiple rows gracefully by checking if any has the address revealed:

```javascript
// Option 1: Include output_index (requires headElement to have it)
// Option 2: Check if any row already has address revealed
if (rows.length > 0 && rows.some(row => row.address)) {
    console.log("duplicate private payment "+params.join(', '));
    return transaction_callbacks.ifOk();
}
```

**Permanent Fix**:
Replace `throw Error()` with proper error callback to handle errors gracefully in async context:

```javascript
if (rows.length > 1 && !objAsset.fixed_denominations) {
    // Multiple outputs are normal for divisible assets
    // Check if any already has address revealed
    if (rows.some(row => row.address)) {
        console.log("duplicate private payment "+params.join(', '));
        return transaction_callbacks.ifOk();
    }
}
```

**Additional Measures**:
- Wrap database callback invocations in try-catch blocks in `sqlite_pool.js` to prevent uncaught exceptions
- Add test case verifying that resending divisible asset private payments with multiple outputs doesn't crash the node
- Add monitoring to detect and alert on uncaught exceptions before they cause crashes

## Proof of Concept

```javascript
// Test file: test/private_payment_crash.test.js
const network = require('../network.js');
const composer = require('../composer.js');
const divisible_asset = require('../divisible_asset.js');

describe('Divisible Asset Private Payment Resend', function() {
    it('should not crash when resending private payment with multiple outputs', function(done) {
        // Setup: Create divisible asset private payment with 2 outputs
        const privatePayment = {
            unit: 'test_unit_hash_12345',
            message_index: 0,
            payload: {
                asset: 'divisible_asset_hash',
                outputs: [
                    { address: 'RECIPIENT_ADDRESS', amount: 1000, blinding: 'blind1' },
                    { address: 'CHANGE_ADDRESS', amount: 500, blinding: 'blind2' }
                ],
                inputs: [/* valid inputs */]
            }
        };
        
        // Step 1: First send - should succeed and save both outputs
        network.handleOnlinePrivatePayment(ws, [privatePayment], false, {
            ifQueued: () => {},
            ifAccepted: (unit) => {
                console.log('First send accepted:', unit);
                
                // Step 2: Resend same payment - should NOT crash
                // This should trigger the bug: query returns 2 rows, throws exception
                network.handleOnlinePrivatePayment(ws, [privatePayment], false, {
                    ifQueued: () => {},
                    ifAccepted: (unit) => {
                        console.log('Second send accepted as duplicate:', unit);
                        done(); // Test passes - no crash
                    },
                    ifValidationError: (unit, error) => {
                        // Expected: graceful error or duplicate detection
                        // Actual: Node crashes before this callback executes
                        console.log('Validation error (acceptable):', error);
                        done();
                    }
                });
            },
            ifValidationError: (unit, error) => {
                done(new Error('First send failed: ' + error));
            }
        });
        
        // If Node crashes due to uncaught exception, this test fails
    });
});
```

## Notes

This vulnerability is a clear implementation bug where the code makes incorrect assumptions about database query results. The invariant check `if (rows.length > 1)` is designed to catch database corruption, but for divisible assets without `output_index` in the query, returning multiple rows is the expected and correct behavior when a payment has multiple outputs (payment + change).

The critical flaw is using `throw` in an async callback context. Node.js async callbacks are not wrapped in try-catch by the database pool implementation, so any thrown exception becomes uncaught and terminates the process. The proper pattern is to return errors via the callback mechanism (`transaction_callbacks.ifError()`), which would allow graceful error handling and prevent crashes.

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

**File:** divisible_asset.js (L32-37)
```javascript
			for (var j=0; j<payload.outputs.length; j++){
				var output = payload.outputs[j];
				conn.addQuery(arrQueries, 
					"INSERT INTO outputs (unit, message_index, output_index, address, amount, blinding, asset) VALUES (?,?,?,?,?,?,?)",
					[unit, message_index, j, output.address, parseInt(output.amount), output.blinding, payload.asset]
				);
```

**File:** network.js (L2150-2166)
```javascript
	joint_storage.checkIfNewUnit(unit, {
		ifKnown: function(){
			//assocUnitsInWork[unit] = true;
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
