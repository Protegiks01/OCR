# AUDIT REPORT

## Title
Uncaught Exception in Divisible Asset Private Payment Duplicate Check Causes Node Crash

## Summary
The `validateAndSavePrivatePaymentChain()` function in `private_payment.js` throws an uncaught exception when reprocessing divisible asset private payments with multiple outputs. The duplicate check query omits `output_index` for divisible assets, returning all outputs instead of one. The code incorrectly interprets multiple rows as database corruption and throws synchronously inside an async database callback, causing immediate Node.js process termination. [1](#0-0) 

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay

Any network participant can crash individual nodes by resending legitimate divisible asset private payments. Each crashed node requires manual restart. While public DAG transactions continue processing normally, private payment functionality is disrupted on affected nodes. Persistent attacks targeting multiple nodes can delay private payment processing for extended periods (≥1 hour).

## Finding Description

**Location**: `byteball/ocore/private_payment.js:58-79`, function `validateAndSavePrivatePaymentChain()`

**Intended Logic**: The duplicate check should detect already-processed private payments and gracefully return via the `ifOk()` callback to prevent reprocessing.

**Actual Logic**: For divisible assets (`!objAsset.fixed_denominations`), the duplicate check query omits `output_index` from the WHERE clause. [2](#0-1)  When multiple outputs exist (normal for divisible assets with payment + change), the query returns multiple rows. The code then throws an uncaught exception before the duplicate-handling logic can execute. [3](#0-2) 

**Code Evidence**:

The vulnerability spans multiple components:

1. **Duplicate check query construction**: For divisible assets, `output_index` is not included in the WHERE clause (lines 60-64 only add it for `fixed_denominations`) [4](#0-3) 

2. **Exception thrown before duplicate handling**: The throw at line 70 executes BEFORE the graceful duplicate check at line 72 [3](#0-2) 

3. **Multiple outputs saved per divisible payment**: Each output gets a unique `output_index` (0, 1, 2...) [5](#0-4) 

4. **Entry point when unit already known**: When a unit is recognized as known, `validateAndSavePrivatePaymentChain()` is called directly [6](#0-5) 

5. **No try-catch in database callback invocation**: The user callback is invoked without exception handling [7](#0-6) 

6. **Unit known check**: Returns `ifKnown` when unit exists in database [8](#0-7) 

**Exploitation Path**:

1. **Preconditions**: Attacker creates legitimate divisible asset private payment with 2+ outputs (e.g., payment + change to self)

2. **Step 1 - Initial Processing**: 
   - Attacker sends private payment to victim node via P2P network
   - Node processes via `network.handleOnlinePrivatePayment()`
   - `checkIfNewUnit()` returns `ifNew` (first time seeing this unit) [9](#0-8) 
   - Duplicate check query returns 0 rows
   - All outputs saved successfully with different `output_index` values (0, 1, 2...) [5](#0-4) 

3. **Step 2 - Resend Attack**:
   - Attacker resends identical private payment message
   - `checkIfNewUnit()` recognizes unit as known (exists in database) [10](#0-9) 
   - Calls `privatePayment.validateAndSavePrivatePaymentChain()` directly [11](#0-10) 
   - Duplicate check query: `SELECT address FROM outputs WHERE unit=? AND message_index=?` (no `output_index` for divisible assets) [2](#0-1) 
   - Query returns multiple rows (all outputs from Step 1)

4. **Step 3 - Crash**:
   - Condition `if (rows.length > 1)` evaluates to true [12](#0-11) 
   - `throw Error("more than one output...")` executes inside database callback
   - Exception is uncaught (callback invoked without try-catch wrapper) [13](#0-12) 
   - No global `uncaughtException` handler exists in codebase (verified by grep search showing no handlers in production code, only in test files)
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

**Affected Assets**: All divisible asset private payments (including blackbytes and custom divisible assets)

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
Add `output_index` to the duplicate check query for divisible assets to match the behavior of indivisible assets:

```javascript
// In private_payment.js, lines 58-65
var sql = "SELECT address FROM outputs WHERE unit=? AND message_index=?";
var params = [headElement.unit, headElement.message_index];
if (objAsset.fixed_denominations){
    if (!ValidationUtils.isNonnegativeInteger(headElement.output_index))
        return transaction_callbacks.ifError("no output index in head private element");
    sql += " AND output_index=?";
    params.push(headElement.output_index);
} else {
    // ADD THIS: For divisible assets, also check output_index if provided
    if (ValidationUtils.isNonnegativeInteger(headElement.output_index)) {
        sql += " AND output_index=?";
        params.push(headElement.output_index);
    }
}
```

**Permanent Fix**:
Replace the synchronous `throw` with proper async error callback:

```javascript
// In private_payment.js, line 70-71
if (rows.length > 1)
    return transaction_callbacks.ifError("more than one output "+sql+' '+params.join(', '));
```

**Additional Measures**:
- Add test case verifying resent divisible asset private payments are handled gracefully
- Review all database callbacks for similar synchronous throws
- Consider adding a global uncaughtException handler for graceful degradation (though this should not be the primary fix)

**Validation**:
- Fix prevents node crash when processing duplicate divisible asset private payments
- No breaking changes to existing functionality
- Backward compatible with existing database schema

## Proof of Concept

```javascript
const test = require('ava');
const db = require('../db');
const privatePayment = require('../private_payment.js');
const storage = require('../storage.js');

test.serial('divisible asset private payment duplicate causes crash', async t => {
    // Setup: Create a mock divisible asset with multiple outputs already saved
    const mockUnit = 'test_unit_hash_123';
    const mockMessageIndex = 0;
    const mockAsset = 'test_divisible_asset';
    
    // Simulate that this unit was already processed and has 2 outputs saved
    await new Promise((resolve, reject) => {
        db.query(
            "INSERT INTO outputs (unit, message_index, output_index, address, amount, asset) VALUES (?,?,?,?,?,?)",
            [mockUnit, mockMessageIndex, 0, 'TEST_ADDRESS_1', 1000, mockAsset],
            () => {
                db.query(
                    "INSERT INTO outputs (unit, message_index, output_index, address, amount, asset) VALUES (?,?,?,?,?,?)",
                    [mockUnit, mockMessageIndex, 1, 'TEST_ADDRESS_2', 500, mockAsset],
                    resolve
                );
            }
        );
    });
    
    // Mock the asset as divisible (fixed_denominations = false)
    const mockAssetInfo = {
        fixed_denominations: false,
        asset: mockAsset
    };
    
    // Create a private payment element that would be resent
    const arrPrivateElements = [{
        unit: mockUnit,
        message_index: mockMessageIndex,
        payload: {
            asset: mockAsset,
            outputs: [
                { address: 'TEST_ADDRESS_1', amount: 1000 },
                { address: 'TEST_ADDRESS_2', amount: 500 }
            ]
        }
    }];
    
    // Attempt to reprocess - this should throw uncaught exception
    let crashed = false;
    let errorMessage = '';
    
    try {
        await new Promise((resolve, reject) => {
            // Mock storage.readAsset to return our divisible asset
            const originalReadAsset = storage.readAsset;
            storage.readAsset = (conn, asset, lastBall, callback) => {
                callback(null, mockAssetInfo);
            };
            
            privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
                ifOk: () => {
                    storage.readAsset = originalReadAsset;
                    resolve();
                },
                ifError: (err) => {
                    storage.readAsset = originalReadAsset;
                    reject(new Error(err));
                },
                ifWaitingForChain: () => {
                    storage.readAsset = originalReadAsset;
                    reject(new Error('Unexpected waiting for chain'));
                }
            });
        });
    } catch (err) {
        if (err.message.includes('more than one output')) {
            crashed = true;
            errorMessage = err.message;
        }
    }
    
    // The vulnerability is that the throw happens synchronously in the callback,
    // causing an uncaught exception instead of calling ifError
    t.true(crashed, 'Should throw uncaught exception when multiple outputs found');
    t.true(errorMessage.includes('more than one output'), 'Error message should indicate multiple outputs');
});
```

**Notes**:
- This vulnerability specifically affects divisible assets, which do not include `output_index` in the duplicate check query
- Indivisible assets (with `fixed_denominations: true`) are not affected as they properly include `output_index` in the WHERE clause
- The root cause is the assumption that multiple rows indicate database corruption, when it's actually normal for divisible assets with multiple outputs
- The immediate crash occurs because the `throw` statement executes inside an async database callback without try-catch protection
- This is a process availability issue, not a consensus or fund safety issue, hence Medium severity per Immunefi criteria

### Citations

**File:** private_payment.js (L58-79)
```javascript
					var sql = "SELECT address FROM outputs WHERE unit=? AND message_index=?";
					var params = [headElement.unit, headElement.message_index];
					if (objAsset.fixed_denominations){
						if (!ValidationUtils.isNonnegativeInteger(headElement.output_index))
							return transaction_callbacks.ifError("no output index in head private element");
						sql += " AND output_index=?";
						params.push(headElement.output_index);
					}
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

**File:** divisible_asset.js (L32-37)
```javascript
			for (var j=0; j<payload.outputs.length; j++){
				var output = payload.outputs[j];
				conn.addQuery(arrQueries, 
					"INSERT INTO outputs (unit, message_index, output_index, address, amount, blinding, asset) VALUES (?,?,?,?,?,?,?)",
					[unit, message_index, j, output.address, parseInt(output.amount), output.blinding, payload.asset]
				);
```

**File:** network.js (L2150-2167)
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
		},
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

**File:** joint_storage.js (L21-38)
```javascript
function checkIfNewUnit(unit, callbacks) {
	if (storage.isKnownUnit(unit))
		return callbacks.ifKnown();
	if (assocUnhandledUnits[unit])
		return callbacks.ifKnownUnverified();
	var error = assocKnownBadUnits[unit];
	if (error)
		return callbacks.ifKnownBad(error);
	db.query("SELECT sequence, main_chain_index FROM units WHERE unit=?", [unit], function(rows){
		if (rows.length > 0){
			var row = rows[0];
			if (row.sequence === 'final-bad' && row.main_chain_index !== null && row.main_chain_index < storage.getMinRetrievableMci()) // already stripped
				return callbacks.ifNew();
			storage.setUnitIsKnown(unit);
			return callbacks.ifKnown();
		}
		callbacks.ifNew();
	});
```
