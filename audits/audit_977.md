## Title
Partial Private Payment Chain Acceptance Due to Silent Foreign Key Constraint Failures

## Summary
The `validateAndSavePrivatePaymentChain()` function in `byteball/ocore/indivisible_asset.js` uses `INSERT OR IGNORE` for database operations, which silently suppresses foreign key constraint violations. When validation succeeds for all elements but some elements reference addresses not present in the `addresses` table (e.g., after definition changes), the INSERT operations fail silently, resulting in partial chain data being committed to the database with broken references between inputs and outputs.

## Impact
**Severity**: Medium
**Category**: Unintended behavior / Database integrity violation

## Finding Description

**Location**: `byteball/ocore/indivisible_asset.js` (function: `validateAndSavePrivatePaymentChain`, lines 223-281)

**Intended Logic**: The function should atomically save all elements of a private payment chain within a database transaction. If any element fails to save, the entire transaction should be rolled back via the callback at line 45 of `private_payment.js`, ensuring no partial state is committed. [1](#0-0) 

**Actual Logic**: The saving phase uses `INSERT OR IGNORE` pattern, which silently suppresses database constraint violations including foreign key failures. When validation passes for all elements but saving fails for some elements due to missing foreign key references (particularly addresses not in the `addresses` table), the queries complete "successfully" without errors, causing `callbacks.ifOk()` to be invoked and the transaction to commit with partial state. [2](#0-1) 

**Code Evidence**:

The saving loop uses `INSERT OR IGNORE` for inputs: [3](#0-2) 

And for outputs: [4](#0-3) 

The database schema enforces foreign key constraints on addresses: [5](#0-4) 

Foreign keys are explicitly enabled in SQLite: [6](#0-5) 

Addresses are only inserted under specific conditions in writer.js: [7](#0-6) 

**Exploitation Path**:

1. **Preconditions**: 
   - Attacker controls an address with an initial definition
   - The address has been used previously (exists in `addresses` table)

2. **Step 1**: Attacker posts a `definition_chg` message to change the address definition
   - The definition_chash no longer equals the address
   - Future units using this address will not re-insert it into the `addresses` table (per condition at line 152 of writer.js)

3. **Step 2**: Attacker creates a unit authored by the modified address
   - The unit is valid and saved to the database
   - But the address is NOT inserted into `addresses` table because `definition_chash !== author.address` and the unit may not have `content_hash`

4. **Step 3**: Attacker creates a private payment chain where an intermediate element references this address as `input_address`
   - Validation passes: the address IS among unit authors (check at line 146-147 of indivisible_asset.js succeeds)
   - The chain is sent to the victim

5. **Step 4**: Victim processes the private payment chain
   - `parsePrivatePaymentChain` validates all elements successfully
   - `validateAndSavePrivatePaymentChain` begins saving within a transaction
   - For the element with the problematic address:
     - `INSERT OR IGNORE INTO inputs` fails silently due to foreign key constraint: `FOREIGN KEY (address) REFERENCES addresses(address)`
     - No input row is inserted for this element
     - But `INSERT INTO outputs` and `UPDATE outputs` succeed (no address foreign key on outputs table)
   - `async.series` completes without errors
   - `callbacks.ifOk()` is called, triggering `COMMIT`
   - **Result**: Element has outputs saved but no inputs saved in the database

**Security Property Broken**: 
- **Invariant 20 (Database Referential Integrity)**: Orphaned output records exist without corresponding input records
- **Invariant 21 (Transaction Atomicity)**: Partial chain state is committed despite some elements failing to save completely

**Root Cause Analysis**: 
The use of `INSERT OR IGNORE` breaks atomicity by converting database constraint violations into silent no-ops. The validation phase confirms addresses are among unit authors but doesn't verify addresses exist in the `addresses` table. The database schema enforces this via foreign keys, but `INSERT OR IGNORE` suppresses the error, allowing the transaction to commit with inconsistent state.

## Impact Explanation

**Affected Assets**: Indivisible asset private payments

**Damage Severity**:
- **Quantitative**: Any private payment chain can be partially saved, affecting chain integrity
- **Qualitative**: Database contains broken chain references where outputs exist without corresponding inputs

**User Impact**:
- **Who**: Recipients of private payment chains involving addresses with changed definitions
- **Conditions**: When processing private payments for indivisible assets after an address has undergone definition changes
- **Recovery**: Requires manual database cleanup or rejection of the incomplete chain

**Systemic Risk**: 
- Balance calculation errors when traversing incomplete chains
- Provenance tracking failures for affected assets
- Potential for exploitation in complex multi-party transactions
- Cascading failures if other code assumes chain integrity

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user capable of posting definition_chg messages
- **Resources Required**: Minimal - ability to send transactions and private payments
- **Technical Skill**: Medium - requires understanding of address definitions and private payments

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Must have an address with ability to change definition
- **Timing**: Can execute at any time after definition change

**Execution Complexity**:
- **Transaction Count**: 3-4 transactions (initial use, definition change, new unit, private payment)
- **Coordination**: Single attacker, no coordination required
- **Detection Risk**: Low - appears as legitimate private payment

**Frequency**:
- **Repeatability**: High - can be repeated for any address with definition changes
- **Scale**: Limited to specific edge case but affects chain integrity

**Overall Assessment**: Medium likelihood - requires specific preconditions (definition change) but is technically straightforward to execute once conditions are met

## Recommendation

**Immediate Mitigation**: Add explicit validation to verify all addresses exist in the `addresses` table before attempting to save

**Permanent Fix**: 
1. Remove `INSERT OR IGNORE` from inputs/outputs insertion in private payment saving
2. Add pre-save validation to ensure all referenced addresses exist in the `addresses` table
3. Let database foreign key constraints fail loudly, triggering proper error handling and rollback

**Code Changes**:

File: `byteball/ocore/indivisible_asset.js`
Function: `validateAndSavePrivatePaymentChain`

The fix should:
1. Add address existence check before building queries: [8](#0-7) 

2. Change INSERT queries to fail on constraint violations: [9](#0-8) 

3. Remove `db.getIgnore()` to let errors propagate properly

**Additional Measures**:
- Add database integrity check to detect and repair existing broken chains
- Add monitoring to alert on foreign key constraint violations during private payment processing
- Consider adding a unique constraint or check to prevent saving chains with missing inputs

**Validation**:
- Verify fix prevents partial chain saves when addresses are missing
- Ensure proper error propagation triggers rollback
- Test with definition change scenarios
- Confirm no performance degradation

## Notes

This vulnerability specifically affects **indivisible assets only**. The divisible asset implementation in `divisible_asset.js` does not use `INSERT OR IGNORE` and would throw errors on foreign key constraint violations, preventing partial saves. [10](#0-9) 

The validation at line 146-147 of `indivisible_asset.js` ensures addresses are among unit authors, but doesn't guarantee they're in the `addresses` table due to the conditional insertion logic in `writer.js`. Definition changes create a scenario where `definition_chash !== author.address`, causing addresses to be skipped during unit saving, leading to foreign key failures during private payment chain saving. [11](#0-10)

### Citations

**File:** private_payment.js (L42-56)
```javascript
				conn.query("BEGIN", function(){
					var transaction_callbacks = {
						ifError: function(err){
							conn.query("ROLLBACK", function(){
								conn.release();
								callbacks.ifError(err);
							});
						},
						ifOk: function(){
							conn.query("COMMIT", function(){
								conn.release();
								callbacks.ifOk();
							});
						}
					};
```

**File:** indivisible_asset.js (L146-147)
```javascript
			if (!objPartialUnit.authors.some(function(author){ return (author.address === input_address); }))
				return callbacks.ifError("input address not found among unit authors");
```

**File:** indivisible_asset.js (L223-281)
```javascript
function validateAndSavePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	parsePrivatePaymentChain(conn, arrPrivateElements, {
		ifError: callbacks.ifError,
		ifOk: function(bAllStable){
			console.log("saving private chain "+JSON.stringify(arrPrivateElements));
			profiler.start();
			var arrQueries = [];
			for (var i=0; i<arrPrivateElements.length; i++){
				var objPrivateElement = arrPrivateElements[i];
				var payload = objPrivateElement.payload;
				var input_address = objPrivateElement.input_address;
				var input = payload.inputs[0];
				var is_unique = objPrivateElement.bStable ? 1 : null; // unstable still have chances to become nonserial therefore nonunique
				if (!input.type) // transfer
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO inputs \n\
						(unit, message_index, input_index, src_unit, src_message_index, src_output_index, asset, denomination, address, type, is_unique) \n\
						VALUES (?,?,?,?,?,?,?,?,?,'transfer',?)", 
						[objPrivateElement.unit, objPrivateElement.message_index, 0, input.unit, input.message_index, input.output_index, 
						payload.asset, payload.denomination, input_address, is_unique]);
				else if (input.type === 'issue')
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO inputs \n\
						(unit, message_index, input_index, serial_number, amount, asset, denomination, address, type, is_unique) \n\
						VALUES (?,?,?,?,?,?,?,?,'issue',?)", 
						[objPrivateElement.unit, objPrivateElement.message_index, 0, input.serial_number, input.amount, 
						payload.asset, payload.denomination, input_address, is_unique]);
				else
					throw Error("neither transfer nor issue after validation");
				var is_serial = objPrivateElement.bStable ? 1 : null; // initPrivatePaymentValidationState already checks for non-serial
				var outputs = payload.outputs;
				for (var output_index=0; output_index<outputs.length; output_index++){
					var output = outputs[output_index];
					console.log("inserting output "+JSON.stringify(output));
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO outputs \n\
						(unit, message_index, output_index, amount, output_hash, asset, denomination) \n\
						VALUES (?,?,?,?,?,?,?)",
						[objPrivateElement.unit, objPrivateElement.message_index, output_index, 
						output.amount, output.output_hash, payload.asset, payload.denomination]);
					var fields = "is_serial=?";
					var params = [is_serial];
					if (output_index === objPrivateElement.output_index){
						var is_spent = (i===0) ? 0 : 1;
						fields += ", is_spent=?, address=?, blinding=?";
						params.push(is_spent, objPrivateElement.output.address, objPrivateElement.output.blinding);
					}
					params.push(objPrivateElement.unit, objPrivateElement.message_index, output_index);
					conn.addQuery(arrQueries, "UPDATE outputs SET "+fields+" WHERE unit=? AND message_index=? AND output_index=? AND is_spent=0", params);
				}
			}
		//	console.log("queries: "+JSON.stringify(arrQueries));
			async.series(arrQueries, function(){
				profiler.stop('save');
				callbacks.ifOk();
			});
		}
	});
}
```

**File:** initial-db/byteball-sqlite.sql (L304-310)
```sql
	PRIMARY KEY (unit, message_index, input_index),
	UNIQUE  (src_unit, src_message_index, src_output_index, is_unique), -- UNIQUE guarantees there'll be no double spend for type=transfer
	UNIQUE  (type, from_main_chain_index, address, is_unique), -- UNIQUE guarantees there'll be no double spend for type=hc/witnessing
	UNIQUE  (asset, denomination, serial_number, address, is_unique), -- UNIQUE guarantees there'll be no double issue
	FOREIGN KEY (unit) REFERENCES units(unit),
	CONSTRAINT inputsBySrcUnit FOREIGN KEY (src_unit) REFERENCES units(unit),
	CONSTRAINT inputsByAddress FOREIGN KEY (address) REFERENCES addresses(address),
```

**File:** sqlite_pool.js (L51-51)
```javascript
			connection.query("PRAGMA foreign_keys = 1", function(){
```

**File:** writer.js (L149-156)
```javascript
				// actually inserts only when the address is first used.
				// if we change keys and later send a unit signed by new keys, the address is not inserted. 
				// Its definition_chash was updated before when we posted change-definition message.
				if (definition_chash === author.address)
					conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO addresses (address) VALUES(?)", [author.address]);
			}
			else if (objUnit.content_hash)
				conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO addresses (address) VALUES(?)", [author.address]);
```

**File:** divisible_asset.js (L34-37)
```javascript
				conn.addQuery(arrQueries, 
					"INSERT INTO outputs (unit, message_index, output_index, address, amount, blinding, asset) VALUES (?,?,?,?,?,?,?)",
					[unit, message_index, j, output.address, parseInt(output.amount), output.blinding, payload.asset]
				);
```
