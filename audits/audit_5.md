# NoVulnerability found for this question.

## Analysis

While the technical analysis of the race condition is partially correct, this claim **fails the impact validation** under Immunefi's scope for Obyte.

### Technical Assessment

**Verified Claims:**
- Race condition exists between archiving SELECT and UPDATE queries [1](#0-0) 
- Light clients set `is_unique=NULL` for all inputs [2](#0-1) 
- UNIQUE constraint includes `is_unique` column [3](#0-2) 
- Archiving doesn't acquire write mutex [4](#0-3) 
- Writer acquires write mutex [5](#0-4) 

### Critical Flaw in Impact Assessment

**The claim fails because validation prevents actual exploitation:**

Double-spend validation checks the `inputs` table directly, NOT the `is_spent` flag [6](#0-5) . When a unit tries to spend an output:

1. Validation queries: `SELECT ... FROM inputs ... WHERE` (checking if input already exists)
2. If input exists in `inputs` table, validation detects the conflict
3. Transaction is **rejected** or marked as double-spend

Therefore:
- ❌ **No theft occurs** - validation prevents double-spending regardless of `is_spent` value
- ❌ **No fund loss** - outputs cannot actually be spent twice
- ❌ **No balance inflation** - incorrectly-shown balance cannot be withdrawn
- ❌ **No transaction delays ≥1 hour** - individual transactions fail but users can retry immediately with different outputs

### Immunefi Scope Compliance

**Critical Severity** (NOT met):
- ❌ Network shutdown >24h
- ❌ Permanent chain split  
- ❌ Direct fund loss/theft
- ❌ Permanent fund freeze

**High Severity** (NOT met):
- ❌ Permanent fund freeze

**Medium Severity** (NOT met):
- ❌ Temporary delay ≥1 day or ≥1 hour
- ❌ Unintended AA behavior

### Conclusion

This is a **database consistency issue** that causes cosmetic balance display errors and individual transaction failures, but no actual security impact under Immunefi's defined scope. The validation layer [7](#0-6)  provides defense-in-depth that prevents exploitation even when the `is_spent` cache is incorrect.

**Notes:** While this could be improved from a code quality perspective, it does not constitute a valid security vulnerability under the Immunefi Obyte bug bounty program criteria. The multi-layered validation prevents any actual harm despite the race condition.

### Citations

**File:** archiving.js (L78-104)
```javascript
function generateQueriesToUnspendTransferOutputsSpentInArchivedUnit(conn, unit, arrQueries, cb){
	conn.query(
		"SELECT src_unit, src_message_index, src_output_index \n\
		FROM inputs \n\
		WHERE inputs.unit=? \n\
			AND inputs.type='transfer' \n\
			AND NOT EXISTS ( \n\
				SELECT 1 FROM inputs AS alt_inputs \n\
				WHERE inputs.src_unit=alt_inputs.src_unit \n\
					AND inputs.src_message_index=alt_inputs.src_message_index \n\
					AND inputs.src_output_index=alt_inputs.src_output_index \n\
					AND alt_inputs.type='transfer' \n\
					AND inputs.unit!=alt_inputs.unit \n\
			)",
		[unit],
		function(rows){
			rows.forEach(function(row){
				conn.addQuery(
					arrQueries, 
					"UPDATE outputs SET is_spent=0 WHERE unit=? AND message_index=? AND output_index=?", 
					[row.src_unit, row.src_message_index, row.src_output_index]
				);
			});
			cb();
		}
	);
}
```

**File:** writer.js (L33-33)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
```

**File:** writer.js (L359-360)
```javascript
									(objValidationState.arrDoubleSpendInputs.some(function(ds){ return (ds.message_index === i && ds.input_index === j); }) || conf.bLight) 
									? null : 1;
```

**File:** initial-db/byteball-sqlite.sql (L305-305)
```sql
	UNIQUE  (src_unit, src_message_index, src_output_index, is_unique), -- UNIQUE guarantees there'll be no double spend for type=transfer
```

**File:** storage.js (L1749-1751)
```javascript
function archiveJointAndDescendants(from_unit){
	var kvstore = require('./kvstore.js');
	db.executeInTransaction(function doWork(conn, cb){
```

**File:** validation.js (L2026-2073)
```javascript
			var doubleSpendIndexMySQL = "";
			function checkInputDoubleSpend(cb2){
			//	if (objAsset)
			//		profiler2.start();
				doubleSpendWhere += " AND unit != " + conn.escape(objUnit.unit);
				if (objAsset){
					doubleSpendWhere += " AND asset=?";
					doubleSpendVars.push(payload.asset);
				}
				else
					doubleSpendWhere += " AND asset IS NULL";
				var doubleSpendQuery = "SELECT "+doubleSpendFields+" FROM inputs " + doubleSpendIndexMySQL + " JOIN units USING(unit) WHERE "+doubleSpendWhere;
				checkForDoublespends(
					conn, "divisible input", 
					doubleSpendQuery, doubleSpendVars, 
					objUnit, objValidationState, 
					function acceptDoublespends(cb3){
						console.log("--- accepting doublespend on unit "+objUnit.unit);
						var sql = "UPDATE inputs SET is_unique=NULL WHERE "+doubleSpendWhere+
							" AND (SELECT is_stable FROM units WHERE units.unit=inputs.unit)=0";
						if (!(objAsset && objAsset.is_private)){
							objValidationState.arrAdditionalQueries.push({sql: sql, params: doubleSpendVars});
							objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
							return cb3();
						}
						mutex.lock(["private_write"], function(unlock){
							console.log("--- will ununique the conflicts of unit "+objUnit.unit);
							conn.query(
								sql, 
								doubleSpendVars, 
								function(){
									console.log("--- ununique done unit "+objUnit.unit);
									objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
									unlock();
									cb3();
								}
							);
						});
					}, 
					function onDone(err){
						if (err && objAsset && objAsset.is_private && !conf.bLight)
							throw Error("spend proof didn't help: "+err);
					//	if (objAsset)
					//		profiler2.stop('checkInputDoubleSpend');
						cb2(err);
					}
				);
			}
```
