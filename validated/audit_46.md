# Audit Report: Private Fund Freezing via Unstable Unit Archiving

## Summary

The `buildPrivateElementsChain()` function in `indivisible_asset.js` throws an uncaught exception when attempting to reconstruct private payment chains after database inputs have been deleted through archiving. The protocol accepts and saves private payment chains containing unstable units, which can be double-spent and subsequently archived, permanently deleting the database records required to spend those funds.

## Impact

**Severity**: High  
**Category**: Permanent Fund Freeze

**Affected Assets**: All private indivisible assets (blackbytes, private tokens with fixed denominations)

**Damage Severity**:
- **Quantitative**: Complete loss of all private funds received via payment chains containing unstable units that are subsequently double-spent. No recovery mechanism exists.
- **Qualitative**: Permanent, irreversible fund loss requiring database restoration from backup or protocol modification to recover.

**User Impact**:
- **Who**: Any user receiving private payments containing unstable units
- **Conditions**: Victim accepts payment before source units stabilize; attacker double-spends within stabilization window
- **Recovery**: Impossible through normal wallet operations; requires manual database restoration or protocol changes

## Finding Description

**Location**: `byteball/ocore/indivisible_asset.js`, functions `buildPrivateElementsChain()` (lines 603-705) and `validateAndSavePrivatePaymentChain()` (lines 223-281)

**Intended Logic**: Private payment chains should only be saved when all referenced units are stable and their inputs will remain accessible in the database for future spending operations.

**Actual Logic**: The protocol accepts unstable units in private payment chains without enforcing stability. When these units are double-spent, they receive bad sequence status and are archived, permanently deleting their database records. Later attempts to spend the funds fail with uncaught exceptions.

**Exploitation Path**:

1. **Preconditions**: Attacker owns private indivisible assets; victim accepts private payments

2. **Step 1 - Send Unstable Private Payment**:
   - Attacker creates private payment unit with indivisible asset
   - Payment chain includes units that are not yet stable
   - Chain transmitted to victim via `network.js:handleOnlinePrivatePayment()` [1](#0-0) 

3. **Step 2 - Victim Saves Unstable Chain**:
   - Chain validated via `privatePayment.validateAndSavePrivatePaymentChain()` [2](#0-1) 
   - Calls `indivisibleAsset.validateAndSavePrivatePaymentChain()` [3](#0-2) 
   - Unstable units saved with `is_unique = null` but NO stability check prevents saving [4](#0-3) 

4. **Step 3 - Double-Spend Before Stabilization**:
   - Attacker broadcasts conflicting unit spending same outputs
   - Original unit marked as `temp-bad` or `final-bad` sequence

5. **Step 4 - Automatic Archiving**:
   - `purgeUncoveredNonserialJoints()` selects units with bad sequence [5](#0-4) 
   - Archives units via `archiving.generateQueriesToArchiveJoint()` [6](#0-5) 
   - Archiving permanently deletes inputs and outputs from database [7](#0-6) [8](#0-7) 

6. **Step 5 - Victim Attempts to Spend**:
   - Transaction composition calls `buildPrivateElementsChain()` to reconstruct payment history [9](#0-8) 

7. **Step 6 - Chain Reconstruction Fails**:
   - Database query for inputs returns 0 rows (deleted during archiving)
   - Function throws uncaught error in async callback [10](#0-9) 
   - Transaction composition fails; funds permanently frozen

**Security Property Broken**: Input Accessibility - The protocol assumes all inputs in previously-validated private payment chains remain accessible in the database, but archiving violates this by permanently deleting inputs of double-spent units.

**Root Cause Analysis**:
1. **Missing Stability Check**: `validateAndSavePrivatePaymentChain()` accepts unstable units without requiring stability before saving
2. **Destructive Archiving**: Bad-sequence units have inputs/outputs permanently deleted with no mechanism to preserve data needed for spending descendant outputs
3. **Unsafe Error Handling**: `buildPrivateElementsChain()` uses `throw` in async callback instead of proper error callback mechanism

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Malicious user with basic Obyte protocol understanding
- **Resources Required**: Ownership of private indivisible assets to initiate payment; ability to time double-spend
- **Technical Skill**: Moderate - requires understanding DAG structure and stabilization timing

**Preconditions**:
- **Network State**: Normal operation; no special conditions required
- **Attacker State**: Must own private indivisible assets
- **Timing**: Must execute double-spend within stabilization window (~5-15 minutes)

**Execution Complexity**:
- **Transaction Count**: 2 transactions (initial payment + double-spend)
- **Coordination**: Single attacker, no coordination required
- **Detection Risk**: Low - appears as normal payment followed by standard double-spend

**Frequency**:
- **Repeatability**: Can target multiple victims
- **Scale**: Limited by number of victims accepting private payments

**Overall Assessment**: Medium-High likelihood - technically feasible, moderate skill requirement, reasonable success probability within timing window.

## Recommendation

**Immediate Mitigation**:
Add stability check before saving private payment chains:

**Permanent Fix**:
Modify `validateAndSavePrivatePaymentChain()` to enforce stability:
- Check `bAllStable` flag at line 226 before proceeding to save
- Return error if any chain element is unstable
- Alternative: Preserve archived unit inputs/outputs when they have unspent descendant outputs

**Additional Measures**:
- Add test case verifying unstable private payments are rejected
- Add monitoring for private payments with unstable elements
- Consider deferred acceptance of private payments until all units stabilize

## Notes

This vulnerability specifically affects private indivisible asset payments. The root cause is the combination of:
1. Accepting unstable units in private payment chains without stability enforcement
2. Archiving process that permanently deletes database records
3. Reconstruction logic that assumes all historical inputs remain accessible

The fix requires either enforcing stability before accepting private payments, or preserving archived data needed for spending descendant outputs.

### Citations

**File:** network.js (L2114-2127)
```javascript
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
	if (!ValidationUtils.isValidBase64(unit, constants.HASH_LENGTH))
		return callbacks.ifError("invalid unit " + unit);
	if (!ValidationUtils.isNonnegativeInteger(message_index))
		return callbacks.ifError("invalid message_index " + message_index);
	if (!(ValidationUtils.isNonnegativeInteger(output_index) || output_index === -1))
		return callbacks.ifError("invalid output_index " + output_index);

```

**File:** private_payment.js (L23-77)
```javascript
function validateAndSavePrivatePaymentChain(arrPrivateElements, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("no priv elements array");
	var headElement = arrPrivateElements[0];
	if (!headElement.payload)
		return callbacks.ifError("no payload in head element");
	var asset = headElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in head element");
	if (!ValidationUtils.isNonnegativeInteger(headElement.message_index))
		return callbacks.ifError("no message index in head private element");
	
	var validateAndSave = function(){
		storage.readAsset(db, asset, null, function(err, objAsset){
			if (err)
				return callbacks.ifError(err);
			if (!!objAsset.fixed_denominations !== !!headElement.payload.denomination)
				return callbacks.ifError("presence of denomination field doesn't match the asset type");
			db.takeConnectionFromPool(function(conn){
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
					// check if duplicate
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
```

**File:** indivisible_asset.js (L223-242)
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
```

**File:** indivisible_asset.js (L625-632)
```javascript
		conn.query(
			"SELECT src_unit, src_message_index, src_output_index, serial_number, denomination, amount, address, asset, \n\
				(SELECT COUNT(*) FROM unit_authors WHERE unit=?) AS count_authors \n\
			FROM inputs WHERE unit=? AND message_index=?", 
			[_unit, _unit, _message_index],
			function(in_rows){
				if (in_rows.length === 0)
					throw Error("building chain: blackbyte input not found");
```

**File:** indivisible_asset.js (L865-867)
```javascript
											buildPrivateElementsChain(
												conn, unit, message_index, output_index, payload, 
												function(arrPrivateElements){
```

**File:** joint_storage.js (L226-237)
```javascript
	db.query( // purge the bad ball if we've already received at least 7 witnesses after receiving the bad ball
		"SELECT unit FROM units "+byIndex+" \n\
		WHERE "+cond+" AND sequence IN('final-bad','temp-bad') AND content_hash IS NULL \n\
			AND NOT EXISTS (SELECT * FROM dependencies WHERE depends_on_unit=units.unit) \n\
			AND NOT EXISTS (SELECT * FROM balls WHERE balls.unit=units.unit) \n\
			AND (units.creation_date < "+db.addTime('-10 SECOND')+" OR EXISTS ( \n\
				SELECT DISTINCT address FROM units AS wunits CROSS JOIN unit_authors USING(unit) CROSS JOIN my_witnesses USING(address) \n\
				WHERE wunits."+order_column+" > units."+order_column+" \n\
				LIMIT 0,1 \n\
			)) \n\
			/* AND NOT EXISTS (SELECT * FROM unhandled_joints) */ \n\
		ORDER BY units."+order_column+" DESC", 
```

**File:** joint_storage.js (L256-256)
```javascript
									archiving.generateQueriesToArchiveJoint(conn, objJoint, 'uncovered', arrQueries, function(){
```

**File:** archiving.js (L26-27)
```javascript
		conn.addQuery(arrQueries, "DELETE FROM inputs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM outputs WHERE unit=?", [unit]);
```

**File:** archiving.js (L53-54)
```javascript
		conn.addQuery(arrQueries, "DELETE FROM inputs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM outputs WHERE unit=?", [unit]);
```
