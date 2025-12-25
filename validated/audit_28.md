# Audit Report: Private Fund Freezing via Unstable Unit Archiving

## Summary

The `validateAndSavePrivatePaymentChain()` function accepts and saves private payment chains containing unstable units without enforcing stability checks. When these unstable units are subsequently double-spent and archived, the database records required to reconstruct the payment chain are permanently deleted, rendering the funds unspendable.

## Impact

**Severity**: High  
**Category**: Permanent Fund Freeze

All private indivisible assets (blackbytes, private tokens with fixed denominations) received via payment chains containing unstable units become permanently frozen if those units are double-spent before stabilization. The victim loses complete access to these funds with no recovery mechanism available through normal wallet operations.

## Finding Description

**Location**: `byteball/ocore/indivisible_asset.js:223-281`, function `validateAndSavePrivatePaymentChain()`

**Intended Logic**: Private payment chains should only be saved when all referenced units are stable, ensuring database records remain accessible for future spending operations.

**Actual Logic**: The protocol accepts unstable units in private payment chains without stability enforcement. The function receives a `bAllStable` parameter but never validates it before saving. [1](#0-0) 

When unstable units are double-spent, they receive bad sequence status and are selected for archiving. [2](#0-1) 

The archiving process permanently deletes inputs and outputs from the database. [3](#0-2) 

Later attempts to spend the funds fail because `buildPrivateElementsChain()` cannot find the deleted database records and throws uncaught exceptions in async callbacks. [4](#0-3) [5](#0-4) 

**Exploitation Path**:

1. **Preconditions**: Attacker owns private indivisible assets; victim wallet accepts private payments

2. **Step 1**: Attacker creates private payment unit containing unstable source units in the payment chain

3. **Step 2**: Victim receives and validates the chain via `private_payment.js:validateAndSavePrivatePaymentChain()`, which calls `indivisible_asset.js:validateAndSavePrivatePaymentChain()`. Unstable units are saved with `is_unique = null` without stability verification. [6](#0-5) 

4. **Step 3**: Attacker double-spends one of the unstable units before it stabilizes (within ~5-15 minute stabilization window)

5. **Step 4**: The original unit receives sequence status of `temp-bad` or `final-bad`. The `purgeUncoveredNonserialJoints()` function archives bad-sequence units. [7](#0-6) 

6. **Step 5**: Victim attempts to spend received funds. The wallet calls `buildPrivateElementsChain()` to reconstruct the payment history. Database queries return 0 rows because archiving deleted the records, causing uncaught exceptions that prevent transaction composition.

**Security Property Broken**: Input Accessibility - The protocol assumes all inputs in previously-validated private payment chains remain accessible in the database, but archiving violates this assumption by permanently deleting inputs of double-spent units.

**Root Cause Analysis**:
1. Missing stability enforcement: `validateAndSavePrivatePaymentChain()` receives `bAllStable` parameter but never checks it before proceeding to save
2. Incomplete feature implementation: The protocol has logic to handle unstable units (`updateIndivisibleOutputsThatWereReceivedUnstable()`) but lacks protection against archiving deleting required data
3. Destructive archiving: No safeguards prevent deleting database records that descendant transactions depend on

## Impact Explanation

**Affected Assets**: All private indivisible assets (blackbytes, private tokens with fixed denominations)

**Damage Severity**:
- **Quantitative**: Complete, permanent loss of all private funds received via payment chains containing any unstable unit that is subsequently double-spent
- **Qualitative**: Irreversible fund freeze requiring manual database restoration from backup or protocol modification

**User Impact**:
- **Who**: Any user receiving private payments containing unstable units
- **Conditions**: Exploitable when victim accepts payment before all chain units stabilize and attacker double-spends within stabilization window
- **Recovery**: Impossible through normal operations; requires database restoration or protocol changes

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Malicious user with basic Obyte protocol knowledge
- **Resources Required**: Ownership of private indivisible assets to initiate payments
- **Technical Skill**: Moderate - requires understanding DAG stabilization timing

**Preconditions**:
- **Network State**: Normal operation
- **Timing**: Must double-spend within ~5-15 minute stabilization window

**Execution Complexity**:
- **Transaction Count**: Two (initial payment + double-spend)
- **Coordination**: Single attacker, no external coordination needed
- **Detection Risk**: Low - appears as normal private payment followed by standard double-spend

**Overall Assessment**: Medium-High likelihood - technically feasible with moderate skill, reasonable success probability within timing window

## Recommendation

**Immediate Mitigation**:
Add stability check before saving private payment chains: [8](#0-7) 

Modify to reject unstable chains:
```javascript
ifOk: function(bAllStable){
    if (!bAllStable)
        return callbacks.ifError("Private payment chain contains unstable units");
    // ... continue with saving
}
```

**Alternative Approach**:
Prevent archiving of units that are referenced in saved private payment chains by checking for dependent records before deletion.

## Notes

The protocol contains explicit logic for handling unstable units in private payments (comments at line 235 reference this), suggesting this was a partially-implemented feature rather than an oversight. The `updateIndivisibleOutputsThatWereReceivedUnstable()` function demonstrates awareness of the issue. [9](#0-8)  However, the implementation is incomplete as it lacks protection against the archiving scenario, creating a genuine security vulnerability.

### Citations

**File:** indivisible_asset.js (L223-235)
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
```

**File:** indivisible_asset.js (L284-373)
```javascript
// must be executed within transaction
function updateIndivisibleOutputsThatWereReceivedUnstable(conn, onDone){
	
	function updateOutputProps(unit, is_serial, onUpdated){
		// may update several outputs
		conn.query(
			"UPDATE outputs SET is_serial=? WHERE unit=?", 
			[is_serial, unit],
			function(){
				is_serial ? updateInputUniqueness(unit, onUpdated) : onUpdated();
			}
		);
	}
	
	function updateInputUniqueness(unit, onUpdated){
		// may update several inputs
		conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [unit], function(){
			onUpdated();
		});
	}
	
	console.log("updatePrivateIndivisibleOutputsThatWereReceivedUnstable starting");
	conn.query(
		"SELECT unit, message_index, sequence FROM outputs "+(conf.storage === 'sqlite' ? "INDEXED BY outputsIsSerial" : "")+" \n\
		JOIN units USING(unit) \n\
		WHERE outputs.is_serial IS NULL AND units.is_stable=1 AND is_spent=0", // is_spent=0 selects the final output in the chain
		function(rows){
			if (rows.length === 0)
				return onDone();
			async.eachSeries(
				rows,
				function(row, cb){
					
					function updateFinalOutputProps(is_serial){
						updateOutputProps(row.unit, is_serial, cb);
					}
					
					function goUp(unit, message_index){
						// we must have exactly 1 input per message
						conn.query(
							"SELECT src_unit, src_message_index, src_output_index \n\
							FROM inputs \n\
							WHERE unit=? AND message_index=?", 
							[unit, message_index],
							function(src_rows){
								if (src_rows.length === 0)
									throw Error("updating unstable: blackbyte input not found");
								if (src_rows.length > 1)
									throw Error("updating unstable: more than one input found");
								var src_row = src_rows[0];
								if (src_row.src_unit === null) // reached root of the chain (issue)
									return cb();
								conn.query(
									"SELECT sequence, is_stable, is_serial FROM outputs JOIN units USING(unit) \n\
									WHERE unit=? AND message_index=? AND output_index=?", 
									[src_row.src_unit, src_row.src_message_index, src_row.src_output_index],
									function(prev_rows){
										if (prev_rows.length === 0)
											throw Error("src unit not found");
										var prev_output = prev_rows[0];
										if (prev_output.is_serial === 0)
											throw Error("prev is already nonserial");
										if (prev_output.is_stable === 0)
											throw Error("prev is not stable");
										if (prev_output.is_serial === 1 && prev_output.sequence !== 'good')
											throw Error("prev is_serial=1 but seq!=good");
										if (prev_output.is_serial === 1) // already was stable when initially received
											return cb();
										var is_serial = (prev_output.sequence === 'good') ? 1 : 0;
										updateOutputProps(src_row.src_unit, is_serial, function(){
											if (!is_serial) // overwrite the tip of the chain
												return updateFinalOutputProps(0);
											goUp(src_row.src_unit, src_row.src_message_index);
										});
									}
								);
							}
						);
					}
					
					var is_serial = (row.sequence === 'good') ? 1 : 0;
					updateOutputProps(row.unit, is_serial, function(){
						goUp(row.unit, row.message_index);
					});
				},
				onDone
			);
		}
	);
}
```

**File:** indivisible_asset.js (L631-632)
```javascript
				if (in_rows.length === 0)
					throw Error("building chain: blackbyte input not found");
```

**File:** indivisible_asset.js (L660-661)
```javascript
						if (out_rows.length === 0)
							throw Error("blackbyte output not found");
```

**File:** joint_storage.js (L227-228)
```javascript
		"SELECT unit FROM units "+byIndex+" \n\
		WHERE "+cond+" AND sequence IN('final-bad','temp-bad') AND content_hash IS NULL \n\
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

**File:** private_payment.js (L76-77)
```javascript
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
```
