## Title
Database Portability Bug: Empty Wallet Array Causes MySQL Syntax Error in Private Chain Forwarding

## Summary
The `forwardPrivateChainsToOtherMembersOfWallets()` function in `wallet_defined_by_keys.js` passes `arrWallets` directly to an SQL IN clause without validation. When `arrWallets` is empty, MySQL backends produce invalid SQL syntax `IN()` causing application crashes, while SQLite backends handle it gracefully. This creates database-dependent behavior and violates defensive programming principles. [1](#0-0) 

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay / Application Stability Issue

## Finding Description

**Location**: `byteball/ocore/wallet_defined_by_keys.js` - Function `forwardPrivateChainsToOtherMembersOfWallets()` (lines 820-831)

**Intended Logic**: The function should query the database to find device addresses of other wallet members and forward private payment chains to them. It should handle edge cases like empty wallet arrays gracefully across all database backends.

**Actual Logic**: The function passes `arrWallets` directly to the SQL IN clause without validation. On MySQL backends, empty arrays produce `IN()` which is invalid SQL syntax, causing the query to throw an error and crash the operation.

**Code Evidence**: [1](#0-0) 

**Database Backend Handling**:

For SQLite, the `expandArrayPlaceholders` function provides protection: [2](#0-1) 

Specifically, empty arrays are converted to NULL: [3](#0-2) 

For MySQL, no such protection exists - the raw mysql library is used: [4](#0-3) 

**Exploitation Path**:

1. **Preconditions**: 
   - Node running MySQL backend
   - Function called with empty `arrWallets` array (bypassing current call-site guards)

2. **Step 1**: External code or future modification calls `forwardPrivateChainsToOtherMembersOfWallets(arrChains, [], bForwarded, conn, onSaved)`

3. **Step 2**: MySQL library constructs query: `SELECT device_address FROM extended_pubkeys WHERE wallet IN() AND device_address!=?`

4. **Step 3**: MySQL rejects `IN()` as invalid syntax, throwing SQL error

5. **Step 4**: Error propagates through mysql_pool.js which throws (line 47), crashing the operation and preventing private chain forwarding [5](#0-4) 

**Security Property Broken**: **Transaction Atomicity** (Invariant #21) - The multi-step operation of forwarding private chains fails partially, leaving the transaction in an inconsistent state where some operations complete but chain forwarding does not.

**Root Cause Analysis**: 

The codebase uses two different database backends with inconsistent array handling:
- SQLite has custom array expansion logic that handles empty arrays
- MySQL uses the raw Node.js mysql library which does not

This inconsistency creates database-dependent bugs. The pattern throughout the codebase shows developers are aware of this issue and manually guard against empty arrays: [6](#0-5) [7](#0-6) 

However, `forwardPrivateChainsToOtherMembersOfWallets` lacks this defensive validation despite being an exported function.

## Impact Explanation

**Affected Assets**: Private payment operations and multi-signature wallet coordination

**Damage Severity**:
- **Quantitative**: Affects individual operations where private chains need forwarding; does not affect funds directly
- **Qualitative**: Causes operation failure and application instability on MySQL nodes

**User Impact**:
- **Who**: MySQL backend users attempting private payment operations
- **Conditions**: When wallet array determination returns empty result and call-site guards are absent
- **Recovery**: Restart operation; switch to SQLite; or patch function with validation

**Systemic Risk**: Limited - current call sites have protective checks, but exported function API creates future risk [8](#0-7) [9](#0-8) 

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Internal developer error or external module calling exported function
- **Resources Required**: Ability to call exported function or modify call site
- **Technical Skill**: Low - simply requires calling function with empty array

**Preconditions**:
- **Network State**: MySQL backend in use
- **Attacker State**: Access to call exported function or modify codebase
- **Timing**: No specific timing requirements

**Execution Complexity**:
- **Transaction Count**: Single function call
- **Coordination**: None required
- **Detection Risk**: Immediate (SQL error logged)

**Frequency**:
- **Repeatability**: Every time function called with empty array on MySQL
- **Scale**: Individual operations

**Overall Assessment**: Low likelihood in current codebase (all call sites protected), but Medium risk for future code changes or external callers

## Recommendation

**Immediate Mitigation**: Add input validation at function entry

**Permanent Fix**: Implement consistent empty array handling for both database backends

**Code Changes**:

The function should validate inputs before constructing the query:

```javascript
function forwardPrivateChainsToOtherMembersOfWallets(arrChains, arrWallets, bForwarded, conn, onSaved){
    console.log("forwardPrivateChainsToOtherMembersOfWallets", arrWallets);
    
    // ADDED: Input validation
    if (!Array.isArray(arrWallets) || arrWallets.length === 0) {
        return onSaved ? onSaved() : null;
    }
    
    conn = conn || db;
    conn.query(
        "SELECT device_address FROM extended_pubkeys WHERE wallet IN(?) AND device_address!=?", 
        [arrWallets, device.getMyDeviceAddress()], 
        function(rows){
            var arrDeviceAddresses = rows.map(function(row){ return row.device_address; });
            walletGeneral.forwardPrivateChainsToDevices(arrDeviceAddresses, arrChains, bForwarded, conn, onSaved);
        }
    );
}
```

**Additional Measures**:
- Add unit tests for empty array handling
- Document function preconditions in JSDoc comments
- Consider standardizing empty array handling across both database backends
- Add validation to other exported functions with similar patterns

**Validation**:
- [x] Fix prevents exploitation (empty array returns early)
- [x] No new vulnerabilities introduced (graceful degradation)
- [x] Backward compatible (no wallet members means no forwarding needed)
- [x] Performance impact acceptable (single check)

## Notes

**Regarding Non-String Elements**: The security question also asks about non-string elements in `arrWallets`. After analysis, non-string elements (numbers, null, etc.) do NOT cause SQL syntax errors - they are valid SQL values. The query will execute but may return unexpected results if wallet IDs are expected to be strings. This is a semantic issue rather than a syntax error and falls into the Low/QA category.

**Current Protection Status**: All identified call sites in `wallet.js` check for empty arrays before calling this function, which prevents the issue in practice with current code. However, the function is exported (line 878) and part of the module's public API, making it vulnerable to future code changes or external callers. [10](#0-9) 

**Database Inconsistency**: This issue highlights a broader architectural concern - the codebase attempts to support both SQLite and MySQL but handles edge cases differently in each backend's query layer, creating subtle portability bugs.

### Citations

**File:** wallet_defined_by_keys.js (L820-831)
```javascript
function forwardPrivateChainsToOtherMembersOfWallets(arrChains, arrWallets, bForwarded, conn, onSaved){
	console.log("forwardPrivateChainsToOtherMembersOfWallets", arrWallets);
	conn = conn || db;
	conn.query(
		"SELECT device_address FROM extended_pubkeys WHERE wallet IN(?) AND device_address!=?", 
		[arrWallets, device.getMyDeviceAddress()], 
		function(rows){
			var arrDeviceAddresses = rows.map(function(row){ return row.device_address; });
			walletGeneral.forwardPrivateChainsToDevices(arrDeviceAddresses, arrChains, bForwarded, conn, onSaved);
		}
	);
}
```

**File:** wallet_defined_by_keys.js (L878-878)
```javascript
exports.forwardPrivateChainsToOtherMembersOfWallets = forwardPrivateChainsToOtherMembersOfWallets;
```

**File:** sqlite_pool.js (L349-382)
```javascript
function expandArrayPlaceholders(args){
	var sql = args[0];
	var params = args[1];
	if (!Array.isArray(params) || params.length === 0)
		return;
	var assocLengthsOfArrayParams = {};
	for (var i=0; i<params.length; i++)
		if (Array.isArray(params[i])){
		//	if (params[i].length === 0)
		//		throw Error("empty array in query params");
			assocLengthsOfArrayParams[i] = params[i].length;
		}
	if (Object.keys(assocLengthsOfArrayParams).length === 0)
		return;
	var arrParts = sql.split('?');
	if (arrParts.length - 1 !== params.length)
		throw Error("wrong parameter count in " + sql + ", params " + params.join(', '));
	var expanded_sql = "";
	for (var i=0; i<arrParts.length; i++){
		expanded_sql += arrParts[i];
		if (i === arrParts.length-1) // last part
			break;
		var len = assocLengthsOfArrayParams[i];
		if (len > 0) // array
			expanded_sql += _.fill(Array(len), "?").join(",");
		else if (len === 0)
			expanded_sql += "NULL"; // _.flatten() will remove the empty array
		else
			expanded_sql += "?";
	}
	var flattened_params = _.flatten(params);
	args[0] = expanded_sql;
	args[1] = flattened_params;
}
```

**File:** mysql_pool.js (L14-67)
```javascript
	safe_connection.query = function () {
		var last_arg = arguments[arguments.length - 1];
		var bHasCallback = (typeof last_arg === 'function');
		if (!bHasCallback){ // no callback
			last_arg = function(){};
			//return connection_or_pool.original_query.apply(connection_or_pool, arguments);
		}
		var count_arguments_without_callback = bHasCallback ? (arguments.length-1) : arguments.length;
		var new_args = [];
		var q;
		
		for (var i=0; i<count_arguments_without_callback; i++) // except callback
			new_args.push(arguments[i]);
		if (!bHasCallback)
			return new Promise(function(resolve){
				new_args.push(resolve);
				safe_connection.query.apply(safe_connection, new_args);
			});
		
		// add callback with error handling
		new_args.push(function(err, results, fields){
			if (err){
				console.error("\nfailed query: "+q.sql);
				/*
				//console.error("code: "+(typeof err.code));
				if (false && err.code === 'ER_LOCK_DEADLOCK'){
					console.log("deadlock, will retry later");
					setTimeout(function(){
						console.log("retrying deadlock query "+q.sql+" after timeout ...");
						connection_or_pool.original_query.apply(connection_or_pool, new_args);
					}, 100);
					return;
				}*/
				throw err;
			}
			if (Array.isArray(results))
				results = results.map(function(row){
					for (var key in row){
						if (Buffer.isBuffer(row[key])) // VARBINARY fields are read as buffer, we have to convert them to string
							row[key] = row[key].toString();
					}
					return Object.assign({}, row);
				});
			var consumed_time = Date.now() - start_ts;
			if (consumed_time > 25)
				console.log("long query took "+consumed_time+"ms:\n"+new_args.filter(function(a, i){ return (i<new_args.length-1); }).join(", ")+"\nload avg: "+require('os').loadavg().join(', '));
			last_arg(results, fields);
		});
		//console.log(new_args);
		var start_ts = Date.now();
		q = connection_or_pool.original_query.apply(connection_or_pool, new_args);
		//console.log(q.sql);
		return q;
	};
```

**File:** aa_composer.js (L1046-1047)
```javascript
						AND sequence='good' AND main_chain_index<=? \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
```

**File:** definition.js (L1009-1010)
```javascript
					if (arrSrcUnits.length === 0) // not spending anything from our address
						return cb2(false);
```

**File:** wallet.js (L908-911)
```javascript
		if (arrWallets.length > 0)
			arrFuncs.push(function(cb){
				walletDefinedByKeys.forwardPrivateChainsToOtherMembersOfWallets(arrChains, arrWallets, bForwarded, conn, cb);
			});
```

**File:** wallet.js (L2208-2209)
```javascript
								if (wallet)
									walletDefinedByKeys.forwardPrivateChainsToOtherMembersOfWallets(arrChainsOfCosignerPrivateElements, [wallet], false, conn, cb2);
```
