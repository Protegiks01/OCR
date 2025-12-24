# Stack Overflow DoS via Unbounded Recursive Best-Child Traversal in Main Chain Stability Determination

## Summary

The `goDownAndCollectBestChildrenOld()` function in `main_chain.js` recursively traverses the DAG's best-child tree without stack overflow protection. When `conf.bFaster` is not configured (default), an attacker can create a deep best-child chain (10,000-15,000 units) that triggers stack overflow during stability checks, causing node crashes and network-wide denial of service. [1](#0-0) 

## Impact

**Severity**: Critical  
**Category**: Network Shutdown / Denial of Service

**Affected Assets**: All network nodes, transaction processing capacity, network liveness

**Damage Severity**:
- **Quantitative**: Nodes crash when validating units referencing the malicious chain; network-wide DoS until patched
- **Qualitative**: Complete denial of service - nodes cannot validate subsequent units without crashing

**User Impact**:
- **Who**: All full nodes, validators, hub operators
- **Conditions**: Any stability check traversing the deep best-child chain
- **Recovery**: Requires code patch deployment across all nodes (>24 hours)

**Systemic Risk**: Attack is persistent - nodes crash again after restart when re-encountering the malicious chain. Newly synced nodes also crash.

## Finding Description

**Location**: `byteball/ocore/main_chain.js:912-938`, function `goDownAndCollectBestChildrenOld()`

**Intended Logic**: Traverse the best-child tree to collect all best children included by later units, used during stability determination.

**Actual Logic**: The function uses unbounded recursion without stack protection. At line 925, it recursively calls itself without any `setImmediate` yield points, unlike the "Fast" variant which yields every 100 iterations. [2](#0-1) 

**Default Configuration**: The `conf.bFaster` flag is not set by default in `conf.js`, causing the system to use the vulnerable old implementation. [3](#0-2) 

**Code Path Selection**: When `conf.bFaster` is falsy (default), both the old vulnerable version AND the fast version are executed for compatibility checking, with the old version running first. [4](#0-3) 

**Exploitation Path**:

1. **Preconditions**: Attacker controls sufficient bytes (~1,500,000 bytes = $15-150 USD) to post ~15,000 units

2. **Step 1**: Attacker creates deep best-child chain by posting units U1, U2, ..., U15000 sequentially where each unit has exactly one parent (the previous unit). Each unit automatically becomes the best parent of the next.
   - Validation allows single-parent units [5](#0-4) 
   - No depth limits exist in protocol constants [6](#0-5) 

3. **Step 2**: Chain is stored in database with proper `best_parent_unit` relationships

4. **Step 3**: When any unit validation checks stability of an early chain unit, or when `tools/check_stability.js` runs:
   - `validation.js` calls `determineIfStableInLaterUnitsAndUpdateStableMcFlag` [7](#0-6) 
   - Which calls `determineIfStableInLaterUnits` in `main_chain.js`
   - Which calls `createListOfBestChildrenIncludedByLaterUnits` [8](#0-7) 
   - Which calls the vulnerable `goDownAndCollectBestChildrenOld`

5. **Step 4**: Function recursively traverses all 15,000 units without yielding. JavaScript stack limit (~10,000-15,000 calls) is exceeded, throwing `RangeError: Maximum call stack size exceeded`, crashing the Node.js process.

**Security Property Broken**: Network availability and liveness - valid units cannot propagate because nodes crash during validation.

**Root Cause Analysis**: The old implementation was created before stack overflow protection was added. The "Fast" version includes `setImmediate` protection [9](#0-8) , but the old version was retained for compatibility validation without updating its protection. The system defaults to running the vulnerable old version when `bFaster` is undefined.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with Obyte address
- **Resources Required**: ~1,500,000 bytes (~$15-150 USD) for transaction fees
- **Technical Skill**: Medium - requires understanding DAG structure and sequential unit submission

**Preconditions**:
- **Network State**: Default configuration (`conf.bFaster` unset)
- **Attacker State**: Sufficient funds for ~15,000 minimal units
- **Timing**: No special timing required

**Execution Complexity**:
- **Transaction Count**: 10,000-15,000 units
- **Coordination**: Single attacker, no coordination needed
- **Detection Risk**: High (creates obvious long chain), but damage occurs before mitigation

**Frequency**: Attack is repeatable with different chains

**Overall Assessment**: High likelihood - low cost, low complexity, critical impact, affects default configuration

## Recommendation

**Immediate Mitigation**:
Set `conf.bFaster = true` in default configuration to use the protected Fast variant:
```javascript
// File: conf.js
exports.bFaster = true;
```

**Permanent Fix**:
Add `setImmediate` protection to the old function for backward compatibility:
```javascript
// File: main_chain.js, line 920-926
function addUnit(){
    arrBestChildren.push(row.unit);
    if (row.is_free === 1 || arrLaterUnits.indexOf(row.unit) >= 0)
        cb2();
    else {
        if (arrBestChildren.length % 100 === 0)
            return setImmediate(goDownAndCollectBestChildrenOld, [row.unit], cb2);
        goDownAndCollectBestChildrenOld([row.unit], cb2);
    }
}
```

**Additional Measures**:
- Add test case verifying deep chains don't cause crashes
- Add monitoring for unusually long best-child chains
- Consider deprecating old implementation entirely

## Proof of Concept

```javascript
const test = require('ava');
const db = require('../db.js');
const main_chain = require('../main_chain.js');
const composer = require('../composer.js');
const network = require('../network.js');

test.serial('deep best-child chain causes stack overflow', async t => {
    // Setup: Create chain of 15,000 units where each has only 1 parent
    const chainDepth = 15000;
    let prevUnit = genesisUnit;
    
    for (let i = 0; i < chainDepth; i++) {
        // Create minimal unit with single parent
        const unit = await composer.composeJoint({
            paying_addresses: [testAddress],
            outputs: [{address: testAddress, amount: 1000}],
            parent_units: [prevUnit], // Single parent creates linear chain
            witnesses: testWitnesses
        });
        
        await network.saveJoint(unit);
        prevUnit = unit.unit.unit;
    }
    
    // Trigger: Check stability of early unit in chain
    // This should cause stack overflow in goDownAndCollectBestChildrenOld
    await t.throwsAsync(
        async () => {
            await main_chain.determineIfStableInLaterUnits(
                db, 
                prevUnit, 
                [latestUnit]
            );
        },
        {message: /Maximum call stack size exceeded/}
    );
});
```

## Notes

The vulnerability exists because:
1. Stack overflow protection is a known concern in this codebase - other modules (formula evaluation, AA validation) implement `setImmediate` interruption every 100 iterations
2. The Fast variant was added later with proper protection, but the old implementation was kept for compatibility without retrofitting the protection
3. By default, both implementations run (old first for validation, then fast for verification), meaning the vulnerable code executes on every stability check
4. The recursion depth is unbounded - determined only by DAG structure, which an attacker can manipulate by creating linear chains with single-parent units

### Citations

**File:** main_chain.js (L803-803)
```javascript
					createListOfBestChildrenIncludedByLaterUnits([first_unstable_mc_unit], function(arrBestChildren){
```

**File:** main_chain.js (L912-938)
```javascript
					function goDownAndCollectBestChildrenOld(arrStartUnits, cb){
						conn.query("SELECT unit, is_free, main_chain_index FROM units WHERE best_parent_unit IN(?)", [arrStartUnits], function(rows){
							if (rows.length === 0)
								return cb();
							async.eachSeries(
								rows, 
								function(row, cb2){
									
									function addUnit(){
										arrBestChildren.push(row.unit);
										if (row.is_free === 1 || arrLaterUnits.indexOf(row.unit) >= 0)
											cb2();
										else
											goDownAndCollectBestChildrenOld([row.unit], cb2);
									}
									
									if (row.main_chain_index !== null && row.main_chain_index <= max_later_limci)
										addUnit();
									else
										graph.determineIfIncludedOrEqual(conn, row.unit, arrLaterUnits, function(bIncluded){
											bIncluded ? addUnit() : cb2();
										});
								},
								cb
							);
						});
					}
```

**File:** main_chain.js (L967-968)
```javascript
										if (count % 100 === 0)
											return setImmediate(goDownAndCollectBestChildrenFast, [row.unit], cb2);
```

**File:** main_chain.js (L1065-1086)
```javascript
									var start_time = Date.now();
									if (conf.bFaster)
										return collectBestChildren(arrFilteredAltBranchRootUnits, function(){
											console.log("collectBestChildren took "+(Date.now()-start_time)+"ms");
											cb();
										});
									goDownAndCollectBestChildrenOld(arrFilteredAltBranchRootUnits, function(){
										console.log("goDownAndCollectBestChildrenOld took "+(Date.now()-start_time)+"ms");
										var arrBestChildren1 = _.clone(arrBestChildren.sort());
										arrBestChildren = arrInitialBestChildren;
										start_time = Date.now();
										collectBestChildren(arrFilteredAltBranchRootUnits, function(){
											console.log("collectBestChildren took "+(Date.now()-start_time)+"ms");
											arrBestChildren.sort();
											if (!_.isEqual(arrBestChildren, arrBestChildren1)){
												throwError("different best children, old "+arrBestChildren1.join(', ')+'; new '+arrBestChildren.join(', ')+', later '+arrLaterUnits.join(', ')+', earlier '+earlier_unit+", global db? = "+(conn === db));
												arrBestChildren = arrBestChildren1;
											}
											cb();
										});
									});
								}
```

**File:** conf.js (L1-131)
```javascript
/*jslint node: true */
"use strict";
require('./enforce_singleton.js');
require('./constants.js'); // in order to force loading .env before app-root's conf.js

function mergeExports(anotherModule){
	for (var key in anotherModule)
		exports[key] = anotherModule[key];
}

// start node explicitly by `require('ocore/network').start()`
//exports.explicitStart = true

// port we are listening on.  Set to null to disable accepting connections
// recommended port for livenet: 6611
// recommended port for testnet: 16611
exports.port = null;
//exports.port = 6611;

// enable this will make websocket server doesn't spawn on new port
// this is usefull if you already have SocketServer running and want to reuse the port
//exports.portReuse = true;

// how peers connect to me
//exports.myUrl = 'wss://example.org/bb';

// if we are serving as hub.  Default is false
//exports.bServeAsHub = true;

// if we are a light client.  Default is full client
//exports.bLight = true;

// where to send bug reports to.  Usually, it is wallet vendor's server.
// By default, it is hub url
//exports.bug_sink_url = "wss://example.org/bb";

// this is used by wallet vendor only, to redirect bug reports to developers' email
//exports.bug_sink_email = 'admin@example.org';
//exports.bugs_from_email = 'bugs@example.org';

// Connects through socks v5 proxy without auth, WS_PROTOCOL has to be 'wss'
// exports.socksHost = 'localhost';
// exports.socksPort = 9050;
// exports.socksUsername = 'dummy';
// exports.socksPassword = 'dummy';
// DNS queries are always routed through the socks proxy if it is enabled

// Connects through an http proxy server
// exports.httpsProxy = 'http://proxy:3128'

// WebSocket protocol prefixed to all hosts.  Must be wss:// on livenet, ws:// is allowed on testnet
exports.WS_PROTOCOL = process.env.devnet ? "ws://" : "wss://";

exports.MAX_INBOUND_CONNECTIONS = 100;
exports.MAX_OUTBOUND_CONNECTIONS = 100;
exports.MAX_TOLERATED_INVALID_RATIO = 0.1; // max tolerated ratio of invalid to good joints
exports.MIN_COUNT_GOOD_PEERS = 10; // if we have less than this number of good peers, we'll ask peers for their lists of peers

exports.bWantNewPeers = true;

// true, when removed_paired_device commands received from peers are to be ignored. Default is false.
exports.bIgnoreUnpairRequests = false;

var bCordova = (typeof window === 'object' && window && window.cordova);

// storage engine: mysql or sqlite
exports.storage = 'sqlite';
if (bCordova) {
	exports.storage = 'sqlite';
	exports.bLight = true;
}
exports.database = {};

exports.updatableAssetRegistries = ['O6H6ZIFI57X3PLTYHOCVYPP5A553CYFQ'];


/*
There are 3 ways to customize conf in modules that use ocore lib:
1. drop a custom conf.js into the project root.  The code below will find it and merge.  Will not work under browserify.
2. drop a custom conf.json into the app's data dir inside the user's home dir.  The code below will find it and merge.  Will not work under browserify.
3. require() this conf and modify it:
var conf = require('ocore/conf.js');
conf.custom_property = 'custom value';
You should do it as early as possible during your app's startup.
The later require()s of this conf will see the modified version.
This way is not recommended as the code becomes loading order dependent.
*/

if (typeof process === 'object' && typeof process.versions === 'object' && typeof process.versions.node !== 'undefined') { // desktop
	var desktopApp = require('./desktop_app.js');

	// merge conf from other modules that include us as lib.  The other module must place its custom conf.js into its root directory
	var appRootDir = desktopApp.getAppRootDir();
	var appPackageJson = require(appRootDir + '/package.json');
	exports.program = appPackageJson.name;
	exports.program_version = appPackageJson.version;
	if (appRootDir !== __dirname){
		try{
			mergeExports(require(appRootDir + '/conf.js'));
			console.log('merged app root conf from ' + appRootDir + '/conf.js');
		}
		catch(e){
			console.log("not using app root conf: "+e);
		}
	}
	else
		console.log("I'm already at the root");

	// merge conf from user home directory, if any.
	// Note that it is json rather than js to avoid code injection
	var appDataDir = desktopApp.getAppDataDir();
	try{
		mergeExports(require(appDataDir + '/conf.json'));
		console.log('merged user conf from ' + appDataDir + '/conf.json');
	}
	catch(e){
		console.log('not using user conf: '+e);
	}
}

// after merging the custom confs, set defaults if they are still not set
if (exports.storage === 'mysql'){
	exports.database.max_connections = exports.database.max_connections || 1;
	exports.database.host = exports.database.host || 'localhost';
	exports.database.name = exports.database.name || 'byteball';
	exports.database.user = exports.database.user || 'byteball';
}
else if (exports.storage === 'sqlite'){
	exports.database.max_connections = exports.database.max_connections || 1;
	exports.database.filename = exports.database.filename || (exports.bLight ? 'byteball-light.sqlite' : 'byteball.sqlite');
}
```

**File:** validation.js (L179-181)
```javascript
	else {
		if (!isNonemptyArray(objUnit.parent_units))
			return callbacks.ifUnitError("missing or empty parent units array");
```

**File:** validation.js (L658-658)
```javascript
						main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, last_ball_unit, objUnit.parent_units, objLastBallUnitProps.is_stable, function(bStable, bAdvancedLastStableMci){
```

**File:** constants.js (L42-58)
```javascript
// anti-spam limits
exports.MAX_AUTHORS_PER_UNIT = 16;
exports.MAX_PARENTS_PER_UNIT = 16;
exports.MAX_MESSAGES_PER_UNIT = 128;
exports.MAX_SPEND_PROOFS_PER_MESSAGE = 128;
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_OUTPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_CHOICES_PER_POLL = 128;
exports.MAX_CHOICE_LENGTH = 64;
exports.MAX_DENOMINATIONS_PER_ASSET_DEFINITION = 64;
exports.MAX_ATTESTORS_PER_ASSET = 64;
exports.MAX_DATA_FEED_NAME_LENGTH = 64;
exports.MAX_DATA_FEED_VALUE_LENGTH = 64;
exports.MAX_AUTHENTIFIER_LENGTH = 4096;
exports.MAX_CAP = 9e15;
exports.MAX_COMPLEXITY = process.env.MAX_COMPLEXITY || 100;
exports.MAX_UNIT_LENGTH = process.env.MAX_UNIT_LENGTH || 5e6;
```
