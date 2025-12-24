# NoVulnerability found for this question.

**Reason**: After thorough code analysis, while a TOCTOU race condition does exist between different mutex locks (validation uses `mutex.lock(arrAuthorAddresses)` [1](#0-0)  vs writer uses `mutex.lock(["write"])` [2](#0-1) ), and cache reads can occur unsynchronized when `conf.bFaster=true` [3](#0-2) , the **actual impact does not meet Immunefi scope criteria**.

The code clearly shows that when the race condition occurs, it throws **assertion errors** that crash the node:
- `throw Error("not a single MC child?")` [4](#0-3) 
- `throw Error("first unstable MC unit is not our input unit")` [5](#0-4) 

**Critical Gap**: Node crashes requiring restart do not map to any Immunefi severity category:
- ❌ **NOT Critical**: Not "Network Shutdown >24h" (nodes restart), not "Permanent Chain Split" (nodes crash rather than silently diverge)
- ❌ **NOT High**: Not "Permanent Fund Freeze"
- ❌ **NOT Medium**: Not "Temporary Transaction Delay ≥1 hour" (individual node restarts are quick), not "Unintended AA Behavior"

The claim's "**potential** chain divergence" is speculative and not demonstrated by code evidence. The concrete outcome is node crashes, which while annoying, do not meet the strict Immunefi impact requirements for Critical/High/Medium severity.

Additionally, `conf.bFaster` usage in production deployments is not confirmed—it does not appear in default configuration [6](#0-5) , making the precondition uncertain.

### Citations

**File:** validation.js (L223-223)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
```

**File:** writer.js (L33-33)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
```

**File:** storage.js (L1502-1503)
```javascript
	if (conf.bFaster && objEarlierUnitProps2 && arrLaterUnitProps2.every(function(p){ return !!p; }))
		return handleProps(objEarlierUnitProps2, arrLaterUnitProps2);
```

**File:** main_chain.js (L791-791)
```javascript
					throw Error("not a single MC child?");
```

**File:** main_chain.js (L794-794)
```javascript
					throw Error("first unstable MC unit is not our input unit");
```

**File:** conf.js (L1-50)
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

```
