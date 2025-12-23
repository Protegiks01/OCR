# No Vulnerability Found for This Question

After thorough investigation of the suspected "Old Core Connection Leak" in the `subscribe` request handler, I can confirm:

## Analysis Summary

**The vulnerability described in the security question does NOT exist.**

The concern was that a peer with `old_core=true` could be marked as subscribed (line 3008) before being disconnected, leaving stale subscription state.

## Why No Vulnerability Exists

### 1. **Return Statement Prevents Execution**

The code at lines 3003-3008 contains a critical `return` statement that prevents the vulnerability: [1](#0-0) 

The `return ws.close(...)` at line 3006 **immediately exits the function**, preventing line 3008 (`ws.bSubscribed = true`) from ever executing when `ws.old_core` is true.

### 2. **Version Handler Cleanup**

If a peer subscribes first (before version is checked), the version handler properly cleans up: [2](#0-1) 

When an old core is detected after subscription, the version handler:
- Sets `ws.bSubscribed = false` (line 2529)
- Then closes the connection (line 2532)

This prevents any stale subscription state.

### 3. **sendMessage Safety Check**

Even if subscription state somehow persisted, the `sendMessage` function has a built-in guard: [3](#0-2) 

Messages are only sent to connections with `readyState === ws.OPEN`, preventing any attempt to send joints to closed connections.

### 4. **Connection Cleanup**

The WebSocket close event handler removes peers from the connection arrays: [4](#0-3) 

This ensures closed connections are removed from `arrOutboundPeers`, preventing them from being iterated in `forwardJoint`.

## Notes

The code demonstrates **defense in depth** with multiple layers of protection:
1. Primary protection: `return` statement prevents `bSubscribed` from being set for old cores
2. Secondary protection: Version handler cleans up subscription state if version arrives after subscribe
3. Tertiary protection: `sendMessage` checks connection state before sending
4. Quaternary protection: Close handlers remove peers from connection arrays

All execution paths correctly handle old core peers without leaving stale subscription state. The security question appears to test understanding of JavaScript control flow (`return` semantics) and WebSocket connection lifecycle management.

### Citations

**File:** network.js (L108-111)
```javascript
function sendMessage(ws, type, content) {
	var message = JSON.stringify([type, content]);
	if (ws.readyState !== ws.OPEN)
		return console.log("readyState="+ws.readyState+' on peer '+ws.peer+', will not send '+message);
```

**File:** network.js (L481-486)
```javascript
	ws.on('close', function onWsClose() {
		var i = arrOutboundPeers.indexOf(ws);
		console.log('close event, removing '+i+': '+url);
		if (i !== -1)
			arrOutboundPeers.splice(i, 1);
		cancelRequestsOnClosedConnection(ws);
```

**File:** network.js (L2526-2534)
```javascript
			if (version2int(ws.library_version) < version2int(constants.minCoreVersionForFullNodes)){
				ws.old_core = true;
				if (ws.bSubscribed){
					ws.bSubscribed = false;
					sendJustsaying(ws, 'upgrade_required');
					sendJustsaying(ws, "old core (full)");
					return ws.close(1000, "old core (full)");
				}
			}
```

**File:** network.js (L3003-3008)
```javascript
			if (ws.old_core){ // can be also set in 'version'
				sendJustsaying(ws, 'upgrade_required');
				sendErrorResponse(ws, tag, "old core (full)");
				return ws.close(1000, "old core (full)");
			}
			ws.bSubscribed = true;
```
