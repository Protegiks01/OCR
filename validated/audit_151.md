# Audit Report: Light Client Infinite Retry Loop via bRetrying Flag Reset in Signed Message Validation

## Title
Infinite Retry Loop in Light Client Signed Message Validation Due to bRetrying Flag Reset

## Summary
The `validateOrReadDefinition()` function in `signed_message.js` unconditionally resets the `bRetrying` flag to `false` when the `last_ball_unit` database query succeeds, even when called with `bRetrying=true` from a retry attempt. [1](#0-0)  This breaks the retry limiting logic at the definition lookup stage, [2](#0-1)  allowing light clients to enter an infinite loop when validating signed messages with missing address definitions, causing resource exhaustion and denial of service.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay / Network Resource Exhaustion

**Affected Assets**: Light client node resources (CPU, memory, network bandwidth, validation queue)

**Damage Severity**:
- **Quantitative**: Each retry cycle consumes one database query and one network request to the light vendor with a 300-second timeout. [3](#0-2) [4](#0-3)  If an attacker sends N malicious messages concurrently, N validation threads enter infinite loops simultaneously.
- **Qualitative**: The victim light client becomes unresponsive and unable to process legitimate validations. Memory accumulates with nested callback closures on each retry iteration.

**User Impact**:
- **Who**: Light client users who accept device messages via prosaic contracts or arbiter contracts
- **Conditions**: Attacker must be paired with victim's device or able to send contract messages; requires a valid `last_ball_unit` that exists in the network but an address definition that doesn't exist or that the light vendor refuses to provide
- **Recovery**: Client must be restarted and attacker must be blocked from sending further malicious messages

**Systemic Risk**: Light clients are critical for mobile and resource-constrained deployments. Compromising their availability reduces overall network accessibility. Multiple concurrent attacks multiply resource consumption.

## Finding Description

**Location**: `byteball/ocore/signed_message.js:157-212`, function `validateOrReadDefinition()`

**Intended Logic**: The `bRetrying` flag should limit light clients to one retry attempt after requesting history from the vendor. On the first call with `bRetrying=undefined` or `false`, if the definition is not found, the client requests history and retries with `bRetrying=true`. On the retry call with `bRetrying=true`, if the definition is still not found, the check at line 182 should error out.

**Actual Logic**: When the `last_ball_unit` query succeeds (line 160 returns rows.length > 0), line 176 unconditionally executes `bRetrying = false`, overwriting the parameter value. This occurs even when the function was called with `bRetrying=true` from a previous retry. When the subsequent definition lookup fails, the check at line 182 evaluates `!conf.bLight || bRetrying` as `false || false = false` (because `bRetrying` was reset to false), so it doesn't return an error and instead requests history again, creating an infinite loop.

**Code Evidence**: [5](#0-4) 

**Exploitation Path**:

1. **Preconditions**: 
   - Victim runs a light client (`conf.bLight = true`)
   - Attacker can send device messages (paired device or contract proposal)
   - A valid `last_ball_unit` exists in the network
   - Address definition for the signer doesn't exist or vendor won't provide it

2. **Step 1**: Attacker crafts and sends a signed message via `prosaic_contract_response` [6](#0-5)  or `arbiter_contract_response` [7](#0-6)  containing:
   - Valid `last_ball_unit` that exists in the network
   - `authors[0].address` set to an address with no definition in the database
   - No `definition` field in the message
   - Valid signature

3. **Step 2**: First validation attempt:
   - `validateOrReadDefinition(cb)` called with `bRetrying=undefined`
   - Line 160: Query finds the `last_ball_unit` (rows.length > 0)
   - Line 176: `bRetrying = false` (set from undefined)
   - Line 179-180: Definition lookup fails, triggers `ifDefinitionNotFound` callback
   - Line 182: Check `!conf.bLight || bRetrying` = `false || false` = `false`, doesn't error
   - Line 185-186: Requests history from vendor and retries with `bRetrying=true`

4. **Step 3**: Second validation attempt (first retry):
   - `validateOrReadDefinition(cb, true)` called with `bRetrying=true`
   - Line 160: Query finds the unit again
   - **Line 176: `bRetrying = false`** ← Bug: resets the retry counter!
   - Line 179-180: Definition still not found
   - Line 182: Check `!conf.bLight || bRetrying` = `false || false` = `false`, doesn't error (should error!)
   - Line 185-186: Requests history again and retries with `bRetrying=true`

5. **Step 4**: Infinite loop continues:
   - Each iteration makes a database query and network request (up to 300s timeout)
   - Callback closures accumulate in memory
   - Validation never completes

**Security Property Broken**: Validation operations must complete atomically and deterministically, either succeeding or failing within a bounded time. This infinite loop violates that invariant, causing indefinite resource consumption without resolution.

**Root Cause Analysis**: The assignment at line 176 appears to be defensive programming to ensure `bRetrying` has a boolean value after the unit query succeeds. However, it inadvertently resets the retry counter when transitioning from the unit lookup phase to the definition lookup phase. The code conflates two distinct retry scenarios: (1) retrying unit lookup when the full node is catching up, and (2) retrying definition lookup after requesting history from the vendor. Setting `bRetrying = false` after a successful unit query allows unlimited retries of the definition lookup phase.

## Impact Explanation

**Affected Assets**: Light client node resources (CPU, memory, network bandwidth, validation queue)

**Damage Severity**:
- **Quantitative**: Each retry consumes 1 database query (~milliseconds) and 1 network request with up to 300-second timeout. Memory grows with nested callback closures. With N concurrent malicious messages, N validation threads hang indefinitely.
- **Qualitative**: Victim light client becomes unresponsive and cannot process legitimate validations or other operations.

**User Impact**:
- **Who**: Light client users accepting device messages via prosaic/arbiter contracts
- **Conditions**: Attacker must pair with victim or send contract proposals; attack works during normal network operation
- **Recovery**: Requires restarting the client and blocking the attacker

**Systemic Risk**:
- Attack can be automated and repeated continuously
- Multiple concurrent attacks multiply impact
- Light clients are essential for mobile/low-resource deployments

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any peer with device pairing capability
- **Resources Required**: Ability to pair device or send contract messages; knowledge of a valid `last_ball_unit`
- **Technical Skill**: Medium - requires understanding signed message format and device messaging protocol

**Preconditions**:
- **Network State**: Normal operation with at least one stable unit
- **Attacker State**: Paired device or contract proposal acceptance
- **Timing**: No specific timing requirements

**Execution Complexity**:
- **Transaction Count**: Single device message per attack
- **Coordination**: None required
- **Detection Risk**: Low - appears as normal validation activity

**Frequency**:
- **Repeatability**: Unlimited
- **Scale**: Can target multiple light clients

**Overall Assessment**: Medium likelihood - requires device pairing but trivial to execute once paired; light clients are common targets.

## Recommendation

**Immediate Mitigation**:
Remove the unconditional reset of `bRetrying` at line 176. The flag should only be initialized on first entry, not reset on subsequent calls:

```javascript
// Change line 176 from:
bRetrying = false;

// To:
if (bRetrying === undefined)
    bRetrying = false;
```

**Permanent Fix**:
Separate the retry logic for unit lookup and definition lookup into distinct flags or use a counter to track total retries across both phases:

```javascript
function validateOrReadDefinition(cb, retryState) {
    if (!retryState)
        retryState = {unitRetried: false, defRetried: false};
    
    // Unit lookup phase
    if (rows.length === 0) {
        if (retryState.unitRetried)
            return handleResult("last_ball_unit not found");
        // Request and retry with unitRetried=true
    }
    
    // Definition lookup phase
    if (definition not found) {
        if (retryState.defRetried)
            return handleResult("definition not found");
        // Request and retry with defRetried=true
    }
}
```

**Additional Measures**:
- Add test case verifying retry limit is enforced for light clients
- Add timeout at the validation function level (not just network level)
- Log warning when multiple retries occur for the same message
- Consider rate limiting device messages from paired devices

**Validation**:
- Fix prevents infinite retry loop
- Maintains backward compatibility
- No performance impact on normal operations

## Proof of Concept

```javascript
// Test: test/signed_message_retry_loop.test.js
const signed_message = require('../signed_message.js');
const conf = require('../conf.js');
const db = require('../db.js');

describe('Light client signed message validation retry limit', function() {
    before(function() {
        // Set up light client mode
        conf.bLight = true;
    });
    
    it('should error after one retry when definition not found', function(done) {
        this.timeout(10000); // Should complete quickly, not hang
        
        // Create signed message with valid last_ball_unit but missing definition
        const objSignedMessage = {
            signed_message: "test message",
            authors: [{
                address: "NONEXISTENT_ADDRESS_WITH_NO_DEFINITION",
                authentifiers: {"r": "valid_signature_here"}
            }],
            last_ball_unit: "VALID_UNIT_HASH_IN_DATABASE",
            version: "1.0"
        };
        
        let retryCount = 0;
        
        // Mock network.requestHistoryFor to count retries
        const network = require('../network.js');
        const originalRequestHistoryFor = network.requestHistoryFor;
        network.requestHistoryFor = function(units, addresses, callback) {
            retryCount++;
            if (retryCount > 2) {
                // Should not reach here - indicates infinite loop
                network.requestHistoryFor = originalRequestHistoryFor;
                done(new Error('Infinite retry detected: ' + retryCount + ' retries'));
                return;
            }
            // Simulate vendor not having the definition
            callback();
        };
        
        signed_message.validateSignedMessage(db, objSignedMessage, function(err) {
            network.requestHistoryFor = originalRequestHistoryFor;
            
            // Should error after first retry (retryCount should be exactly 1)
            if (!err) {
                return done(new Error('Expected error after retry'));
            }
            if (retryCount !== 1) {
                return done(new Error('Expected exactly 1 retry, got ' + retryCount));
            }
            if (!err.includes('definition expected')) {
                return done(new Error('Wrong error: ' + err));
            }
            done();
        });
    });
});
```

## Notes

This vulnerability specifically affects light clients in the Obyte network. Full nodes that maintain complete transaction history are not affected because they use a different code path (lines 169-173) that doesn't rely on the `bRetrying` flag in the same way.

The bug occurs at the intersection of two retry mechanisms: one for catching up on missing units and another for requesting missing definitions. The unconditional reset at line 176 was likely intended to handle the transition from unit lookup to definition lookup, but it breaks the retry limiting logic.

The 300-second timeout per network request [3](#0-2)  means each retry iteration can hang for up to 5 minutes, making this a practical denial-of-service vector even with moderate numbers of malicious messages.

### Citations

**File:** signed_message.js (L157-187)
```javascript
	function validateOrReadDefinition(cb, bRetrying) {
		var bHasDefinition = ("definition" in objAuthor);
		if (bNetworkAware) {
			conn.query("SELECT main_chain_index, timestamp FROM units WHERE unit=?", [objSignedMessage.last_ball_unit], function (rows) {
				if (rows.length === 0) {
					var network = require('./network.js');
					if (!conf.bLight && !network.isCatchingUp() || bRetrying)
						return handleResult("last_ball_unit " + objSignedMessage.last_ball_unit + " not found");
					if (conf.bLight)
						network.requestHistoryFor([objSignedMessage.last_ball_unit], [objAuthor.address], function () {
							validateOrReadDefinition(cb, true);
						});
					else
						eventBus.once('catching_up_done', function () {
							// no retry flag, will retry multiple times until the catchup is over
							validateOrReadDefinition(cb);
						});
					return;
				}
				bRetrying = false;
				var last_ball_mci = rows[0].main_chain_index;
				var last_ball_timestamp = rows[0].timestamp;
				storage.readDefinitionByAddress(conn, objAuthor.address, last_ball_mci, {
					ifDefinitionNotFound: function (definition_chash) { // first use of the definition_chash (in particular, of the address, when definition_chash=address)
						if (!bHasDefinition) {
							if (!conf.bLight || bRetrying)
								return handleResult("definition expected but not provided");
							var network = require('./network.js');
							return network.requestHistoryFor([], [objAuthor.address], function () {
								validateOrReadDefinition(cb, true);
							});
```

**File:** network.js (L38-38)
```javascript
var RESPONSE_TIMEOUT = 300*1000; // after this timeout, the request is abandoned
```

**File:** network.js (L259-264)
```javascript
		var cancel_timer = bReroutable ? null : setTimeout(function(){
			ws.assocPendingRequests[tag].responseHandlers.forEach(function(rh){
				rh(ws, request, {error: "[internal] response timeout"});
			});
			delete ws.assocPendingRequests[tag];
		}, RESPONSE_TIMEOUT);
```

**File:** wallet.js (L515-519)
```javascript
						signed_message.validateSignedMessage(db, objSignedMessage, objContract.peer_address, function(err) {
							if (err || objSignedMessage.authors[0].address !== objContract.peer_address || objSignedMessage.signed_message != objContract.title)
								return callbacks.ifError("wrong contract signature");
							processResponse(objSignedMessage);
						});
```

**File:** wallet.js (L752-756)
```javascript
						signed_message.validateSignedMessage(db, objSignedMessage, objContract.peer_address, function(err) {
							if (err || objSignedMessage.authors[0].address !== objContract.peer_address || objSignedMessage.signed_message != objContract.title)
								return callbacks.ifError("wrong contract signature");
							processResponse(objSignedMessage);
						});
```
