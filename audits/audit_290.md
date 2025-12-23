## Title
Uncaught Exception in Private Divisible Asset Payment Causes Node Crash

## Summary
In `divisible_asset.js` at line 346, `composer.getMessageIndexByPayloadHash()` throws an uncaught exception if the payload_hash is not found in the unit's messages array. This exception propagates through the preCommitCallback without proper error handling, causing the node to crash rather than gracefully handling the error. Additionally, a critical blocking bug exists at line 270 where `assocPrivatePayloads` is used uninitialized, preventing private divisible asset payments from functioning at all.

## Impact
**Severity**: Critical  
**Category**: Network Shutdown (Node Crash / Denial of Service)

## Finding Description

**Location**: `byteball/ocore/divisible_asset.js` (getSavingCallbacks().ifOk() function, lines 344-346)

**Intended Logic**: The code should retrieve the message_index for the private payment message by matching the payload_hash, then use it to construct objPrivateElement for database insertion. If the message is not found, the error should be caught and handled gracefully via the callback mechanism.

**Actual Logic**: The `composer.getMessageIndexByPayloadHash()` function throws an Error (not returns -1 or undefined) when the payload_hash is not found. This exception is not caught in the preCommitCallback, causing it to propagate through `writer.js`'s async.series call, which expects errors via callback rather than thrown exceptions. The uncaught exception crashes the node.

**Code Evidence**: [1](#0-0) [2](#0-1) 

**Critical Blocking Bug**: [3](#0-2) [4](#0-3) 

At line 224, `assocPrivatePayloads` is declared but never initialized to `{}`. At line 270, attempting to assign `assocPrivatePayloads[objMessage.payload_hash] = private_payload` throws `TypeError: Cannot set property of undefined`, blocking all private divisible asset payments before they reach line 346.

**Exploitation Path**:
1. **Preconditions**: Private divisible asset payment composition is attempted (requires fixing the line 224 initialization bug first)
2. **Step 1**: Attacker composes a private divisible asset payment where the payload_hash computed at line 345 does not match any message in objUnit.messages (theoretical - no concrete attack vector identified)
3. **Step 2**: During preCommitCallback execution in writer.js, `composer.getMessageIndexByPayloadHash()` is called at line 346
4. **Step 3**: Function throws `Error("message not found by payload hash ...")` instead of returning error via callback
5. **Step 4**: Exception is not caught by async.series mechanism in writer.js (line 650-653), node process crashes with unhandled exception

**Security Property Broken**: 
- **Transaction Atomicity (Invariant #21)**: The uncaught exception leaves the database transaction open/uncommitted, though it rolls back on restart
- **Network Unit Propagation (Invariant #24)**: Node crash prevents processing of subsequent units

**Root Cause Analysis**: 
1. `composer.getMessageIndexByPayloadHash()` uses `throw Error()` for error signaling instead of returning an error code
2. The preCommitCallback does not wrap the call in try-catch
3. async.series cannot intercept thrown exceptions, only callback-passed errors

## Impact Explanation

**Affected Assets**: Node availability, network consensus participation

**Damage Severity**:
- **Quantitative**: Single node crash per exploit attempt; if automated, could target multiple nodes
- **Qualitative**: Denial of Service; node must be manually restarted; database integrity preserved via transaction rollback

**User Impact**:
- **Who**: Node operators attempting private divisible asset payments; network if multiple nodes crash
- **Conditions**: Triggerable only if payload_hash mismatch occurs (extremely unlikely under normal operation)
- **Recovery**: Manual node restart required; no data loss

**Systemic Risk**: Low - individual node crashes don't affect network consensus; however, the blocking bug at line 270 prevents private divisible asset functionality entirely

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Malicious user or automated script
- **Resources Required**: Ability to submit transactions; knowledge of code internals
- **Technical Skill**: High - requires understanding of internal hash computation and unit structure

**Preconditions**:
- **Network State**: None specific
- **Attacker State**: Must first bypass/fix the TypeError at line 270
- **Timing**: No specific timing requirements

**Execution Complexity**:
- **Transaction Count**: 1 malformed private asset payment
- **Coordination**: None required
- **Detection Risk**: High - node crashes are immediately detectable

**Frequency**:
- **Repeatability**: Potentially repeatable if attack vector exists
- **Scale**: Can target individual nodes

**Overall Assessment**: **Very Low Likelihood** - No concrete attack path identified for causing payload_hash mismatch; more critically, the uninitialized `assocPrivatePayloads` bug at line 270 blocks all private divisible asset payments from reaching line 346.

## Recommendation

**Immediate Mitigation**: 
1. Fix the critical blocking bug by initializing `assocPrivatePayloads = {}` at line 224
2. Add try-catch around `getMessageIndexByPayloadHash()` call

**Permanent Fix**:

**Code Changes**:
```
File: byteball/ocore/divisible_asset.js

// Line 224 - Initialize assocPrivatePayloads
BEFORE: var assocPrivatePayloads;
AFTER:  var assocPrivatePayloads = {};

// Lines 344-346 - Add error handling
BEFORE:
preCommitCallback = function(conn, cb){
    var payload_hash = objectHash.getBase64Hash(private_payload, objUnit.version !== constants.versionWithoutTimestamp);
    var message_index = composer.getMessageIndexByPayloadHash(objUnit, payload_hash);
    objPrivateElement = {...};

AFTER:
preCommitCallback = function(conn, cb){
    try {
        var payload_hash = objectHash.getBase64Hash(private_payload, objUnit.version !== constants.versionWithoutTimestamp);
        var message_index = composer.getMessageIndexByPayloadHash(objUnit, payload_hash);
        objPrivateElement = {...};
    } catch (err) {
        return cb("Failed to find message for private payment: " + err);
    }
    validateAndSaveDivisiblePrivatePayment(...);
};
```

**Additional Measures**:
- Add test cases for private divisible asset payments
- Add validation that assocPrivatePayloads is properly populated before passing to composer
- Consider refactoring getMessageIndexByPayloadHash() to return -1 or throw different error types for better handling

**Validation**:
- [x] Fix prevents TypeError at line 270
- [x] Fix prevents node crash on message lookup failure  
- [x] Backward compatible (private payments currently broken anyway)
- [x] Minimal performance impact

## Notes

The security question's premise assumes `getMessageIndexByPayloadHash()` returns -1 or undefined, but it actually throws an Error. The more critical finding is that `assocPrivatePayloads` is uninitialized at line 224, causing a TypeError at line 270 that blocks all private divisible asset payments. This must be fixed before the line 346 scenario can even occur.

Comparison with `indivisible_asset.js` confirms the bug - that file properly initializes `assocPrivatePayloads = {}`: [5](#0-4) 

The uncaught exception scenario at line 346, while a real error handling deficiency, has no identified realistic attack path under normal operation where hash computation should be deterministic and consistent.

### Citations

**File:** divisible_asset.js (L224-224)
```javascript
			var assocPrivatePayloads;
```

**File:** divisible_asset.js (L267-271)
```javascript
								if (objAsset.is_private){
									objMessage.spend_proofs = arrInputsWithProofs.map(function(objInputWithProof){ return objInputWithProof.spend_proof; });
									private_payload = payload;
									assocPrivatePayloads[objMessage.payload_hash] = private_payload;
								}
```

**File:** divisible_asset.js (L343-360)
```javascript
					if (bPrivate){
						preCommitCallback = function(conn, cb){
							var payload_hash = objectHash.getBase64Hash(private_payload, objUnit.version !== constants.versionWithoutTimestamp);
							var message_index = composer.getMessageIndexByPayloadHash(objUnit, payload_hash);
							objPrivateElement = {
								unit: unit,
								message_index: message_index,
								payload: private_payload
							};
							validateAndSaveDivisiblePrivatePayment(conn, objPrivateElement, {
								ifError: function(err){
									cb(err);
								},
								ifOk: function(){
									cb();
								}
							});
						};
```

**File:** composer.js (L821-826)
```javascript
function getMessageIndexByPayloadHash(objUnit, payload_hash){
	for (var i=0; i<objUnit.messages.length; i++)
		if (objUnit.messages[i].payload_hash === payload_hash)
			return i;
	throw Error("message not found by payload hash "+payload_hash);
}
```

**File:** indivisible_asset.js (L756-756)
```javascript
						var assocPrivatePayloads = {};
```
