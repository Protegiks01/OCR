## Title
Denial of Service via Stack Overflow in Lodash cloneDeep on Untrusted Private Payment Payloads

## Summary
An attacker can crash nodes by sending private indivisible asset payments with deeply nested objects in the payload. The vulnerability exists in `indivisible_asset.js:validatePrivatePayment()` where `_.cloneDeep()` is called on external input before structural validation, causing stack overflow when processing objects nested thousands of levels deep.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay / Network Disruption

The attacker can crash any node processing their malicious private payment. With automated retries, this could keep targeted nodes offline for extended periods. Coordinated attacks against multiple nodes could cause temporary network degradation. Witness nodes could be targeted to delay consensus, and light client hubs could be disrupted, affecting connected users.

## Finding Description

**Location**: `byteball/ocore/indivisible_asset.js:154`, function `validatePrivatePayment()`

**Intended Logic**: Private payment payloads should be validated before processing to reject malformed or malicious structures that could cause resource exhaustion.

**Actual Logic**: The payload is cloned using `_.cloneDeep()` before comprehensive structural validation occurs. Initial validation only checks top-level types, not object depth. [1](#0-0) 

The initial validation checks that `payload.outputs` is an array and that the indexed element is an object, but does not validate internal structure or depth. The `isNonemptyObject` check only verifies: [2](#0-1) 

At line 154, `_.cloneDeep(payload)` is invoked on this partially-validated structure: [3](#0-2) 

The comprehensive validation that would reject deeply nested objects occurs at line 158 via `validation.validatePayment()`, which checks: [4](#0-3) 

However, this validation executes AFTER the vulnerable cloning operation.

**Exploitation Path**:

1. **Preconditions**: Node is running and processing private payments through hub/wallet messaging system

2. **Step 1**: Attacker crafts malicious private payment with deeply nested object in payload
   - Creates payload where `outputs[0].amount` is a 10,000-level nested object instead of number
   - Sends via hub/wallet messaging (not direct P2P, which is disabled)
   - Code path: WebSocket → `network.js:onWebsocketMessage()` → `wallet.js:handlePrivatePaymentChains()` → `network.js:handleOnlinePrivatePayment()` [5](#0-4) [6](#0-5) 

3. **Step 2**: Message reaches `parsePrivatePaymentChain()` → `validatePrivatePayment()`
   - Initial validation (lines 54-78) checks top-level structure only
   - Deeply nested `amount` field passes because `isNonemptyObject` only checks if outputs[0] exists and is an object
   
4. **Step 3**: At line 154, `_.cloneDeep(payload)` attempts recursive clone
   - Lodash cloneDeep uses recursion to traverse object tree
   - Attempts to clone all 10,000 nested levels
   - Node.js hits maximum call stack size
   
5. **Step 4**: Node crashes with "RangeError: Maximum call stack size exceeded"
   - Validation at line 158 that would reject malformed `amount` never executes
   - Node becomes unavailable until restart
   - Attacker can repeatedly send malicious payloads

**Security Property Broken**: Network Unit Propagation - Valid nodes should process incoming private payments without crashing. This vulnerability allows selective node crashes through malicious private payments.

**Root Cause Analysis**: 
- Validation ordering flaw: comprehensive validation occurs after expensive cloning operation
- `isNonemptyObject()` utility only checks surface-level properties, not depth
- No depth limit enforcement before recursive operations
- Lodash cloneDeep's recursion-based implementation vulnerable to stack overflow

## Impact Explanation

**Affected Assets**: Node availability, network reliability

**Damage Severity**:
- **Quantitative**: Any node processing the malicious private payment will crash. Attacker can target specific nodes or broadcast widely
- **Qualitative**: Temporary disruption of targeted nodes. If coordinated against witness nodes or hubs, could cause network-wide delays

**User Impact**:
- **Who**: Node operators processing private payments, light clients connected to compromised hubs
- **Conditions**: Node receives and processes crafted private payment through hub/wallet messaging
- **Recovery**: Automatic restart possible, but attacker can repeatedly crash with new payloads

**Systemic Risk**: Coordinated attacks could temporarily degrade network performance by targeting multiple nodes simultaneously, delaying transaction confirmations.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any actor with ability to send messages through hub/wallet system
- **Resources Required**: Minimal - ability to construct deeply nested JSON and send via Obyte messaging
- **Technical Skill**: Low - create nested JSON structure and send through standard messaging channels

**Preconditions**:
- **Network State**: Normal operation with nodes processing private payments
- **Attacker State**: No special permissions or positions required
- **Timing**: Can execute at any time

**Execution Complexity**:
- **Transaction Count**: Single malicious private payment per target
- **Coordination**: None required for individual node targeting
- **Detection Risk**: Low - appears as normal private payment until crash occurs

**Frequency**:
- **Repeatability**: Unlimited - attacker can craft multiple malicious payloads
- **Scale**: Can target individual nodes or broadcast to multiple nodes

**Overall Assessment**: High likelihood - trivial to execute, requires no resources, repeatable without cost.

## Recommendation

**Immediate Mitigation**:
Validate payload structure depth before cloning. Add check before line 154:

```javascript
// Add depth validation before cloneDeep
function checkObjectDepth(obj, maxDepth, currentDepth = 0) {
    if (currentDepth > maxDepth) return false;
    if (typeof obj !== 'object' || obj === null) return true;
    return Object.values(obj).every(val => 
        checkObjectDepth(val, maxDepth, currentDepth + 1)
    );
}

// Before line 154
if (!checkObjectDepth(payload, 100)) // reasonable depth limit
    return callbacks.ifError("payload structure too deeply nested");
```

**Permanent Fix**:
Restructure validation to occur before cloning, or use non-recursive cloning approach:

```javascript
// Move comprehensive validation before cloning
// Or use structured cloning with depth limits
// Or avoid cloning entirely by careful property access
```

**Additional Measures**:
- Add integration test verifying deeply nested payloads are rejected
- Add monitoring for stack overflow crashes in private payment processing
- Document depth limits in protocol specification
- Consider rate limiting private payment processing per peer

**Validation**:
- Fix prevents stack overflow with deeply nested objects
- No performance degradation for normal payloads
- Backward compatible with existing valid private payments
- Proper error message returned to sender

## Notes

**Attack Vector Correction**: The claim states exploitation is "via the P2P network," but direct P2P private payment sending is disabled at [7](#0-6) . The actual attack vector is through the hub/wallet messaging system, which still allows exploitation via [8](#0-7) .

The core vulnerability remains valid despite this inaccuracy - the malicious payload reaches the vulnerable code through an active messaging path, and the stack overflow occurs exactly as described.

### Citations

**File:** indivisible_asset.js (L54-78)
```javascript
	var payload = objPrivateElement.payload;
	if (!ValidationUtils.isStringOfLength(payload.asset, constants.HASH_LENGTH))
		return callbacks.ifError("invalid asset in private payment");
	if (!ValidationUtils.isPositiveInteger(payload.denomination))
		return callbacks.ifError("invalid denomination in private payment");
	if (!ValidationUtils.isNonemptyObject(objPrivateElement.output))
		return callbacks.ifError("no output");
	if (!ValidationUtils.isNonnegativeInteger(objPrivateElement.output_index))
		return callbacks.ifError("invalid output index");
	if (!ValidationUtils.isNonemptyArray(payload.outputs))
		return callbacks.ifError("invalid outputs");
	var our_hidden_output = payload.outputs[objPrivateElement.output_index];
	if (!ValidationUtils.isNonemptyObject(payload.outputs[objPrivateElement.output_index]))
		return callbacks.ifError("no output at output_index");
	if (!ValidationUtils.isValidAddress(objPrivateElement.output.address))
		return callbacks.ifError("bad address in output");
	if (!ValidationUtils.isNonemptyString(objPrivateElement.output.blinding))
		return callbacks.ifError("bad blinding in output");
	if (objectHash.getBase64Hash(objPrivateElement.output) !== our_hidden_output.output_hash)
		return callbacks.ifError("output hash doesn't match, output="+JSON.stringify(objPrivateElement.output)+", hash="+our_hidden_output.output_hash);
	if (!ValidationUtils.isArrayOfLength(payload.inputs, 1))
		return callbacks.ifError("inputs array must be 1 element long");
	var input = payload.inputs[0];
	if (!ValidationUtils.isNonemptyObject(input))
		return callbacks.ifError("no inputs[0]");
```

**File:** indivisible_asset.js (L152-159)
```javascript
			arrFuncs.push(function(cb){
				// we need to unhide the single output we are interested in, other outputs stay partially hidden like {amount: 300, output_hash: "base64"}
				var partially_revealed_payload = _.cloneDeep(payload);
				var our_output = partially_revealed_payload.outputs[objPrivateElement.output_index];
				our_output.address = objPrivateElement.output.address;
				our_output.blinding = objPrivateElement.output.blinding;
				validation.validatePayment(conn, partially_revealed_payload, objPrivateElement.message_index, objPartialUnit, objValidationState, cb);
			});
```

**File:** validation_utils.js (L76-78)
```javascript
function isNonemptyObject(obj){
	return (obj && typeof obj === "object" && !Array.isArray(obj) && Object.keys(obj).length > 0);
}
```

**File:** validation.js (L1926-1929)
```javascript
		if (hasFieldsExcept(output, ["address", "amount", "blinding", "output_hash"]))
			return callback("unknown fields in payment output");
		if (!isPositiveInteger(output.amount))
			return callback("amount must be positive integer, found "+output.amount);
```

**File:** network.js (L2114-2126)
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

**File:** network.js (L2613-2614)
```javascript
		case 'private_payment':
			return sendError(`direct sending of private payments disabled, use chat instead`);
```

**File:** wallet.js (L383-385)
```javascript
			case 'private_payments':
				handlePrivatePaymentChains(ws, body, from_address, callbacks);
				break;
```

**File:** wallet.js (L770-773)
```javascript
function handlePrivatePaymentChains(ws, body, from_address, callbacks){
	var arrChains = body.chains;
	if (!ValidationUtils.isNonemptyArray(arrChains))
		return callbacks.ifError("no chains found");
```
