# AUDIT REPORT

## Title
Incomplete Private Payment Chain Validation Causes Light Client Crash via Synchronous Exception

## Summary
The `handleOnlinePrivatePayment()` function validates only the first element of private payment chains before storing the entire array in the database. When background processing attempts to access the `.unit` property of unvalidated elements, missing properties create the string `"undefined"` which triggers an uncaught synchronous exception in `requestHistoryAfterMCI()`, crashing light client nodes.

## Impact
**Severity**: Medium  
**Category**: Temporary Transaction Delay (≥1 hour)

Light client nodes crash when processing malformed private payment data. Each affected node remains offline until manually restarted. The malformed data persists in the database causing repeated crashes until manually cleaned. This affects individual light client nodes (wallets, services) but does not impact the broader network.

## Finding Description

**Location**: `byteball/ocore/private_payment.js` lines 11-20, `byteball/ocore/network.js` lines 2114-2148 and 2332-2337

**Intended Logic**: All elements in a private payment chain should be validated before storage. The system should gracefully handle malformed data without crashing.

**Actual Logic**: Only the first element is validated before the entire array is stored as JSON. [1](#0-0)  Later processing assumes all elements have a `.unit` property, but unvalidated elements may be missing this field. [2](#0-1)  When `undefined` is converted to the string `"undefined"` via `Object.keys()`, [3](#0-2)  it fails validation and triggers a synchronous throw that is not caught by the async error callback mechanism. [4](#0-3) 

**Exploitation Path**:

1. **Preconditions**: Target is a light client node (`conf.bLight = true`) that accepts private payments via hub messages.

2. **Step 1**: Attacker crafts malicious private payment with valid first element but subsequent elements missing the `.unit` property, then sends it to victim via chat/hub.

3. **Step 2**: Victim's `handleOnlinePrivatePayment()` validates only `arrPrivateElements[0].unit` [5](#0-4)  and stores entire array including malformed elements in database. [6](#0-5) 

4. **Step 3**: Background job `requestUnfinishedPastUnitsOfSavedPrivateElements()` retrieves stored data from database [7](#0-6)  and passes to `requestUnfinishedPastUnitsOfPrivateChains()`. [8](#0-7) 

5. **Step 4**: Inside `findUnfinishedPastUnitsOfPrivateChains()`, the loop accesses `.unit` on all elements without checking existence. Missing `.unit` becomes `undefined`, which JavaScript converts to string `"undefined"` when used as object key. [9](#0-8) 

6. **Step 5**: The string `"undefined"` (length 9) fails base64 validation requiring length 44, triggering synchronous throw before async operations begin. No try-catch exists in call chain, causing unhandled exception that crashes Node.js process. [10](#0-9) 

**Security Property Broken**: Input validation invariant - all external network data must be fully validated before storage and processing.

**Root Cause Analysis**: 
- Validation only checks first array element, assuming downstream code will validate the rest
- `findUnfinishedPastUnitsOfPrivateChains()` executes before full validation and makes unsafe assumptions about data structure
- `requestHistoryAfterMCI()` uses synchronous `throw` for validation failures instead of async error callbacks, creating inconsistent error handling that callers cannot catch

## Impact Explanation

**Affected Assets**: Light client node availability (no direct fund loss)

**Damage Severity**:
- **Quantitative**: Each malicious message crashes one light client node. Attacker can target multiple nodes. Node remains offline until manual restart. Repeated crashes occur until database is manually cleaned.
- **Qualitative**: Denial of service against light client infrastructure. Disrupts wallet operations and private payment processing for affected nodes.

**User Impact**:
- **Who**: Light client operators (wallet users, service providers) and their customers
- **Conditions**: Any light client that receives the malicious private payment message (via hub/chat), regardless of whether they are the intended recipient
- **Recovery**: Manual process restart required. Database cleanup needed to prevent repeated crashes.

**Systemic Risk**: Coordinated attack on multiple light clients (especially hub operators) degrades network usability. Attack can be automated to continuously crash nodes upon restart.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any network user with ability to send chat messages (no special privileges)
- **Resources Required**: Network connection to send messages via hub, ability to craft JSON
- **Technical Skill**: Low - basic understanding of message format

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Standard user with chat capabilities
- **Timing**: Any time

**Execution Complexity**:
- **Transaction Count**: Single malicious message per target
- **Coordination**: None
- **Detection Risk**: Low - appears as normal private payment traffic until crash

**Frequency**:
- **Repeatability**: Unlimited - can crash same node repeatedly
- **Scale**: Can target multiple nodes with broadcast messages

**Overall Assessment**: High likelihood - trivial to execute, reliable crash mechanism, affects all light clients processing private payments.

## Recommendation

**Immediate Mitigation**:
Add validation for all private payment chain elements in `handleOnlinePrivatePayment()`:

```javascript
// In network.js, after line 2126, add:
for (var i = 1; i < arrPrivateElements.length; i++) {
    if (!arrPrivateElements[i].unit || !ValidationUtils.isValidBase64(arrPrivateElements[i].unit, constants.HASH_LENGTH))
        return callbacks.ifError("invalid unit in chain element " + i);
    if (!ValidationUtils.isNonnegativeInteger(arrPrivateElements[i].message_index))
        return callbacks.ifError("invalid message_index in chain element " + i);
}
```

**Permanent Fix**:
Convert `requestHistoryAfterMCI()` to use async error handling consistently:

```javascript
// In network.js, replace throw at line 2337 with:
if (!arrUnits.every(unit => ValidationUtils.isValidBase64(unit, constants.HASH_LENGTH)))
    return onDone("some units are invalid: " + arrUnits.join(', '));
```

**Additional Measures**:
- Add defensive check in `findUnfinishedPastUnitsOfPrivateChains()` to skip elements without `.unit` property
- Add database constraint or cleanup job to remove malformed private payment data
- Add test case verifying multi-element private payment chain validation

## Proof of Concept

```javascript
// test/private_payment_validation.test.js
const network = require('../network.js');
const db = require('../db.js');
const conf = require('../conf.js');

describe('Private Payment Chain Validation', function() {
    this.timeout(10000);
    
    before(function(done) {
        // Set light client mode
        conf.bLight = true;
        done();
    });
    
    it('should reject private payment chains with missing unit properties', function(done) {
        // Craft malicious private payment chain
        const maliciousChain = [
            {
                unit: 'A'.repeat(44), // Valid 44-char base64 unit hash
                message_index: 0,
                output_index: 0,
                payload: {
                    asset: 'B'.repeat(44),
                    denomination: 1
                }
            },
            {
                // Missing .unit property - this should be caught
                message_index: 1,
                output_index: 0,
                payload: {}
            }
        ];
        
        // Mock WebSocket connection
        const mockWs = { peer: 'test_peer' };
        
        // Attempt to handle malicious chain
        network.handleOnlinePrivatePayment(mockWs, maliciousChain, false, {
            ifError: function(error) {
                // Should reach here with validation error
                expect(error).to.include('invalid unit');
                done();
            },
            ifQueued: function() {
                // Should NOT reach here - this means malformed data was stored
                done(new Error('Malformed private payment was stored without validation'));
            },
            ifAccepted: function() {
                done(new Error('Malformed private payment was accepted'));
            },
            ifValidationError: function(unit, error) {
                done(new Error('Should have been caught earlier'));
            }
        });
    });
    
    it('should not crash when processing stored malformed chains', function(done) {
        // First, inject malformed data into database (simulating stored bad data)
        const malformedJson = JSON.stringify([
            { unit: 'A'.repeat(44), message_index: 0, payload: { asset: 'B'.repeat(44) } },
            { message_index: 1, payload: {} } // Missing .unit
        ]);
        
        db.query(
            "INSERT INTO unhandled_private_payments (unit, message_index, output_index, json, peer) VALUES (?,?,?,?,?)",
            ['A'.repeat(44), 0, -1, malformedJson, ''],
            function() {
                // Now trigger processing - this should NOT crash
                const originalExit = process.exit;
                let exitCalled = false;
                
                process.exit = function(code) {
                    exitCalled = true;
                    process.exit = originalExit;
                };
                
                process.on('uncaughtException', function(err) {
                    // If we catch an uncaught exception, the bug exists
                    process.exit = originalExit;
                    if (err.message.includes('some units are invalid')) {
                        done(new Error('Unhandled exception caused by malformed private payment: ' + err.message));
                    } else {
                        throw err;
                    }
                });
                
                // Trigger background processing
                network.requestUnfinishedPastUnitsOfSavedPrivateElements();
                
                // Give it time to process
                setTimeout(function() {
                    process.exit = originalExit;
                    if (exitCalled) {
                        done(new Error('Process.exit was called - node crashed'));
                    } else {
                        // Clean up test data
                        db.query("DELETE FROM unhandled_private_payments WHERE unit=?", ['A'.repeat(44)], function() {
                            done(); // Test passed - no crash
                        });
                    }
                }, 2000);
            }
        );
    });
});
```

## Notes

This vulnerability specifically affects light client nodes (`conf.bLight = true`) as indicated by the conditional check. [11](#0-10)  Full nodes follow a different code path that includes additional validation. The root cause is a mismatch between validation assumptions and actual data structure requirements - the code assumes all elements have `.unit` properties but only validates the first element before storage.

Direct P2P private payment messages are currently disabled [12](#0-11)  but private payments via hub/chat still use the same vulnerable code path through `handleOnlinePrivatePayment()` called from `wallet.js`. The hub acts as a trusted relay but does not validate message content, so malicious users can still exploit this vulnerability by sending crafted messages through the hub to victim light clients.

### Citations

**File:** network.js (L2118-2126)
```javascript
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

**File:** network.js (L2131-2133)
```javascript
		db.query(
			"INSERT "+db.getIgnore()+" INTO unhandled_private_payments (unit, message_index, output_index, json, peer) VALUES (?,?,?,?,?)", 
			[unit, message_index, output_index, JSON.stringify(arrPrivateElements), bViaHub ? '' : ws.peer], // forget peer if received via hub
```

**File:** network.js (L2142-2147)
```javascript
	if (conf.bLight && arrPrivateElements.length > 1){
		savePrivatePayment(function(){
			updateLinkProofsOfPrivateChain(arrPrivateElements, unit, message_index, output_index);
			rerequestLostJointsOfPrivatePayments(); // will request the head element
		});
		return;
```

**File:** network.js (L2332-2337)
```javascript
function requestHistoryAfterMCI(arrUnits, addresses, minMCI, onDone){
	if (!onDone)
		onDone = function(){};
	var arrAddresses = Array.isArray(addresses) ? addresses : [];
	if (!arrUnits.every(unit => ValidationUtils.isValidBase64(unit, constants.HASH_LENGTH)))
		throw Error("some units are invalid: " + arrUnits.join(', '));
```

**File:** network.js (L2387-2390)
```javascript
			rows.forEach(function(row){
				var arrPrivateElements = JSON.parse(row.json);
				arrChains.push(arrPrivateElements);
			});
```

**File:** network.js (L2391-2391)
```javascript
			requestUnfinishedPastUnitsOfPrivateChains(arrChains, function onPrivateChainsReceived(err){
```

**File:** network.js (L2613-2614)
```javascript
		case 'private_payment':
			return sendError(`direct sending of private payments disabled, use chat instead`);
```

**File:** private_payment.js (L11-19)
```javascript
function findUnfinishedPastUnitsOfPrivateChains(arrChains, includeLatestElement, handleUnits){
	var assocUnits = {};
	arrChains.forEach(function(arrPrivateElements){
		assocUnits[arrPrivateElements[0].payload.asset] = true; // require asset definition
		for (var i = includeLatestElement ? 0 : 1; i<arrPrivateElements.length; i++) // skip latest element
			assocUnits[arrPrivateElements[i].unit] = true;
	});
	var arrUnits = Object.keys(assocUnits);
	storage.filterNewOrUnstableUnits(arrUnits, handleUnits);
```
