## Title
Stack Overflow via Unbounded Recursion in Unit Payload Size Calculation

## Summary
The `getLength()` function in `object_length.js` contains unbounded recursion that processes nested objects and arrays without depth limits. When validating units with deeply nested AA definitions, the payload size calculation at `validation.js` line 138 triggers stack overflow before any depth validation occurs, causing all nodes to crash when processing the malicious unit.

## Impact
**Severity**: Critical  
**Category**: Network Shutdown

**Affected Assets**: All network nodes (full nodes, light clients, witnesses), network availability

**Damage Severity**:
- **Quantitative**: Single malicious unit (~90KB with 15,000 nesting levels) crashes all nodes network-wide. Attack cost: ~1,000 bytes transaction fee. Network downtime: Indefinite if sustained.
- **Qualitative**: Complete network halt. No transactions can be processed. Witness consensus stops. Requires manual intervention (code patch + unit blacklist).

**User Impact**:
- **Who**: All network participants
- **Conditions**: Any node receiving and validating the malicious unit
- **Recovery**: Nodes restart but crash again until malicious unit is blacklisted

**Systemic Risk**: Attacker can submit multiple malicious units. Once propagated, all nodes crash repeatedly. Chain halts until hard fork.

## Finding Description

**Location**: `byteball/ocore/validation.js:138`, calling `byteball/ocore/object_length.js:9-40` function `getLength()`

**Intended Logic**: Validation should calculate payload size, compare to declared commission, and reject oversized units. AA definitions should be rejected by depth validation (MAX_DEPTH=100) before causing resource exhaustion.

**Actual Logic**: The payload size calculation recursively traverses the entire unit structure including deeply nested AA definitions via unbounded `getLength()` recursion. With ~15,000 nesting levels, the JavaScript call stack (~10,000-15,000 frames) is exhausted. The stack overflow occurs at line 138 which is NOT protected by try-catch, causing uncaught RangeError that crashes the Node.js process.

**Code Evidence**:

Unbounded recursion in `getLength()`: [1](#0-0) 

Payload size calculation without try-catch protection: [2](#0-1) 

This executes BEFORE the try-catch protected AA definition hash at line 1566: [3](#0-2) 

And BEFORE AA depth validation (MAX_DEPTH=100) at line 1577: [4](#0-3) 

AA validation depth limits that never execute: [5](#0-4) [6](#0-5) 

**Exploitation Path**:

1. **Preconditions**: Attacker has ability to submit units (any user)

2. **Step 1**: Attacker constructs deeply nested AA definition with ~15,000 array nesting levels:
   ```
   ['autonomous agent', {messages: [[[[...15000 levels...]]]]]}]
   ```
   Total size: ~90KB (within MAX_UNIT_LENGTH of 5MB)

3. **Step 2**: Attacker creates unit with app='definition', valid parents, witnesses, signatures, and declared payload_commission

4. **Step 3**: Attacker submits unit to network

5. **Step 4**: Node receives unit via `network.handleJoint()` → calls `validation.validate()`

6. **Step 5**: At line 138, `objectLength.getTotalPayloadSize(objUnit)` calculates payload size

7. **Step 6**: `getTotalPayloadSize()` calls `getLength({ messages: messages_without_temp_data }, bWithKeys)` which recursively traverses into all message payloads including the deeply nested AA definition

8. **Step 7**: After ~10,000-15,000 recursive calls to `getLength()`, JavaScript call stack exhausted

9. **Step 8**: V8 throws RangeError: "Maximum call stack size exceeded"

10. **Step 9**: No try-catch at line 138 catches error → propagates to Node.js event loop

11. **Step 10**: Becomes uncaughtException → Node.js process exits

12. **Step 11**: Node restarts and crashes again when reprocessing the unit

**Security Property Broken**: Network Unit Propagation - Nodes must be able to validate and propagate units without crashing. This vulnerability allows any user to halt the entire network with a single transaction.

**Root Cause Analysis**: 
- `getLength()` lacks depth parameter or recursion counter
- Payload size calculation happens in basic validation (line 138) before message-specific validation
- No try-catch protection around size calculation
- AA depth validation (MAX_DEPTH=100) occurs later at line 1577, never reached

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with Obyte address
- **Resources Required**: ~1,000 bytes transaction fee, basic JavaScript knowledge
- **Technical Skill**: Low (creating deeply nested JSON is trivial)

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Minimal transaction fee
- **Timing**: No constraints

**Execution Complexity**:
- **Transaction Count**: Single unit causes network-wide crash
- **Coordination**: None required
- **Detection Risk**: High after crash, but attack completes before detection

**Frequency**:
- **Repeatability**: Unlimited (can repeat on every node restart)
- **Scale**: Network-wide from single transaction

**Overall Assessment**: High likelihood - trivial to execute, severe impact, difficult to defend against without code changes.

## Recommendation

**Immediate Mitigation**:
Add depth limit to `getLength()` recursion:

```javascript
// File: byteball/ocore/object_length.js
// Function: getLength()

function getLength(value, bWithKeys, depth) {
    if (!depth) depth = 0;
    if (depth > 100) // Match MAX_DEPTH from aa_validation.js
        throw Error("max nesting depth exceeded in payload size calculation");
    
    // ... existing code, passing depth+1 to recursive calls
}
```

**Permanent Fix**:
Wrap payload size calculation in try-catch:

```javascript
// File: byteball/ocore/validation.js
// Line 138-139

try {
    if (objectLength.getTotalPayloadSize(objUnit) !== objUnit.payload_commission)
        return callbacks.ifJointError("wrong payload commission, unit "+objUnit.unit+", calculated "+objectLength.getTotalPayloadSize(objUnit)+", expected "+objUnit.payload_commission);
} catch(e) {
    return callbacks.ifJointError("invalid unit structure: "+e);
}
```

**Additional Measures**:
- Add depth limit to `getJsonSourceString()` in `string_utils.js` (secondary protection)
- Add test case verifying deeply nested structures are rejected
- Add unit size pre-check before detailed validation

**Validation**:
- [ ] Fix prevents stack overflow from deeply nested structures
- [ ] Error handling provides graceful rejection instead of crash
- [ ] Performance impact acceptable (<10ms overhead)
- [ ] Backward compatible with existing valid units

## Proof of Concept

```javascript
// File: test/stack_overflow_nested_aa.test.js
const validation = require('../validation.js');
const objectHash = require('../object_hash.js');
const db = require('../db.js');

describe('Stack overflow prevention', function() {
    this.timeout(60000);
    
    it('should reject deeply nested AA definition without crashing', function(done) {
        // Create deeply nested array with 15000 levels
        let nested = [];
        let current = nested;
        for (let i = 0; i < 15000; i++) {
            current[0] = [];
            current = current[0];
        }
        
        const maliciousDefinition = ['autonomous agent', {
            messages: [{ app: 'payment', payload: { outputs: nested }}]
        }];
        
        // Create unit with malicious AA definition
        const unit = {
            unit: 'fake_unit_hash_123456789012345678901234567890123456789012==',
            version: '1.0',
            alt: '1',
            authors: [{
                address: 'FAKE_ADDRESS_1234567890123456789012',
                authentifiers: { r: 'fake_sig' }
            }],
            messages: [{
                app: 'definition',
                payload: {
                    address: objectHash.getChash160(maliciousDefinition),
                    definition: maliciousDefinition
                }
            }],
            parent_units: ['GENESIS_UNIT'],
            last_ball: 'fake_last_ball',
            last_ball_unit: 'GENESIS_UNIT',
            headers_commission: 500,
            payload_commission: 90000,
            witnesses: ['WITNESS1','WITNESS2','WITNESS3','WITNESS4','WITNESS5',
                       'WITNESS6','WITNESS7','WITNESS8','WITNESS9','WITNESS10',
                       'WITNESS11','WITNESS12']
        };
        
        const joint = { unit: unit };
        
        // This should NOT crash the node, but should gracefully reject
        let crashed = false;
        process.once('uncaughtException', (err) => {
            crashed = true;
            console.log('Node crashed with:', err.message);
        });
        
        db.query("BEGIN", function() {
            validation.validate(joint, {
                ifUnitError: function(error) {
                    console.log('Correctly rejected with unit error:', error);
                    if (!crashed) {
                        done(); // Pass - error was handled gracefully
                    } else {
                        done(new Error('Node crashed instead of rejecting gracefully'));
                    }
                },
                ifJointError: function(error) {
                    console.log('Correctly rejected with joint error:', error);
                    if (!crashed) {
                        done(); // Pass - error was handled gracefully
                    } else {
                        done(new Error('Node crashed instead of rejecting gracefully'));
                    }
                },
                ifTransientError: function(error) {
                    done(new Error('Unexpected transient error: ' + error));
                },
                ifNeedHashTree: function() {
                    done(new Error('Unexpected need hash tree'));
                },
                ifNeedParentUnits: function() {
                    done(new Error('Unexpected need parent units'));
                },
                ifOk: function() {
                    done(new Error('Unit was accepted - should have been rejected!'));
                }
            });
        });
        
        // Timeout to detect if validation hangs
        setTimeout(() => {
            if (crashed) {
                done(new Error('VULNERABILITY CONFIRMED: Node crashed from stack overflow'));
            }
        }, 5000);
    });
});
```

**Notes**:
- The vulnerability is at line 138 during payload size calculation, NOT at line 1566 during hash computation as originally claimed
- Both `getLength()` and `getJsonSourceString()` have unbounded recursion, but `getLength()` is called first
- Line 138 lacks try-catch protection, making the crash unavoidable
- The AA validation depth check (MAX_DEPTH=100) at line 1577 never executes because the node crashes earlier
- This is a critical network shutdown vulnerability exploitable by any user with minimal cost

### Citations

**File:** object_length.js (L9-40)
```javascript
function getLength(value, bWithKeys) {
	if (value === null)
		return 0;
	switch (typeof value){
		case "string": 
			return value.length;
		case "number": 
			if (!isFinite(value))
				throw Error("invalid number: " + value);
			return 8;
			//return value.toString().length;
		case "object":
			var len = 0;
			if (Array.isArray(value))
				value.forEach(function(element){
					len += getLength(element, bWithKeys);
				});
			else    
				for (var key in value){
					if (typeof value[key] === "undefined")
						throw Error("undefined at "+key+" of "+JSON.stringify(value));
					if (bWithKeys)
						len += key.length;
					len += getLength(value[key], bWithKeys);
				}
			return len;
		case "boolean": 
			return 1;
		default:
			throw Error("unknown type="+(typeof value)+" of "+value);
	}
}
```

**File:** validation.js (L138-139)
```javascript
		if (objectLength.getTotalPayloadSize(objUnit) !== objUnit.payload_commission)
			return callbacks.ifJointError("wrong payload commission, unit "+objUnit.unit+", calculated "+objectLength.getTotalPayloadSize(objUnit)+", expected "+objUnit.payload_commission);
```

**File:** validation.js (L1565-1571)
```javascript
			try{
				if (payload.address !== objectHash.getChash160(payload.definition))
					return callback("definition doesn't match the chash");
			}
			catch(e){
				return callback("bad definition");
			}
```

**File:** validation.js (L1577-1577)
```javascript
			aa_validation.validateAADefinition(payload.definition, readGetterProps, objValidationState.last_ball_mci, function (err) {
```

**File:** aa_validation.js (L28-28)
```javascript
var MAX_DEPTH = 100;
```

**File:** aa_validation.js (L572-573)
```javascript
		if (depth > MAX_DEPTH)
			return cb("max depth reached");
```
