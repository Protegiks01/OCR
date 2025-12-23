## Title
Node Crash via Missing Null-Check in Catchup Chain Traversal

## Summary
The `prepareCatchupChain()` function in `catchup.js` contains a missing null-check that causes immediate node crash when a unit with `last_ball_unit = null` is encountered during backwards traversal while having `main_chain_index > last_stable_mci`. The recursive call `goUp(null)` triggers an uncaught exception in `storage.readJointWithBall()`.

## Impact
**Severity**: Medium  
**Category**: Temporary Network Disruption (Node Crash / DoS)

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: The `goUp()` function should traverse backwards through the last ball chain until reaching a unit with `main_chain_index <= last_stable_mci`, building a catchup chain for syncing peers.

**Actual Logic**: When a unit has `last_ball_unit = null` but `main_chain_index > last_stable_mci`, the code recursively calls `goUp(null)` without validation, causing `storage.readJointWithBall(db, null, ...)` to throw an uncaught error that crashes the Node.js process.

**Code Evidence**: [1](#0-0) 

**Exploitation Path**:

1. **Preconditions**: 
   - Responding node's database contains a unit U where `last_ball_unit = NULL` (due to corruption, early protocol state, or legacy data)
   - Unit U has `main_chain_index = N` where `N > 0`
   - Peer sends catchup request with `last_stable_mci = M` where `M < N`

2. **Step 1**: Peer sends catchup request triggering `prepareCatchupChain()` execution [2](#0-1) 

3. **Step 2**: Function builds catchup chain and reaches unit U during `goUp()` traversal. At line 90, condition evaluates: `N > M` (true), so executes `goUp(objJoint.unit.last_ball_unit)` which becomes `goUp(null)`

4. **Step 3**: `goUp(null)` calls `storage.readJointWithBall(db, null, ...)`, which calls `readJoint(conn, null, ...)` [3](#0-2) 

5. **Step 4**: In `readJoint()`, the function eventually queries the database with `unit = null`. The SQL query `WHERE units.unit=?` with parameter `[null]` returns no rows (SQL `column = NULL` never matches). This triggers the `ifNotFound` callback which throws: [4](#0-3) 
   
   This uncaught exception crashes the Node.js process immediately.

**Security Property Broken**: **Invariant #19 (Catchup Completeness)** - The catchup protocol fails catastrophically instead of handling edge cases gracefully, preventing syncing nodes from completing synchronization.

**Root Cause Analysis**: 
The code assumes all non-genesis units have valid `last_ball_unit` references based on protocol validation rules [5](#0-4) , but doesn't defensively handle database inconsistencies. The database schema allows NULL values [6](#0-5) , creating a mismatch between protocol assumptions and data layer constraints.

## Impact Explanation

**Affected Assets**: Node availability, network synchronization capability

**Damage Severity**:
- **Quantitative**: Complete node crash requiring manual restart; any peer requesting catchup during vulnerable state triggers crash
- **Qualitative**: Denial of Service - node becomes unavailable until manually restarted

**User Impact**:
- **Who**: Hub operators, full nodes serving catchup requests
- **Conditions**: Database corruption or inconsistent state exists; any peer sends catchup request with appropriate `last_stable_mci`
- **Recovery**: Manual node restart required; database repair needed to prevent recurrence

**Systemic Risk**: If a hub node experiences this crash during peak sync periods, multiple syncing peers would be unable to catch up, causing temporary network fragmentation.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any network peer (no special privileges required)
- **Resources Required**: Ability to send catchup requests (standard peer capability)
- **Technical Skill**: Low - simply sending catchup request with appropriate parameters

**Preconditions**:
- **Network State**: Target node must have database corruption or inconsistent unit with `last_ball_unit = NULL`
- **Attacker State**: Standard peer connection to vulnerable node
- **Timing**: Can be triggered at any time once preconditions exist

**Execution Complexity**:
- **Transaction Count**: Zero - only requires catchup protocol message
- **Coordination**: Single peer acting alone
- **Detection Risk**: Crash is immediately visible; source peer identifiable from logs

**Frequency**:
- **Repeatability**: Can crash node repeatedly if database corruption persists
- **Scale**: Per-node impact (each corrupted node vulnerable independently)

**Overall Assessment**: **Low likelihood** in practice because it requires pre-existing database corruption or inconsistent state. Cannot be directly triggered by malicious peer without first corrupting target's database. However, if corruption exists, exploitation is trivial.

## Recommendation

**Immediate Mitigation**: Add defensive null-check before recursive call to prevent crash on corrupted data.

**Permanent Fix**: Validate `last_ball_unit` is not null before recursion, and handle edge case gracefully by either stopping traversal or returning error.

**Code Changes**:

The fix should be applied at line 90 in `catchup.js`:

```javascript
// BEFORE (vulnerable):
(objUnitProps.main_chain_index <= last_stable_mci) ? cb() : goUp(objJoint.unit.last_ball_unit);

// AFTER (fixed):
if (objUnitProps.main_chain_index <= last_stable_mci) {
    cb();
} else if (!objJoint.unit.last_ball_unit) {
    cb("last_ball_unit is missing at MCI " + objUnitProps.main_chain_index);
} else {
    goUp(objJoint.unit.last_ball_unit);
}
```

**Additional Measures**:
- Database integrity check on startup to detect units with NULL `last_ball_unit` where `main_chain_index > 0`
- Enhanced logging when catchup fails to aid debugging
- Consider adding database constraint to prevent NULL `last_ball_unit` for non-genesis units
- Add monitoring/alerting for catchup protocol failures

**Validation**:
- [x] Fix prevents crash by handling null gracefully
- [x] No new vulnerabilities introduced (proper error handling)
- [x] Backward compatible (error response instead of crash)
- [x] Performance impact negligible (single null-check)

## Proof of Concept

**Test Environment Setup**:
```bash
git clone https://github.com/byteball/ocore.git
cd ocore
npm install
```

**Exploit Simulation** (requires database manipulation):

```javascript
/*
 * PoC: Node Crash via Missing Last Ball in Catchup
 * Demonstrates: Node crashes when encountering null last_ball_unit during catchup
 * Expected Result: Node process terminates with uncaught exception
 */

const db = require('./db.js');
const catchup = require('./catchup.js');

async function simulateCrash() {
    // Step 1: Simulate corrupted database state
    // (In practice, this would be existing corruption)
    // Create a unit with last_ball_unit = NULL but MCI > 0
    
    // Step 2: Trigger catchup with last_stable_mci = 0
    const catchupRequest = {
        last_stable_mci: 0,
        last_known_mci: 100,
        witnesses: [/* valid witness list */]
    };
    
    // Step 3: Call prepareCatchupChain
    catchup.prepareCatchupChain(catchupRequest, {
        ifError: function(err) {
            console.log("Error (should not reach here on crash): ", err);
        },
        ifOk: function(result) {
            console.log("Success (should not reach here on crash)");
        }
    });
    
    // Expected: Node crashes with "Error: joint not found, unit null"
    // The error handler above will NOT be called because the error is thrown synchronously
}

// Note: This PoC requires actual database corruption to demonstrate
// In test environment, you would need to manually set a unit's last_ball_unit to NULL
```

**Expected Output** (when vulnerability exists):
```
/path/to/ocore/storage.js:612
    throw Error("joint not found, unit "+unit);
    ^

Error: joint not found, unit null
    at readJointWithBall (/path/to/ocore/storage.js:612:9)
    at goUp (/path/to/ocore/catchup.js:87:12)
    ...
[Node process terminates]
```

**Expected Output** (after fix applied):
```
Error callback received: last_ball_unit is missing at MCI [X]
[Node continues running]
```

## Notes

**Answer to Security Question**: YES, the recursive call `goUp(objJoint.unit.last_ball_unit)` **crashes the node** when `last_ball_unit` is null. It does NOT loop indefinitely - it immediately throws an uncaught exception that terminates the Node.js process.

**Exploitability Caveat**: While the crash is real and deterministic, practical exploitation requires the target node to have pre-existing database corruption or inconsistent state. A malicious peer cannot directly cause this corruption through normal protocol operations. Therefore, this is more accurately classified as a **robustness issue** rather than a directly exploitable vulnerability.

**Protocol Design Context**: The Obyte protocol's validation rules [5](#0-4)  require all non-genesis units to have valid `last_ball_unit` values. However, the database schema permits NULL values, and the catchup code lacks defensive checks against this schema-code mismatch.

**Recommendation Priority**: Medium - should be fixed to improve node robustness and prevent DoS in edge cases, but low urgency given the requirement for pre-existing corruption.

### Citations

**File:** catchup.js (L86-93)
```javascript
				function goUp(unit){
					storage.readJointWithBall(db, unit, function(objJoint){
						objCatchupChain.stable_last_ball_joints.push(objJoint);
						storage.readUnitProps(db, unit, function(objUnitProps){
							(objUnitProps.main_chain_index <= last_stable_mci) ? cb() : goUp(objJoint.unit.last_ball_unit);
						});
					});
				}
```

**File:** network.js (L3057-3066)
```javascript
				catchup.prepareCatchupChain(catchupRequest, {
					ifError: function(error){
						sendErrorResponse(ws, tag, error);
						unlock();
					},
					ifOk: function(objCatchupChain){
						sendResponse(ws, tag, objCatchupChain);
						unlock();
					}
				});
```

**File:** storage.js (L609-623)
```javascript
function readJointWithBall(conn, unit, handleJoint) {
	readJoint(conn, unit, {
		ifNotFound: function(){
			throw Error("joint not found, unit "+unit);
		},
		ifFound: function(objJoint){
			if (objJoint.ball)
				return handleJoint(objJoint);
			conn.query("SELECT ball FROM balls WHERE unit=?", [unit], function(rows){
				if (rows.length === 1)
					objJoint.ball = rows[0].ball;
				handleJoint(objJoint);
			});
		}
	});
```

**File:** validation.js (L185-186)
```javascript
		if (!isStringOfLength(objUnit.last_ball_unit, constants.HASH_LENGTH))
			return callbacks.ifUnitError("wrong length of last ball unit");
```

**File:** initial-db/byteball-sqlite.sql (L7-7)
```sql
	last_ball_unit CHAR(44) NULL,
```
