## Title
Event Loop Resource Leak in check_stability.js Due to Unclosed Database Connection Timers

## Summary
The `check_stability.js` utility script creates database connections with persistent `setInterval` timers that are never cleared, and the script does not call `process.exit()` after completion. This causes the Node.js process to hang indefinitely, and when run repeatedly in automated scripts, leads to process accumulation and eventual system resource exhaustion.

## Impact
**Severity**: Low/QA (Operational Issue - Out of Scope for Bug Bounty)
**Category**: Infrastructure Resource Exhaustion (Not Meeting Immunefi Criteria)

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: The script should execute the stability check, log the result, and exit cleanly, releasing all resources.

**Actual Logic**: After the callback executes and logs the result, the script does not explicitly exit. The database pool creates connections with `setInterval` timers that keep the Node.js event loop alive indefinitely.

**Code Evidence**:

The script does not call `process.exit()` or `db.close()`: [2](#0-1) 

SQLite pool creates persistent timers for each connection: [3](#0-2) 

Comparison with properly written tools that call `process.exit()`: [4](#0-3) [5](#0-4) 

**Exploitation Path**:
1. **Preconditions**: Script is added to cron job or automated monitoring system
2. **Step 1**: Script executes and initializes database pool with connection(s)
3. **Step 2**: Each database connection creates a `setInterval` timer (60 second interval)
4. **Step 3**: Callback executes and logs result, but script does not exit
5. **Step 4**: Process hangs waiting for timer events; new invocations create additional hanging processes
6. **Step 5**: After repeated executions, system accumulates hung processes, exhausting PIDs, memory, and file descriptors

**Security Property Broken**: None of the 24 protocol-level invariants. This is an operational/infrastructure issue.

**Root Cause Analysis**: The SQLite connection pool implementation uses `setInterval` for monitoring long-running queries, but this timer is never cleared. The script lacks proper cleanup (`process.exit()` or `db.close()`), causing the event loop to remain active.

## Impact Explanation

**Affected Assets**: System resources (process table, memory, file descriptors), not protocol assets

**Damage Severity**:
- **Quantitative**: Unbounded process accumulation over time
- **Qualitative**: Operational disruption to node infrastructure

**User Impact**:
- **Who**: Node operators running the script in automation
- **Conditions**: Repeated execution without proper process management
- **Recovery**: Manual process cleanup, script restart

**Systemic Risk**: Limited - affects only infrastructure where script is deployed, not the protocol itself

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Not an attack - operational misconfiguration
- **Resources Required**: None (legitimate script usage)
- **Technical Skill**: Basic scripting knowledge

**Preconditions**:
- **Network State**: Any
- **Attacker State**: N/A - this is a bug, not an attack
- **Timing**: Script must be run repeatedly in automation

**Execution Complexity**:
- **Transaction Count**: 0 (no protocol transactions involved)
- **Coordination**: None
- **Detection Risk**: Easily detected via process monitoring

**Frequency**:
- **Repeatability**: Every execution
- **Scale**: Limited to nodes running this specific script

**Overall Assessment**: High likelihood of occurrence if script is used in automation, but **NOT a security vulnerability per Immunefi criteria**.

## Recommendation

**Immediate Mitigation**: Add `process.exit()` after callback execution

**Permanent Fix**: Ensure all utility scripts properly exit after completion

**Code Changes**:

File: `byteball/ocore/tools/check_stability.js`

Add `process.exit()` after logging:
```javascript
main_chain.determineIfStableInLaterUnits(db, earlier_unit, arrLaterUnits, function (bStable) {
    console.log('--- stable? ', bStable);
    process.exit(); // Add this line
});
```

**Additional Measures**:
- Review all tools/ scripts for similar issues
- Consider using `timer.unref()` on non-critical monitoring timers in sqlite_pool.js
- Add integration tests for utility scripts to verify clean exit

## Notes

**This is NOT a valid security vulnerability** under the Immunefi Obyte Bug Bounty program criteria. 

The issue identified is:
- **Scope**: Operational/infrastructure concern in utility script
- **Impact**: Does not affect protocol security, consensus, or fund safety
- **Category**: Code quality/operational best practice

The security question posed a hypothetical about resource exhaustion, and while the technical analysis confirms the script does have a resource leak, this finding:

✗ Does not cause network transaction delays (script is optional tooling)  
✗ Does not affect protocol consensus or DAG integrity  
✗ Does not enable fund theft or freezing  
✗ Does not cause AA misbehavior  
✗ Is not exploitable by malicious actors  
✗ Does not break any of the 24 protocol invariants

**Classification**: This is a **Low/QA operational issue** (out of scope for bug bounty), not a Medium/High/Critical security vulnerability. The script is in the `tools/` directory for manual/debugging use, not part of the core protocol runtime. Proper deployment would use process managers (systemd, supervisor) that handle hung processes.

The fix is trivial (one line) and represents a coding best practice rather than a security patch. Similar to other utility scripts in the codebase [6](#0-5)  and [7](#0-6) , adding `process.exit()` ensures clean termination.

### Citations

**File:** tools/check_stability.js (L1-14)
```javascript
/*jslint node: true */
'use strict';
var db = require('../db.js');
var main_chain = require('../main_chain.js');

var args = process.argv.slice(2);
var earlier_unit = args[0];
var arrLaterUnits = args[1].split(',');

console.log("checking stability of " + earlier_unit + " in " + arrLaterUnits);

main_chain.determineIfStableInLaterUnits(db, earlier_unit, arrLaterUnits, function (bStable) {
	console.log('--- stable? ', bStable);
});
```

**File:** sqlite_pool.js (L169-169)
```javascript
		setInterval(connection.printLongQuery.bind(connection), 60 * 1000);
```

**File:** tools/supply.js (L17-23)
```javascript
storage.readLastMainChainIndex(function(last_mci){
	storage.readLastStableMcIndex(db, function(last_stable_mci){
		balances.readAllUnspentOutputs(not_circulating, function(supply) {
			console.error('readAllUnspentOutputs took '+(Date.now()-start_time)+'ms');
			console.error(Object.assign({last_mci, last_stable_mci}, supply));
			process.exit();
		});
```

**File:** tools/validate_aa_definitions.js (L28-32)
```javascript
		},
		function (err) {
			console.log('done, err = ', err);
			process.exit();
		}
```
