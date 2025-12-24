# Race Condition in 'seen address' Definition Evaluation Causes Consensus Divergence

## Summary

A race condition exists in address definition evaluation where `last_ball_mci` is captured early during validation but used later to query for stable units. Since validation and stabilization use non-conflicting mutex locks and run in separate DEFERRED transactions, concurrent stabilization can cause different nodes to observe different `is_stable` values for the same units, leading to non-deterministic definition evaluation and permanent chain splits.

## Impact

**Severity**: Critical  
**Category**: Permanent Chain Split Requiring Hard Fork

The entire network can permanently fork into incompatible branches where some nodes accept a unit while others reject it. All transactions after the divergence point exist only on one fork. Recovery requires a hard fork with manual chain reconciliation affecting all network participants.

## Finding Description

**Location**: `byteball/ocore/definition.js:748-760` (function `validateAuthentifiers()` → `evaluate()`) and `byteball/ocore/validation.js:598`

**Intended Logic**: Address definitions containing `['seen address', 'ADDRESS']` should deterministically evaluate identically on all nodes by checking if the address appeared in any stable unit with MCI ≤ last_ball_mci.

**Actual Logic**: The validation state `last_ball_mci` is captured early [1](#0-0) , but the stability status check occurs much later during definition evaluation [2](#0-1) . Between these moments, the stabilization process can mark units as stable, causing race conditions.

**Root Cause Analysis**:

1. **Non-conflicting mutex locks**: Validation acquires locks on author addresses [3](#0-2) , while stabilization acquires the "write" lock [4](#0-3) . These are different lock keys that don't conflict.

2. **Async stabilization**: When `determineIfStableInLaterUnitsAndUpdateStableMcFlag()` determines a unit is stable in view of parents, it calls `handleResult(bStable, true)` immediately [5](#0-4) , allowing validation to proceed. Only afterward does it acquire the "write" lock and update the database.

3. **DEFERRED transaction isolation**: Both validation and stabilization use `conn.query("BEGIN")` [6](#0-5)  without IMMEDIATE or EXCLUSIVE modifiers, starting DEFERRED transactions that can see committed changes from concurrent transactions.

4. **Temporal gap**: From when `last_ball_mci` is captured to when the "seen address" query executes, stabilization can commit updates to the `is_stable` flag [7](#0-6) .

**Exploitation Path**:

1. **Preconditions**: 
   - Unit Y exists at MCI=90 with address "ATTACKER_ADDR", currently unstable (is_stable=0)
   - Attacker can create units with custom address definitions

2. **Step 1**: Attacker creates Unit X with address definition `["and", [["sig", {pubkey: "KEY"}], ["not", ["seen address", "ATTACKER_ADDR"]]]]` and last_ball referencing MCI=100

3. **Step 2**: Unit X propagates to network nodes that start validation at slightly different times

4. **Step 3 - Node A**:
   - Validation starts, captures last_ball_mci=100
   - Passes last_ball stability check
   - Meanwhile, stabilization marks MCI=90 as stable
   - Definition evaluation queries for "seen address" 
   - Query finds Unit Y with is_stable=1, returns true
   - Definition evaluates: ["not", true] = false
   - **Rejects Unit X**

5. **Step 4 - Node B**:
   - Validation starts, captures last_ball_mci=100  
   - Passes last_ball stability check
   - Definition evaluation queries for "seen address"
   - Unit Y still has is_stable=0 (stabilization hasn't committed)
   - Query finds no stable units, returns false
   - Definition evaluates: ["not", false] = true
   - **Accepts Unit X**

6. **Step 5**: Permanent consensus divergence - Node A's DAG excludes Unit X while Node B's DAG includes it, creating incompatible forks.

**Security Property Broken**: Definition Evaluation Integrity - Address definitions must evaluate identically across all nodes to maintain consensus.

## Impact Explanation

**Affected Assets**: All units, bytes, and custom assets in descendant units from the divergence point

**Damage Severity**:
- **Quantitative**: Entire network splits into incompatible chains with all transactions after the split valid only on one fork
- **Qualitative**: Catastrophic consensus failure requiring community coordination on canonical chain

**User Impact**:
- **Who**: All network participants
- **Conditions**: Exploitable whenever validation coincides with stabilization (frequent during normal operation)
- **Recovery**: Hard fork required with manual transaction history reconciliation

**Systemic Risk**: 
- Repeatable attack creating multiple chain splits
- Can trigger naturally without malicious intent
- Light clients cannot detect splits without full validation

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with standard wallet capabilities
- **Resources**: Minimal - standard unit submission fees
- **Technical Skill**: Understanding of address definitions and stabilization timing

**Preconditions**:
- **Network State**: Normal operation with active stabilization
- **Attacker State**: Ability to submit units with custom definitions
- **Timing**: Submit during stabilization window (common occurrence)

**Execution Complexity**:
- **Transaction Count**: Single unit submission
- **Coordination**: None - can occur accidentally
- **Detection Risk**: Undetectable until chain split manifests

**Frequency**:
- **Repeatability**: Unlimited with any custom definition referencing "seen address"
- **Scale**: Single execution splits entire network

**Overall Assessment**: High likelihood - race window exists during every concurrent validation and stabilization, even triggerable without malicious intent.

## Recommendation

**Immediate Mitigation**:

Ensure stability check uses the same database snapshot as definition evaluation by reading is_stable values within a single atomic query, or enforce that all units with MCI ≤ last_ball_mci must already be marked stable before validation proceeds.

**Permanent Fix**:

Option 1: Modify `determineIfStableInLaterUnitsAndUpdateStableMcFlag()` to block validation until stabilization completes:

```javascript
// In main_chain.js, line 1159
// Remove: handleResult(bStable, true);
// Instead: Wait for stabilization before calling handleResult
```

Option 2: Add validation check requiring last_ball_unit must be is_stable=1 in database (uncomment and enforce check at validation.js:590-591).

Option 3: Use IMMEDIATE transactions for validation to acquire locks earlier, preventing concurrent stabilization.

**Validation**:
- Prevents non-deterministic definition evaluation
- Maintains consensus across all nodes
- May impact performance due to serialized validation/stabilization

## Proof of Concept

Due to the complexity of demonstrating race conditions in a test environment, a complete PoC would require:

```javascript
// Conceptual test structure
async function testSeenAddressRaceCondition() {
  // Setup: Create Unit Y at MCI=90 with test address, keep unstable
  // Action 1: Start validation of Unit X with last_ball_mci=100
  // Action 2: Concurrently trigger stabilization of MCI=90
  // Assert: Different nodes reach different validation results
}
```

The race window is timing-dependent and may require multiple attempts to trigger reliably. Production exploitation would monitor network stabilization activity and submit units during these windows.

---

**Notes**: This vulnerability stems from the fundamental architecture where validation and stabilization are intentionally decoupled for performance. The commented-out stability check at validation.js:590-591 suggests prior awareness of last_ball stability concerns, but the current implementation allows unstable last_ball_mci values, creating the race condition window.

### Citations

**File:** validation.js (L223-223)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
```

**File:** validation.js (L244-244)
```javascript
						conn.query("BEGIN", function(){cb();});
```

**File:** validation.js (L598-598)
```javascript
					objValidationState.last_ball_mci = objLastBallUnitProps.main_chain_index;
```

**File:** definition.js (L751-758)
```javascript
				conn.query(
					"SELECT 1 FROM unit_authors CROSS JOIN units USING(unit) \n\
					WHERE address=? AND main_chain_index<=? AND sequence='good' AND is_stable=1 \n\
					LIMIT 1",
					[seen_address, objValidationState.last_ball_mci],
					function(rows){
						cb2(rows.length > 0);
					}
```

**File:** main_chain.js (L1159-1159)
```javascript
		handleResult(bStable, true);
```

**File:** main_chain.js (L1163-1163)
```javascript
		mutex.lock(["write"], async function(unlock){
```

**File:** main_chain.js (L1230-1232)
```javascript
	conn.query(
		"UPDATE units SET is_stable=1 WHERE is_stable=0 AND main_chain_index=?", 
		[mci], 
```
