## Title
Arbiter Contract Status Inconsistency via Double-Spend and Missing Final-Bad Event Handling

## Summary
The arbiter contract system in `arbiter_contract.js` marks contracts as "paid" based on unconfirmed payment units without validating their sequence stability. When a payment unit later becomes `final-bad` due to double-spending at the consensus layer, contract status remains "paid" permanently, creating database inconsistency that enables fraud against payees who deliver goods/services based on incorrect status.

## Impact
**Severity**: Medium  
**Category**: Unintended Application Behavior Without Direct Fund Risk

The arbiter contract system creates permanent state inconsistency between application-layer contract status and consensus-layer unit validity. Payees see "paid" status and may deliver goods/services, but payment units are invalid (`sequence='final-bad'`). No direct theft from wallets occurs, but victims suffer indirect losses through delivery of goods/services for invalidated payments. This represents application-layer logic failure rather than consensus-layer compromise or direct fund theft.

## Finding Description

**Location**: `byteball/ocore/arbiter_contract.js`
- Function `pay()`: lines 539-564
- Event listener `new_my_transactions`: lines 663-692
- Function `openDispute()`: lines 203-262

**Intended Logic**: Contract status should reflect actual blockchain state. Contracts should only be marked "paid" when payment units have achieved stable, irreversible sequence on the DAG.

**Actual Logic**: The system marks contracts "paid" immediately upon payment unit creation or receipt, without validating sequence stability or monitoring for final-bad transitions.

**Code Evidence**:

The `pay()` function allows spending unconfirmed outputs: [1](#0-0) 

Contract status is immediately set to "paid" in the callback: [2](#0-1) 

The `new_my_transactions` event listener also sets status to "paid" upon receiving transaction: [3](#0-2) 

Input selection with `spend_unconfirmed='all'` uses empty confirmation condition: [4](#0-3) 

The protocol correctly propagates final-bad sequence to descendant units: [5](#0-4) 

Validation allows double-spends on different DAG branches (by design): [6](#0-5) 

The `openDispute()` function only checks status, not payment unit validity: [7](#0-6) 

**Exploitation Path**:

1. **Preconditions**: 
   - Attacker has wallet with `spendUnconfirmed: true` enabled
   - Attacker creates arbiter contracts with victims as payees
   - Network allows spending unconfirmed outputs (post-upgrade)

2. **Step 1 - Create Root Transaction**: 
   - Attacker creates unit T0 with outputs to their own address
   - T0 is broadcast but remains unconfirmed (sequence: 'good', MCI: null)

3. **Step 2 - Pay Contracts Using Unconfirmed Chain**:
   - Attacker calls `pay()` which invokes `sendMultiPayment` with `spend_unconfirmed: 'all'`
   - Creates unit T1 spending T0's unconfirmed outputs to pay Contract A
   - Contract A status immediately set to "paid"
   - Creates units T2, T3... in chain, each spending previous unconfirmed outputs
   - All contracts marked "paid" immediately
   - Victims see "paid" status and may deliver goods/services

4. **Step 3 - Double-Spend Root Transaction**:
   - Attacker broadcasts unit T0' that double-spends T0's outputs
   - Both T0 and T0' are valid on different DAG branches (validation allows this)
   - T0' gets included in witness units first and becomes stable
   - T0 transitions to `sequence='final-bad'`

5. **Step 4 - Propagation Without Application Update**:
   - Protocol's `propagateFinalBad()` recursively marks T1, T2, T3... as final-bad
   - Payment units are now permanently invalid at consensus layer
   - Contract statuses remain "paid" at application layer (no listener exists)
   - Database shows `status='paid'` but payment units have `sequence='final-bad'`

6. **Step 5 - Permanent Inconsistency**:
   - Victims have delivered goods/services based on "paid" status
   - Payment never actually occurred (units invalid)
   - `openDispute()` can be called but only checks status field, not unit validity
   - No automatic recovery mechanism exists

**Security Property Broken**: 
Application state synchronization with consensus layer - contract status fails to track actual payment validity through unit sequence changes.

**Root Cause Analysis**: 

The arbiter contract system has architectural separation between application state and consensus state. While the protocol correctly handles double-spends and propagates final-bad sequences at the consensus layer, `arbiter_contract.js` operates at the application layer without:

1. **Sequence validation**: No check that payment unit has `sequence='good'` before setting status
2. **Stabilization wait**: Status updated on `new_my_transactions` (fires for any received unit) rather than `my_transactions_became_stable` 
3. **Rollback mechanism**: No event listener for units becoming final-bad (compare: arbiter response has stabilization listener at lines 737-766)
4. **Validation integration**: The consensus layer correctly inherits bad sequences but application layer ignores this signal

## Impact Explanation

**Affected Assets**: Bytes (base currency) and all custom divisible/indivisible assets used in arbiter contracts

**Damage Severity**:
- **Quantitative**: Attacker can mark multiple contracts "paid" from a single root transaction chain. For N contracts at amount A each, attacker appears to pay N×A but actually pays 0 when root is double-spent.
- **Qualitative**: 
  - Permanent database inconsistency between contract status and blockchain state
  - Payees deliver goods/services for invalid payments
  - Trust degradation in arbiter contract system
  - Dispute system receives invalid cases (status shows "paid" but payment nonexistent)

**User Impact**:
- **Who**: Contract payees (expecting payment for goods/services), arbiters (processing invalid disputes)
- **Conditions**: 
  - Payee monitors contract status via application interface
  - Payee delivers goods/services upon seeing "paid" status before stabilization period
  - Attacker successfully gets double-spend root transaction to win stabilization
- **Recovery**: 
  - No automatic recovery - contracts remain "paid" indefinitely
  - Payees must manually verify payment unit existence and sequence on blockchain
  - Requires manual database correction or dispute resolution

**Systemic Risk**: 
- Attack is repeatable with different contract sets
- Multiple victims can be targeted simultaneously
- Automated systems relying on contract status API are vulnerable
- Undermines trust in application-layer smart contracts built on Obyte

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with understanding of Obyte DAG mechanics and wallet configuration
- **Resources Required**: 
  - Small capital for initial transaction (e.g., 10,000 bytes)
  - Ability to configure `spendUnconfirmed: true` in wallet
  - Network timing control to influence which double-spend branch stabilizes first
- **Technical Skill**: Medium - requires DAG understanding and double-spend timing, but no cryptographic attacks

**Preconditions**:
- **Network State**: Post-upgrade allowing unconfirmed output spending (already active)
- **Attacker State**: Created arbiter contracts with victims
- **Timing**: Must broadcast double-spend and influence witness inclusion within stabilization window (~30 seconds)

**Execution Complexity**:
- **Transaction Count**: 3 + N transactions (root, double-spend, N contract payments)
- **Coordination**: Single attacker, no multi-party coordination needed
- **Detection Risk**: Low during execution; only detectable after root becomes final-bad

**Frequency**:
- **Repeatability**: Unlimited with different contract sets
- **Scale**: Multiple contracts per attack iteration

**Overall Assessment**: Medium likelihood - attack is technically feasible and repeatable, but requires timing precision to win double-spend stabilization race. Not guaranteed but achievable with moderate effort.

## Recommendation

**Immediate Mitigation**:
Add event listener for payment units becoming final-bad:

```javascript
// In arbiter_contract.js after line 766
eventBus.on("sequence_became_bad", function(arrBadUnits) {
    db.query(
        "SELECT hash FROM wallet_arbiter_contracts \n\
        JOIN outputs ON outputs.address=shared_address \n\
        WHERE outputs.unit IN(?) AND status='paid'",
        [arrBadUnits],
        function(rows) {
            rows.forEach(function(row) {
                setField(row.hash, "status", "payment_invalid");
            });
        }
    );
});
```

**Permanent Fix**:
Only mark contracts "paid" after payment unit stabilization:

```javascript
// Replace immediate status update with stabilization listener
eventBus.on("my_transactions_became_stable", function(arrStableUnits) {
    db.query(
        "SELECT hash FROM wallet_arbiter_contracts \n\
        JOIN outputs ON outputs.address=shared_address \n\
        WHERE outputs.unit IN(?) AND status='signed'",
        [arrStableUnits],
        function(rows) {
            rows.forEach(function(row) {
                setField(row.hash, "status", "paid");
            });
        }
    );
});
```

**Additional Measures**:
- Add validation in `openDispute()` to verify payment unit has `sequence='good'`
- Add UI warning for contracts paid with unconfirmed units
- Document stabilization requirement in arbiter contract documentation
- Add monitoring for contracts with final-bad payment units

## Proof of Concept

Due to the complexity of simulating DAG consensus and witness stabilization races, a complete runnable test would require:

1. Multi-node test environment to simulate different branches
2. Witness unit simulation to control stabilization outcomes
3. Timing control to ensure double-spend root wins stabilization

The vulnerability is demonstrated through code analysis showing:
- Missing event listener for final-bad units (grep confirms no "final-bad" handling)
- Status updated on unconfirmed units (line 680)
- No validation of unit sequence before status update
- Protocol correctly propagates final-bad but application ignores it

**Notes**

This vulnerability exists at the **application layer** (arbiter contracts), not the consensus layer. The Obyte protocol correctly handles double-spends, propagates final-bad sequences, and maintains consensus. The issue is that `arbiter_contract.js` fails to integrate with these consensus mechanisms.

The impact is **indirect loss** - victims lose goods/services, not bytes from their wallets. This distinguishes it from Critical severity (direct fund theft) and places it in Medium severity (unintended application behavior). The attacker doesn't steal funds from victim addresses; rather, victims voluntarily deliver goods/services based on incorrect application state.

The attack requires precise timing to win the double-spend stabilization race, which is not guaranteed but is feasible with network positioning. The vulnerability is real and exploitable, but success depends on consensus-layer race conditions.

### Citations

**File:** arbiter_contract.js (L205-206)
```javascript
		if (objContract.status !== "paid")
			return cb("contract can't be disputed");
```

**File:** arbiter_contract.js (L547-547)
```javascript
			spend_unconfirmed: walletInstance.spendUnconfirmed ? 'all' : 'own'
```

**File:** arbiter_contract.js (L554-556)
```javascript
			setField(objContract.hash, "status", "paid", function(objContract){
				cb(null, objContract, unit);
			});
```

**File:** arbiter_contract.js (L680-680)
```javascript
					setField(contract.hash, "status", "paid", function(objContract) {
```

**File:** inputs.js (L54-55)
```javascript
	else if (spend_unconfirmed === 'all')
		confirmation_condition = '';
```

**File:** main_chain.js (L1301-1310)
```javascript
	// all future units that spent these unconfirmed units become final-bad too
	function propagateFinalBad(arrFinalBadUnits, onPropagated){
		if (arrFinalBadUnits.length === 0)
			return onPropagated();
		conn.query("SELECT DISTINCT inputs.unit, main_chain_index FROM inputs LEFT JOIN units USING(unit) WHERE src_unit IN(?)", [arrFinalBadUnits], function(rows){
			console.log("will propagate final-bad to", rows);
			if (rows.length === 0)
				return onPropagated();
			var arrSpendingUnits = rows.map(function(row){ return row.unit; });
			conn.query("UPDATE units SET sequence='final-bad' WHERE unit IN(?)", [arrSpendingUnits], function(){
```

**File:** validation.js (L1470-1492)
```javascript
					graph.determineIfIncludedOrEqual(conn, objConflictingRecord.unit, objUnit.parent_units, function(bIncluded){
						if (bIncluded){
							var error = objUnit.unit+": conflicting "+type+" in inner unit "+objConflictingRecord.unit;

							// too young (serial or nonserial)
							if (objConflictingRecord.main_chain_index > objValidationState.last_ball_mci || objConflictingRecord.main_chain_index === null)
								return cb2(error);

							// in good sequence (final state)
							if (objConflictingRecord.sequence === 'good')
								return cb2(error);

							// to be voided: can reuse the output
							if (objConflictingRecord.sequence === 'final-bad')
								return cb2();

							throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit);
						}
						else{ // arrAddressesWithForkedPath is not set when validating private payments
							if (objValidationState.arrAddressesWithForkedPath && objValidationState.arrAddressesWithForkedPath.indexOf(objConflictingRecord.address) === -1)
								throw Error("double spending "+type+" without double spending address?");
							cb2();
						}
```
