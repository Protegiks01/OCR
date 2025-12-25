# Audit Report: Unbounded TPS Fee Parameters Enable Permanent Network Halt via Governance Attack

## Summary

System variable validation for TPS fee parameters lacks economic bounds enforcement, accepting any positive finite number. The protocol's governance mechanism allows stakeholders controlling 10% of supply to vote extreme values that render the exponential fee formula catastrophically high, permanently halting all transaction processing with no emergency recovery mechanism.

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

Complete network shutdown affecting all 1e15 bytes in circulation. Once extreme fee parameters take effect, all transaction submissions fail validation because calculated `min_tps_fee` exceeds maximum possible user balance. Recovery requires hard fork since governance system cannot function without transaction processing capability.

## Finding Description

**Location**: `byteball/ocore/validation.js:1692-1698`, function `validateMessage()`

**Intended Logic**: System variable validation should enforce economic bounds preventing catastrophic network failure, consistent with how `threshold_size` has minimum bounds of 1000 bytes to ensure operational viability.

**Actual Logic**: Validation only checks positive finite number constraint without considering economic implications of the exponential fee formula. [1](#0-0) 

Compare with `threshold_size` which demonstrates awareness of bounds validation: [2](#0-1) 

**Exploitation Path**:

1. **Preconditions**: Attacker controls addresses holding ≥10% of total supply (1e14 bytes). Threshold defined: [3](#0-2) [4](#0-3) 

2. **Step 1**: Attacker submits `system_vote` messages voting `base_tps_fee = 1e50`. Validation accepts since 1e50 satisfies positive finite number check (lines 1695-1696).

3. **Step 2**: After sufficient balance accumulation, `system_vote_count` message triggers vote counting: [5](#0-4) 

4. **Step 3**: Vote counting calculates balance-weighted median and stores directly without bounds validation: [6](#0-5) 

5. **Step 4**: TPS fee calculation retrieves extreme value and applies exponential formula: [7](#0-6) 

   With `base_tps_fee = 1e50`, `tps_interval = 1`, `tps_fee_multiplier = 10`, and minimal `tps ≈ 1`:
   - Formula: `Math.round(10 * 1e50 * (Math.exp(1) - 1))` ≈ 1.72e51 bytes
   - This exceeds total supply (1e15) by factor of 1.72e36

6. **Step 5**: All subsequent transactions fail validation: [8](#0-7) 

   With `min_tps_fee ≈ 1.72e51`, no user can satisfy balance requirement since maximum possible balance is 1e15 bytes.

7. **Step 6**: Emergency recovery impossible. Emergency vote counting only supports `op_list`: [9](#0-8) 

   Fee parameters (lines 1787-1811) have no emergency override mechanism. Normal governance cannot rectify the situation since all transaction processing is blocked.

**Security Property Broken**: Network liveness invariant - the protocol must maintain ability for legitimate users to submit valid transactions under all governance-approved parameter configurations.

**Root Cause Analysis**: 

The codebase demonstrates explicit awareness of bounds validation through `threshold_size` minimum enforcement, yet fails to apply equivalent economic bounds to TPS fee parameters despite the exponential formula making extreme values network-destroying. No maximum bounds, overflow protections, or emergency recovery mechanisms exist for these parameters, creating an irreversible denial-of-service vector through legitimate governance channels.

## Impact Explanation

**Affected Assets**: All bytes (native currency), custom assets, autonomous agent operations, entire network functionality

**Damage Severity**:
- **Quantitative**: 100% of network transactions permanently blocked. All 1e15 bytes effectively frozen. Recovery requires coordinated hard fork across all nodes.
- **Qualitative**: Complete loss of network utility. All economic activity ceases. Smart contracts cannot execute. Users cannot access funds until hard fork deployment.

**User Impact**:
- **Who**: All network participants - users, witnesses, exchanges, DApp operators, autonomous agents
- **Conditions**: Immediately upon malicious vote taking effect at next MCI stabilization
- **Recovery**: Requires hard fork with manual intervention since governance system cannot function without transaction processing

**Systemic Risk**:
- Attack executes atomically - entire network halts simultaneously
- No gradual degradation or early warning signals
- Cannot be reversed through any protocol mechanism
- Enables ransom attacks or competitor sabotage

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Large stakeholder, compromised exchange, coordinated group, or nation-state actor
- **Resources Required**: Control of 1e14 bytes (10% of supply)
- **Technical Skill**: Medium - requires understanding governance system and ability to submit system_vote messages

**Preconditions**:
- **Network State**: Normal operation with v4 upgrade active: [10](#0-9) 
- **Attacker State**: Must control or coordinate 10% supply holders to vote extreme values
- **Timing**: Vote counting triggers when sufficient balance votes accumulate

**Execution Complexity**:
- **Transaction Count**: Single `system_vote` message (or coordinated set totaling 10%+ supply), plus one `system_vote_count` message
- **Coordination**: Requires either single large holder or multi-party coordination
- **Detection Risk**: Votes visible on-chain but appear legitimate until effects manifest

**Overall Assessment**: Medium-High likelihood. While 10% threshold creates barrier, exchanges routinely hold such amounts. Economic incentives exist for short sellers, ransom attackers, or competing projects. Catastrophic impact and lack of emergency reversal mechanism elevate risk.

## Recommendation

**Immediate Mitigation**:
Add economic bounds validation for TPS fee parameters consistent with `threshold_size` precedent:

```javascript
// File: byteball/ocore/validation.js
// Lines 1692-1698

case "base_tps_fee":
case "tps_interval":
case "tps_fee_multiplier":
    if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
        return callback(payload.subject + " must be a positive number");
    // Add maximum bounds to prevent network halt
    const MAX_BASE_TPS_FEE = 1e9; // Example: 1GB max base fee
    const MAX_TPS_INTERVAL = 1000; // Example: max interval
    const MAX_TPS_FEE_MULTIPLIER = 1000; // Example: max multiplier
    if (payload.subject === "base_tps_fee" && payload.value > MAX_BASE_TPS_FEE)
        return callback("base_tps_fee exceeds maximum " + MAX_BASE_TPS_FEE);
    if (payload.subject === "tps_interval" && payload.value > MAX_TPS_INTERVAL)
        return callback("tps_interval exceeds maximum " + MAX_TPS_INTERVAL);
    if (payload.subject === "tps_fee_multiplier" && payload.value > MAX_TPS_FEE_MULTIPLIER)
        return callback("tps_fee_multiplier exceeds maximum " + MAX_TPS_FEE_MULTIPLIER);
    callback();
    break;
```

**Permanent Fix**:
1. Add emergency recovery mechanism for TPS fee parameters in `main_chain.js:countVotes()` similar to existing `op_list` emergency support
2. Implement sanity checks in `storage.js:getLocalTpsFee()` that cap calculated fees at reasonable maximums
3. Add monitoring alerts when TPS fee parameters approach dangerous thresholds

**Additional Measures**:
- Add test case verifying extreme parameter values are rejected
- Add database trigger preventing insertion of out-of-bounds system variable values
- Document rationale for chosen bounds in protocol specification

## Notes

The critical distinction is between trusting governance participants versus ensuring governance cannot vote parameters that fundamentally break network operation. The protocol already demonstrates this principle through `threshold_size` bounds validation. The inconsistency in applying bounds to TPS fee parameters, combined with their exponential formula and lack of emergency recovery, represents a design oversight rather than intentional governance flexibility. The 10% voting threshold is a governance mechanism, not a security boundary - the protocol should prevent any governance outcome that renders the network inoperable.

### Citations

**File:** validation.js (L916-917)
```javascript
		if (tps_fees_balance + objUnit.tps_fee * share < min_tps_fee * share)
			return callback(`tps_fee ${objUnit.tps_fee} + tps fees balance ${tps_fees_balance} less than required ${min_tps_fee} for address ${address} whose share is ${share}`);
```

**File:** validation.js (L1646-1647)
```javascript
			if (objValidationState.last_ball_mci < constants.v4UpgradeMci && !constants.bDevnet)
				return callback("cannot vote for system params yet");
```

**File:** validation.js (L1683-1690)
```javascript
				case "threshold_size":
					if (!isPositiveInteger(payload.value))
						return callback(payload.subject + " must be a positive integer");
					if (!constants.bTestnet || objValidationState.last_ball_mci > 3543000) {
						if (payload.value < 1000)
							return callback(payload.subject + " must be at least 1000");
					}
					callback();
```

**File:** validation.js (L1692-1698)
```javascript
				case "base_tps_fee":
				case "tps_interval":
				case "tps_fee_multiplier":
					if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
						return callback(payload.subject + " must be a positive number");
					callback();
					break;
```

**File:** constants.js (L15-15)
```javascript
exports.TOTAL_WHITEBYTES = process.env.TOTAL_WHITEBYTES || 1e15;
```

**File:** constants.js (L71-71)
```javascript
exports.SYSTEM_VOTE_COUNT_FEE = 1e9;
```

**File:** constants.js (L72-72)
```javascript
exports.SYSTEM_VOTE_MIN_SHARE = 0.1;
```

**File:** main_chain.js (L1645-1648)
```javascript
async function countVotes(conn, mci, subject, is_emergency = 0, emergency_count_command_timestamp = 0) {
	console.log('countVotes', mci, subject, is_emergency, emergency_count_command_timestamp);
	if (is_emergency && subject !== "op_list")
		throw Error("emergency vote count supported for op_list only, got " + subject);
```

**File:** main_chain.js (L1787-1818)
```javascript
		case "base_tps_fee":
		case "tps_interval":
		case "tps_fee_multiplier":
			const rows = await conn.query(`SELECT value, SUM(balance) AS total_balance
				FROM numerical_votes
				CROSS JOIN voter_balances USING(address)
				WHERE timestamp>=? AND subject=?
				GROUP BY value
				ORDER BY value`,
				[since_timestamp, subject]
			);
			console.log(`total votes for`, subject, rows);
			const total_voted_balance = rows.reduce((acc, row) => acc + row.total_balance, 0);
			let accumulated = 0;
			for (let { value: v, total_balance } of rows) {
				accumulated += total_balance;
				if (accumulated >= total_voted_balance / 2) {
					value = v;
					break;
				}
			}
			if (value === undefined)
				throw Error(`no median value for ` + subject);
			storage.systemVars[subject].unshift({ vote_count_mci: mci, value, is_emergency });
			break;
		
		default:
			throw Error("unknown subject in countVotes: " + subject);
	}
	console.log(`new`, subject, value);
	// a repeated emergency vote on the same mci would overwrite the previous one
	await conn.query(`${is_emergency || mci === 0 ? 'REPLACE' : 'INSERT'} INTO system_vars (subject, value, vote_count_mci, is_emergency) VALUES (?, ?, ?, ?)`, [subject, value, mci === 0 ? -1 : mci, is_emergency]);
```

**File:** storage.js (L1292-1301)
```javascript
async function getLocalTpsFee(conn, objUnitProps, count_units = 1) {
	const objLastBallUnitProps = await readUnitProps(conn, objUnitProps.last_ball_unit);
	const last_ball_mci = objLastBallUnitProps.main_chain_index;
	const base_tps_fee = getSystemVar('base_tps_fee', last_ball_mci); // unit's mci is not known yet
	const tps_interval = getSystemVar('tps_interval', last_ball_mci);
	const tps_fee_multiplier = getSystemVar('tps_fee_multiplier', last_ball_mci);
	const tps = await getLocalTps(conn, objUnitProps, count_units);
	console.log(`local tps at ${objUnitProps.unit} ${tps}`);
	const tps_fee_per_unit = Math.round(tps_fee_multiplier * base_tps_fee * (Math.exp(tps / tps_interval) - 1));
	return count_units * tps_fee_per_unit;
```
