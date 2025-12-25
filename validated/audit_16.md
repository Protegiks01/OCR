# Audit Report: Unbounded TPS Fee Parameters Enable Permanent Network Halt via Governance Attack

## Summary

System variable validation for TPS fee parameters (`base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) accepts any positive finite number without economic bounds, enabling stakeholders controlling 10% of supply to vote catastrophically high values. The exponential fee calculation formula then produces astronomical `min_tps_fee` requirements exceeding total network supply, permanently halting all transaction processing with no emergency recovery mechanism.

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

Complete and permanent network shutdown affecting all 1e15 bytes in circulation. All transaction submissions fail validation because calculated `min_tps_fee` exceeds maximum possible user balance. Recovery requires coordinated hard fork since governance system cannot function without transaction processing capability.

## Finding Description

**Location**: `byteball/ocore/validation.js:1692-1698`, function `validateMessage()`

**Intended Logic**: System variable validation should enforce economic bounds preventing catastrophic network failure, consistent with how `threshold_size` has minimum bounds of 1000 bytes to ensure operational viability.

**Actual Logic**: Validation only checks that TPS fee parameters are positive finite numbers without considering economic implications of the exponential fee formula. [1](#0-0) 

Contrast this with `threshold_size` which demonstrates the codebase's awareness of bounds validation: [2](#0-1) 

**Exploitation Path**:

1. **Preconditions**: Attacker controls addresses holding ≥10% of total supply (1e14 bytes). The voting threshold is defined as: [3](#0-2) [4](#0-3) [5](#0-4) 

2. **Step 1**: Attacker submits `system_vote` messages voting `base_tps_fee = 1e50`. Validation accepts this value since it satisfies the positive finite number check.

3. **Step 2**: After sufficient balance accumulation, `system_vote_count` message triggers vote counting.

4. **Step 3**: Vote counting calculates balance-weighted median and stores the value directly without additional bounds validation: [6](#0-5) 

5. **Step 4**: TPS fee calculation retrieves the extreme value and applies the exponential formula: [7](#0-6) 

With `base_tps_fee = 1e50`, `tps_interval = 1`, `tps_fee_multiplier = 10`, and minimal `tps ≈ 1`:
- Formula: `Math.round(10 * 1e50 * (Math.exp(1) - 1))` ≈ 1.72e51 bytes
- This exceeds total supply (1e15) by factor of 1.72e36

6. **Step 5**: All subsequent transactions fail validation because no user can satisfy the astronomical fee requirement: [8](#0-7) 

With `min_tps_fee ≈ 1.72e51`, the condition `tps_fees_balance + objUnit.tps_fee < min_tps_fee` is always true since maximum possible balance is 1e15 bytes.

7. **Step 6**: Emergency recovery is impossible. Emergency vote counting only supports `op_list`: [9](#0-8) 

TPS fee parameters have no emergency override mechanism. Normal governance cannot rectify the situation since all transaction processing is blocked.

**Security Property Broken**: Network liveness invariant - the protocol must maintain the ability for legitimate users to submit valid transactions under all governance-approved parameter configurations.

**Root Cause Analysis**: 

The codebase explicitly enforces minimum bounds on `threshold_size` (≥1000 bytes) to ensure operational viability, demonstrating awareness of the need for bounds validation. However, this protection is not applied to TPS fee parameters despite the exponential formula making extreme values network-destroying. No maximum bounds, overflow protections, or emergency recovery mechanisms exist for these parameters.

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
- **Network State**: Normal operation with v4 upgrade active
- **Attacker State**: Must control or coordinate 10% supply holders to vote extreme values
- **Timing**: Vote counting triggers when sufficient balance votes accumulate

**Execution Complexity**:
- **Transaction Count**: Single `system_vote` message (or coordinated set totaling 10%+ supply), plus one `system_vote_count` message
- **Coordination**: Requires either single large holder or multi-party coordination
- **Detection Risk**: Votes visible on-chain but appear legitimate until effects manifest

**Overall Assessment**: Medium-High likelihood. While 10% threshold creates a barrier, exchanges routinely hold such amounts. Economic incentives exist for short sellers, ransom attackers, or competing projects. Catastrophic impact and lack of emergency reversal mechanism elevate risk.

## Recommendation

**Immediate Mitigation**:
Add maximum bounds validation for TPS fee parameters to prevent economically catastrophic values:

```javascript
// File: byteball/ocore/validation.js
// Lines: 1692-1698 (modify)

case "base_tps_fee":
case "tps_fee_multiplier":
    if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
        return callback(payload.subject + " must be a positive number");
    if (payload.value > 1e9) // maximum reasonable fee
        return callback(payload.subject + " must not exceed 1e9");
    callback();
    break;
case "tps_interval":
    if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
        return callback(payload.subject + " must be a positive number");
    if (payload.value < 0.1) // minimum to prevent division issues
        return callback(payload.subject + " must be at least 0.1");
    callback();
    break;
```

**Permanent Fix**:
1. Add economic bounds validation consistent with `threshold_size` enforcement
2. Implement emergency recovery mechanism for all system variables, not just `op_list`
3. Add safety checks in TPS fee calculation to cap at reasonable maximum (e.g., total supply)

**Additional Measures**:
- Add test case verifying extreme TPS fee parameter votes are rejected
- Add monitoring for system variable votes approaching unsafe thresholds
- Document safe ranges for all system parameters
- Consider requiring supermajority (e.g., 67%) for changes to critical fee parameters

## Notes

This vulnerability exploits the governance mechanism itself - a legitimate protocol feature - to achieve network shutdown. The inconsistency between `threshold_size` having minimum bounds (1000 bytes) while TPS fee parameters have no bounds demonstrates this is an oversight rather than intentional design. The exponential nature of the fee formula (`Math.exp()`) makes unbounded parameters particularly dangerous, as even moderately extreme values can produce catastrophic results.

### Citations

**File:** validation.js (L912-917)
```javascript
	for (let address in recipients) {
		const share = recipients[address] / 100;
		const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, objValidationState.last_ball_mci]);
		const tps_fees_balance = row ? row.tps_fees_balance : 0;
		if (tps_fees_balance + objUnit.tps_fee * share < min_tps_fee * share)
			return callback(`tps_fee ${objUnit.tps_fee} + tps fees balance ${tps_fees_balance} less than required ${min_tps_fee} for address ${address} whose share is ${share}`);
```

**File:** validation.js (L1683-1691)
```javascript
				case "threshold_size":
					if (!isPositiveInteger(payload.value))
						return callback(payload.subject + " must be a positive integer");
					if (!constants.bTestnet || objValidationState.last_ball_mci > 3543000) {
						if (payload.value < 1000)
							return callback(payload.subject + " must be at least 1000");
					}
					callback();
					break;
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

**File:** main_chain.js (L1712-1712)
```javascript
		if (total_balance >= constants.SYSTEM_VOTE_MIN_SHARE * constants.TOTAL_WHITEBYTES)
```

**File:** main_chain.js (L1786-1818)
```javascript
		case "threshold_size":
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

**File:** storage.js (L1292-1302)
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
}
```
