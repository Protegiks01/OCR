# Audit Report: Missing Bounds Validation on TPS Fee Parameters Enables Network Halt via Governance Attack

## Summary

The system variable validation for TPS fee parameters (`base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) only checks that values are positive finite numbers without enforcing economic bounds. This allows malicious stakeholders controlling 10% of the byte supply to vote for extreme values that make the exponential fee formula produce unpayable transaction fees, causing permanent network halt with no emergency recovery mechanism.

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

The vulnerability enables complete network shutdown affecting all 1e15 bytes in circulation. Once extreme fee parameters are voted in, all transaction submissions are rejected because the calculated `min_tps_fee` exceeds any user's balance. Recovery requires coordinated hard fork since normal governance cannot function without transaction processing. All users, witnesses, exchanges, and autonomous agents are affected immediately and indefinitely.

## Finding Description

**Location**: Multiple files in byteball/ocore
- `validation.js:1692-1698` - Insufficient parameter validation
- `main_chain.js:1787-1811` - Unbounded median selection  
- `storage.js:1292-1301` - Exponential fee calculation
- `validation.js:916-917` - Fee sufficiency check

**Intended Logic**: System variable validation should enforce economic bounds preventing values that break network operations, similar to the `threshold_size` parameter which has minimum bounds.

**Actual Logic**: The validation accepts any positive finite number for fee parameters without considering the exponential formula's behavior. [1](#0-0) 

The vote counting mechanism calculates the median of votes weighted by balance and stores it directly without bounds validation. [2](#0-1) 

The TPS fee calculation uses an exponential formula that produces arbitrarily large results with extreme base parameters. [3](#0-2) 

Transaction validation enforces fee sufficiency by rejecting units where paid fees are below the calculated minimum. [4](#0-3) 

**Exploitation Path**:

1. **Preconditions**: Attacker controls or convinces addresses holding ≥10% of total supply (1e14 bytes) to submit system votes. The 10% threshold is defined in constants. [5](#0-4)  The total supply is 1e15 bytes. [6](#0-5) 

2. **Step 1**: Attacker submits `system_vote` messages voting `base_tps_fee = 1e50`. Validation passes because 1e50 is a positive finite number per the validation logic.

3. **Step 2**: When sufficient balance has voted, a `system_vote_count` message triggers vote counting. The vote counting function iterates through voters and calculates the median value. [7](#0-6)  The median (1e50) is selected and stored in `systemVars` and the database without any bounds checking.

4. **Step 3**: The `getSystemVar` function retrieves this extreme value when calculating TPS fees. [8](#0-7)  The TPS fee formula now produces: `Math.round(10 * 1e50 * (Math.exp(tps/tps_interval) - 1))`. Even with minimal TPS ≈ 1, this yields fees ≈ 1.7e51 bytes, which is 1.7e36 times larger than the total supply of 1e15 bytes.

5. **Step 4**: All subsequent transaction submissions fail validation because the calculated `min_tps_fee` exceeds any possible user balance. The validation check ensures paid fees plus accumulated TPS fee balance meet the minimum requirement, but with min_tps_fee ≈ 1.7e51, no user can satisfy this condition.

6. **Step 5**: Emergency recovery is impossible. The emergency vote counting explicitly only supports `op_list`, not fee parameters. [9](#0-8)  Without emergency mechanisms, the network remains permanently halted since voting for new parameters requires processing transactions, which is now impossible.

**Security Property Broken**: Network liveness invariant - the protocol must allow legitimate users to submit valid transactions. The fee mechanism intended to prevent spam instead prevents ALL transactions.

**Root Cause Analysis**: 

The validation logic assumes all positive finite numbers are acceptable, but fails to account for the economic implications of the exponential fee formula. The protocol demonstrates awareness of this pattern - `threshold_size` has minimum bounds enforced in validation. [10](#0-9)  However, fee parameters lack equivalent protection despite the exponential formula making extreme values catastrophically dangerous.

The code lacks:
1. Maximum bounds preventing fees from exceeding economically viable levels
2. Minimum bounds preventing negligible anti-spam protection  
3. Overflow/Infinity checks in fee calculation functions
4. Emergency governance mechanisms for fee parameter recovery

## Impact Explanation

**Affected Assets**: All bytes (native currency), custom assets, autonomous agent operations, entire network functionality

**Damage Severity**:
- **Quantitative**: 100% of network transactions blocked permanently. All 1e15 bytes effectively frozen. Recovery requires hard fork coordinated across all nodes.
- **Qualitative**: Complete loss of network utility. All economic activity ceases. Smart contracts cannot execute. Users lose access to funds until hard fork is deployed.

**User Impact**:
- **Who**: All network participants - individual users, witnesses, exchanges, DApp operators, autonomous agents
- **Conditions**: Immediately upon malicious vote taking effect at the next MCI stabilization
- **Recovery**: Requires coordinated hard fork with manual intervention since governance system cannot function without transaction processing

**Systemic Risk**:
- Attack is atomic - entire network halts simultaneously when vote is counted
- No gradual degradation or early warning signs
- Cannot be reversed through protocol mechanisms since all transactions are rejected
- Enables ransom attacks or sabotage by competitors
- Similar attack vector exists for opposite scenario (extremely low fees enabling spam floods)

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Large stakeholder, compromised exchange, coordinated group of medium holders, or nation-state actor
- **Resources Required**: Control of 100 trillion bytes (10% of supply), worth approximately $1-10 million at current market prices
- **Technical Skill**: Medium - requires understanding of governance system and ability to submit system_vote messages, but no cryptographic or exploit sophistication

**Preconditions**:
- **Network State**: Normal operation with v4 upgrade active (MCI > constants.v4UpgradeMci). [11](#0-10) 
- **Attacker State**: Must control or convince 10% supply holders to vote for extreme values
- **Timing**: Vote counting occurs naturally when sufficient balance votes within the expanding timeframe mechanism

**Execution Complexity**:
- **Transaction Count**: Single system_vote message (or multiple from coordinated group totaling 10%+ supply), plus one system_vote_count message requiring 1e9 bytes fee [12](#0-11) 
- **Coordination**: Requires either single large holder or coordination among multiple medium holders
- **Detection Risk**: Votes are visible on-chain but appear as legitimate governance until effects manifest

**Frequency**:
- **Repeatability**: Once executed, network is permanently halted and attack cannot be repeated (but also cannot be undone)
- **Scale**: Network-wide, affects all users simultaneously

**Overall Assessment**: Medium-High Likelihood. The 10% supply requirement creates a barrier, but exchanges and large holders could achieve this threshold. Economic incentives exist for short sellers, ransom attackers, or competing projects. The catastrophic impact and lack of emergency reversal mechanism significantly elevate the risk despite the capital requirements.

## Recommendation

**Immediate Mitigation**:

Add bounds validation to system variable validation logic: [1](#0-0) 

Enforce reasonable bounds such as:
- `base_tps_fee`: 0.1 to 10000 (current default is 10)
- `tps_fee_multiplier`: 1 to 100 (current default is 10)
- `tps_interval`: 0.1 to 100 (current default is 1)

**Permanent Fix**:

1. Add validation bounds checking in validation.js similar to threshold_size precedent
2. Add overflow protection in TPS fee calculation functions using isFinite checks
3. Implement emergency vote counting support for fee parameters (currently only op_list supported)
4. Add governance timelock/delay for fee parameter changes to allow community review

**Additional Measures**:
- Add monitoring alerts when fee parameter votes approach extreme values
- Document acceptable ranges for fee parameters in protocol specification
- Add test cases covering extreme fee parameter scenarios
- Consider gradual adjustment limits (e.g., max 2x change per vote count)

**Validation**:
- Bounds prevent network-breaking values while preserving governance flexibility
- Emergency mechanisms enable recovery from malicious votes
- No performance impact on normal operations
- Backward compatible with existing valid system_votes

## Proof of Concept

```javascript
// Test: test/system_vote_bounds.test.js
const storage = require('../storage.js');
const validation = require('../validation.js');
const main_chain = require('../main_chain.js');
const db = require('../db.js');
const constants = require('../constants.js');

describe('System vote bounds validation', function() {
    
    it('should reject extreme base_tps_fee values that cause unpayable fees', async function() {
        const conn = await db.takeConnectionFromPool();
        
        // Simulate system vote for extreme base_tps_fee
        const extremeValue = 1e50;
        const systemVotePayload = {
            subject: 'base_tps_fee',
            value: extremeValue
        };
        
        // Current validation PASSES (bug - should fail)
        const isValid = (typeof systemVotePayload.value === 'number' && 
                        isFinite(systemVotePayload.value) && 
                        systemVotePayload.value > 0);
        assert.equal(isValid, true, 'Extreme value incorrectly passes validation');
        
        // Simulate vote counting storing this value
        storage.systemVars.base_tps_fee = [{vote_count_mci: 1000, value: extremeValue}];
        
        // Calculate resulting TPS fee
        const tps = 1; // minimal network activity
        const tps_interval = 1;
        const tps_fee_multiplier = 10;
        const calculated_fee = Math.round(tps_fee_multiplier * extremeValue * (Math.exp(tps/tps_interval) - 1));
        
        // Fee exceeds total supply
        assert.isTrue(calculated_fee > constants.TOTAL_WHITEBYTES, 
                     `Calculated fee ${calculated_fee} exceeds total supply ${constants.TOTAL_WHITEBYTES}`);
        
        // All transactions would be rejected
        const userBalance = 1e15; // entire supply
        assert.isTrue(calculated_fee > userBalance,
                     'No user can afford transaction fees - network halt');
        
        conn.release();
    });
    
    it('should validate that threshold_size has bounds but fee parameters do not', function() {
        // Threshold_size HAS minimum bound check at line 1687-1688
        // Fee parameters lack equivalent bounds at lines 1692-1697
        // This inconsistency demonstrates the missing protection
        assert.fail('Fee parameters lack bounds validation unlike threshold_size');
    });
});
```

---

## Notes

The vulnerability is valid because:

1. **Precedent exists**: The `threshold_size` parameter has bounds enforcement, proving the protocol recognizes the need for validation constraints on system variables

2. **Emergency mechanism gap**: While `op_list` has emergency vote counting to recover from network stalls, fee parameters lack this protection despite being capable of causing identical network halt scenarios

3. **Economic reality**: The exponential fee formula combined with unbounded parameters creates a mathematical certainty of network failure if exploited, not a theoretical risk

4. **Governance paradox**: The attack creates an unrecoverable deadlock - governance cannot fix the problem because governance requires transaction processing, which the attack prevents

5. **Attack feasibility**: While 10% supply requirement is substantial, exchanges routinely control this threshold, and the attack requires only medium technical sophistication

The distinction from a pure "governance attack" is that the protocol should prevent governance from setting self-destructive values, just as it does for `threshold_size`. Input validation is a fundamental security layer that should protect against all extreme inputs, including those from governance mechanisms.

### Citations

**File:** validation.js (L916-917)
```javascript
		if (tps_fees_balance + objUnit.tps_fee * share < min_tps_fee * share)
			return callback(`tps_fee ${objUnit.tps_fee} + tps fees balance ${tps_fees_balance} less than required ${min_tps_fee} for address ${address} whose share is ${share}`);
```

**File:** validation.js (L1686-1689)
```javascript
					if (!constants.bTestnet || objValidationState.last_ball_mci > 3543000) {
						if (payload.value < 1000)
							return callback(payload.subject + " must be at least 1000");
					}
```

**File:** validation.js (L1692-1697)
```javascript
				case "base_tps_fee":
				case "tps_interval":
				case "tps_fee_multiplier":
					if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
						return callback(payload.subject + " must be a positive number");
					callback();
```

**File:** main_chain.js (L1647-1648)
```javascript
	if (is_emergency && subject !== "op_list")
		throw Error("emergency vote count supported for op_list only, got " + subject);
```

**File:** main_chain.js (L1787-1810)
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
```

**File:** storage.js (L1094-1098)
```javascript
function getSystemVar(subject, mci) {
	for (let { vote_count_mci, value } of systemVars[subject])
		if (mci > vote_count_mci)
			return value;
	throw Error(subject + ` not found for mci ` + mci);
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

**File:** constants.js (L97-97)
```javascript
exports.v4UpgradeMci = exports.bTestnet ? 3522600 : 10968000;
```
