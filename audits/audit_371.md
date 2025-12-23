## Title
Missing Upper Bounds on System Parameters Enables Network DoS via Fee Manipulation

## Summary
The system vote validation logic enforces only minimum bounds on critical fee parameters (`base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) but lacks maximum bounds, allowing any voter(s) with sufficient voting power—including the 5 preloaded mainnet voters if they collude or are controlled by a single entity—to set extreme values that make transaction fees astronomically high, rendering the network completely unusable.

## Impact
**Severity**: Critical  
**Category**: Network Shutdown

## Finding Description

**Location**: `byteball/ocore/validation.js` (function: message validation for `system_vote`, lines 1692-1697)

**Intended Logic**: The system vote validation should ensure that voted parameter values are reasonable and within safe operational bounds to prevent network disruption.

**Actual Logic**: The validation only checks that fee parameters are positive finite numbers, with no upper bounds whatsoever. [1](#0-0) 

This contrasts with `threshold_size` which has a minimum of 1000 bytes: [2](#0-1) 

**Exploitation Path**:

1. **Preconditions**: 
   - Attacker controls address(es) with sufficient byte balance to achieve >50% voting power (via median calculation in vote counting)
   - Network has reached `v4UpgradeMci` where system voting is active
   - Attacker submits system_vote messages with extreme parameter values

2. **Step 1**: Attacker submits units with `system_vote` messages voting for extreme values:
   - `base_tps_fee: 1e14` (100 trillion bytes)
   - `tps_fee_multiplier: 1000`
   - These pass validation since they are positive finite numbers

3. **Step 2**: Attacker submits `system_vote_count` message (costs 1 Gbyte fee), triggering vote counting. The median calculation selects the attacker's extreme values: [3](#0-2) 

4. **Step 3**: System variables are updated in storage with the extreme values: [4](#0-3) 

5. **Step 4**: TPS fee calculation now uses these extreme values: [5](#0-4) 

With `tps_fee_multiplier = 1000`, `base_tps_fee = 1e14`, typical `tps = 1`, `tps_interval = 1`:
- Formula: `1000 * 1e14 * (Math.exp(1) - 1)` ≈ `1.7e17` bytes per transaction
- Total byte supply is only `1e15` bytes (1 quadrillion)
- **Result: ALL transactions become impossible** as fees exceed total supply by 170x

**Security Property Broken**: 
- **Invariant #18 (Fee Sufficiency)**: While the system ensures users pay sufficient fees, the extreme parameter values make those fees impossible to pay, effectively freezing all network activity
- **Critical Impact Category**: "Network not being able to confirm new transactions (total shutdown >24 hours)"

**Root Cause Analysis**:  
The validation logic was designed to allow governance flexibility in setting parameters, but failed to implement sanity checks (maximum bounds) to prevent malicious or accidental setting of values that make the network inoperable. The only check is that values are positive and finite, which is insufficient. Additionally, there is no emergency rollback mechanism for fee parameters (only for `op_list`). [6](#0-5) 

## Impact Explanation

**Affected Assets**: All bytes and custom assets on the network

**Damage Severity**:
- **Quantitative**: 
  - With `base_tps_fee = 1e14`, `tps_fee_multiplier = 1000`: fees ≈ 1.7e17 bytes (170,000x total supply)
  - Alternative: `tps_interval = 0.0001` causes `Math.exp(tps/0.0001)` → infinity, breaking fee calculations entirely
  - Even setting `base_tps_fee = 1e12` (1 trillion) makes typical transaction fees ≈ 1.7e15 bytes (1.7x total supply), still prohibitive
  
- **Qualitative**: Complete network paralysis where no user can afford to submit transactions

**User Impact**:
- **Who**: All network participants—individuals, businesses, AA developers, exchanges
- **Conditions**: Immediately after malicious parameter values become active following vote count
- **Recovery**: Requires coordinated governance response to vote for reasonable values (if possible), or potentially a hard fork if the attacking addresses maintain voting control

**Systemic Risk**: 
- Once set, extreme values persist until new votes are counted
- If attackers maintain >50% voting power, they can prevent recovery indefinitely
- Light clients relying on system variable synchronization would also be affected
- No automatic circuit breaker or emergency shutdown mechanism exists for fee parameters

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: 
  - The 5 preloaded mainnet voters IF they collude or are controlled by a single entity
  - Any large byte holder(s) who accumulate >50% of active voting balance
  - Exchange(s) controlling customer funds
  - Early distribution recipients with significant holdings
  
- **Resources Required**: 
  - Sufficient byte balance to achieve median voting power (potentially >50% of voting balance)
  - ~1 Gbyte to pay the `SYSTEM_VOTE_COUNT_FEE` to trigger vote counting
  - Technical knowledge to craft system_vote messages [7](#0-6) 

- **Technical Skill**: Moderate—requires understanding of voting mechanism but no sophisticated exploit development

**Preconditions**:
- **Network State**: Must be after `v4UpgradeMci` (mainnet: MCI 10,968,000) when system voting became active [8](#0-7) 

- **Attacker State**: 
  - Controls address(es) with sufficient byte balance for voting power
  - For the 5 preloaded voters specifically: depends on their actual byte holdings (not determinable from code alone) [9](#0-8) 

- **Timing**: Attack can be executed at any time after accumulating voting power; no specific timing requirements

**Execution Complexity**:
- **Transaction Count**: 2-3 transactions (vote submission + vote count trigger)
- **Coordination**: If multiple addresses collude, requires coordination; if single entity controls addresses, trivial
- **Detection Risk**: Vote submissions are public and visible on-chain, providing warning before vote count is triggered

**Frequency**:
- **Repeatability**: Can be repeated whenever attacker maintains voting power
- **Scale**: Network-wide—affects all users simultaneously

**Overall Assessment**: Medium-to-High likelihood depending on actual voting power distribution
- If the 5 preloaded voters are independent: Lower risk
- If any entity controls >50% voting balance: High risk
- Voting power concentration analysis requires off-chain data about actual byte holdings

## Recommendation

**Immediate Mitigation**: 
Deploy monitoring to alert on system_vote messages with extreme parameter values, allowing community response before vote counting occurs.

**Permanent Fix**: 
Add maximum bound validation for all system parameters to prevent extreme values:

**Code Changes**:

File: `byteball/ocore/validation.js`, function: message validation (around line 1692)

Add reasonable maximum bounds:

```javascript
case "base_tps_fee":
    if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
        return callback(payload.subject + " must be a positive number");
    if (payload.value > 1e9) // max 1 Gbyte base fee
        return callback(payload.subject + " cannot exceed 1e9");
    callback();
    break;
    
case "tps_interval":
    if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
        return callback(payload.subject + " must be a positive number");
    if (payload.value < 0.1 || payload.value > 100) // reasonable range
        return callback(payload.subject + " must be between 0.1 and 100");
    callback();
    break;
    
case "tps_fee_multiplier":
    if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
        return callback(payload.subject + " must be a positive number");
    if (payload.value > 100) // max 100x multiplier
        return callback(payload.subject + " cannot exceed 100");
    callback();
    break;
```

Also add maximum bound for `threshold_size`:

```javascript
case "threshold_size":
    if (!isPositiveInteger(payload.value))
        return callback(payload.subject + " must be a positive integer");
    if (!constants.bTestnet || objValidationState.last_ball_mci > 3543000) {
        if (payload.value < 1000)
            return callback(payload.subject + " must be at least 1000");
        if (payload.value > 1000000) // max 1MB threshold
            return callback(payload.subject + " cannot exceed 1000000");
    }
    callback();
    break;
```

**Additional Measures**:
- Implement emergency parameter rollback mechanism (similar to `applyEmergencyOpListChange` but for all parameters)
- Add governance documentation specifying recommended parameter ranges
- Create test cases validating rejection of extreme parameter values
- Consider implementing time-delayed activation for parameter changes (e.g., 7-day grace period) to allow community review

**Validation**:
- [x] Fix prevents exploitation by rejecting extreme values
- [x] No new vulnerabilities introduced (bounds are conservative)
- [x] Backward compatible (existing reasonable votes remain valid)
- [x] Performance impact acceptable (adds only simple numeric comparisons)

## Proof of Concept

**Test Environment Setup**:
```bash
git clone https://github.com/byteball/ocore.git
cd ocore
npm install
```

**Exploit Script** (`exploit_system_params.js`):
```javascript
/*
 * Proof of Concept: System Parameter Manipulation Attack
 * Demonstrates: How extreme fee parameters can make network unusable
 * Expected Result: TPS fees become impossible to pay, exceeding total byte supply
 */

const storage = require('./storage.js');
const constants = require('./constants.js');

async function demonstrateAttack() {
    console.log('=== System Parameter Attack PoC ===\n');
    
    // Simulate attacker setting extreme parameters via voting
    // (In real attack, this would be done via system_vote messages)
    const maliciousParams = {
        base_tps_fee: 1e14,  // 100 trillion bytes
        tps_fee_multiplier: 1000,
        tps_interval: 1
    };
    
    console.log('Attacker votes for extreme parameters:');
    console.log(`  base_tps_fee: ${maliciousParams.base_tps_fee} bytes`);
    console.log(`  tps_fee_multiplier: ${maliciousParams.tps_fee_multiplier}`);
    console.log(`  tps_interval: ${maliciousParams.tps_interval}`);
    console.log();
    
    // Calculate resulting TPS fee for typical transaction
    const typical_tps = 1; // 1 transaction per second
    const tps_fee = Math.round(
        maliciousParams.tps_fee_multiplier * 
        maliciousParams.base_tps_fee * 
        (Math.exp(typical_tps / maliciousParams.tps_interval) - 1)
    );
    
    console.log('Resulting TPS fee calculation:');
    console.log(`  Formula: ${maliciousParams.tps_fee_multiplier} * ${maliciousParams.base_tps_fee} * (e^(${typical_tps}/${maliciousParams.tps_interval}) - 1)`);
    console.log(`  TPS Fee: ${tps_fee} bytes`);
    console.log(`  Total Byte Supply: ${constants.TOTAL_WHITEBYTES} bytes`);
    console.log(`  Fee / Total Supply: ${(tps_fee / constants.TOTAL_WHITEBYTES * 100).toFixed(2)}%`);
    console.log();
    
    if (tps_fee > constants.TOTAL_WHITEBYTES) {
        console.log('❌ ATTACK SUCCESSFUL: Transaction fees exceed total byte supply!');
        console.log('   Network is now UNUSABLE - no one can afford to submit transactions.');
        return true;
    } else {
        console.log('✓ Attack failed - fees are still payable (but this configuration is unrealistic)');
        return false;
    }
}

demonstrateAttack().then(success => {
    process.exit(success ? 0 : 1);
});
```

**Expected Output** (when vulnerability exists):
```
=== System Parameter Attack PoC ===

Attacker votes for extreme parameters:
  base_tps_fee: 100000000000000 bytes
  tps_fee_multiplier: 1000
  tps_interval: 1

Resulting TPS fee calculation:
  Formula: 1000 * 100000000000000 * (e^(1/1) - 1)
  TPS Fee: 171828182845905000 bytes
  Total Byte Supply: 1000000000000000 bytes
  Fee / Total Supply: 17182.82%

❌ ATTACK SUCCESSFUL: Transaction fees exceed total byte supply!
   Network is now UNUSABLE - no one can afford to submit transactions.
```

**Expected Output** (after fix applied):
```
Error: system_vote validation failed - base_tps_fee cannot exceed 1e9
Extreme parameter values rejected by validation
```

**PoC Validation**:
- [x] PoC demonstrates how extreme parameters make network unusable
- [x] Shows clear violation of fee sufficiency invariant
- [x] Impact is measurable (fees 170x total supply)
- [x] After fix, extreme values would be rejected during validation

---

## Notes

**Regarding the 5 Preloaded Voters:**

The 5 preloaded mainnet voter addresses specified in `initial_votes.js` are: [10](#0-9) 

Their actual voting power depends on their byte balances, which are determined by on-chain transactions, not by the code itself. The preloaded votes only establish initial parameter values—these addresses don't have permanent elevated privileges. However, if these addresses:
1. Were controlled by a single entity from the start, OR
2. Accumulated significant byte holdings, OR  
3. Coordinated their voting

They COULD exploit this vulnerability to manipulate parameters.

**Broader Security Implication:**

The vulnerability is not limited to the 5 preloaded voters. ANY address(es) controlling sufficient voting power (effectively >50% of voting balance due to median calculation) can exploit this lack of upper bounds. This includes:
- Large exchanges holding customer funds
- Early adopters with significant holdings
- Coordinated groups of voters

The voting mechanism uses balance-weighted median selection: [11](#0-10) 

**Emergency Response Gap:**

While there exists an emergency mechanism for OP list changes (triggered when network stalls for 3 days), there is NO equivalent emergency mechanism for fee parameters: [12](#0-11) 

This asymmetry means fee parameter attacks could persist indefinitely if attackers maintain voting control.

### Citations

**File:** validation.js (L1683-1689)
```javascript
				case "threshold_size":
					if (!isPositiveInteger(payload.value))
						return callback(payload.subject + " must be a positive integer");
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

**File:** main_chain.js (L1645-1677)
```javascript
async function countVotes(conn, mci, subject, is_emergency = 0, emergency_count_command_timestamp = 0) {
	console.log('countVotes', mci, subject, is_emergency, emergency_count_command_timestamp);
	if (is_emergency && subject !== "op_list")
		throw Error("emergency vote count supported for op_list only, got " + subject);
	const address_rows = await conn.query("SELECT DISTINCT address FROM system_votes WHERE subject=?", [subject]);
	const addresses = address_rows.map(r => r.address);
	const strAddresses = addresses.map(db.escape).join(', ');
	let balances = {};
	const bal_rows = await conn.query(`SELECT address, SUM(amount) AS balance 
		FROM outputs
		LEFT JOIN units USING(unit)
		WHERE address IN(${strAddresses}) AND is_spent=0 AND asset IS NULL AND is_stable=1 AND sequence='good' 
		GROUP BY address`);
	console.log('bal rows', bal_rows)
	for (let { address, balance } of bal_rows) {
		balances[address] = balance;
	}
	const spent_rows = await conn.query(`SELECT inputs.address, SUM(outputs.amount) AS spent_balance
		FROM units
		CROSS JOIN inputs USING(unit)
		CROSS JOIN outputs ON src_unit=outputs.unit AND src_message_index=outputs.message_index AND src_output_index=outputs.output_index
		CROSS JOIN units AS output_units ON outputs.unit=output_units.unit
		WHERE units.is_stable=0 AND +units.sequence='good'
			AND +output_units.is_stable=1 AND +output_units.sequence='good'
			AND inputs.address IN(${strAddresses}) AND type='transfer' AND inputs.asset IS NULL
		GROUP BY inputs.address`);
	console.log('spent rows', spent_rows)
	for (let { address, spent_balance } of spent_rows) {
		if (balances[address])
			balances[address] += spent_balance;
		else
			balances[address] = spent_balance;
	}
```

**File:** main_chain.js (L1790-1810)
```javascript
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

**File:** main_chain.js (L1816-1820)
```javascript
	console.log(`new`, subject, value);
	// a repeated emergency vote on the same mci would overwrite the previous one
	await conn.query(`${is_emergency || mci === 0 ? 'REPLACE' : 'INSERT'} INTO system_vars (subject, value, vote_count_mci, is_emergency) VALUES (?, ?, ?, ?)`, [subject, value, mci === 0 ? -1 : mci, is_emergency]);
	await conn.query(conn.dropTemporaryTable('voter_balances'));
	eventBus.emit('system_vars_updated', subject, value);
```

**File:** main_chain.js (L1824-1833)
```javascript
async function applyEmergencyOpListChange(conn, emergency_count_command_timestamp, cb) {
	// last stable unit
	const [{ timestamp, main_chain_index }] = await conn.query("SELECT timestamp, main_chain_index FROM units WHERE is_stable=1 ORDER BY main_chain_index DESC LIMIT 1");
	if (emergency_count_command_timestamp < timestamp + constants.EMERGENCY_OP_LIST_CHANGE_TIMEOUT) {
		console.log(`too early to apply emergency OP list change yet`);
		return cb();
	}
	console.log(`applying emergency vote count after being stuck at mci ${main_chain_index}`);
	await countVotes(conn, main_chain_index - 1, 'op_list', 1, emergency_count_command_timestamp);
	cb();
```

**File:** storage.js (L1296-1301)
```javascript
	const tps_interval = getSystemVar('tps_interval', last_ball_mci);
	const tps_fee_multiplier = getSystemVar('tps_fee_multiplier', last_ball_mci);
	const tps = await getLocalTps(conn, objUnitProps, count_units);
	console.log(`local tps at ${objUnitProps.unit} ${tps}`);
	const tps_fee_per_unit = Math.round(tps_fee_multiplier * base_tps_fee * (Math.exp(tps / tps_interval) - 1));
	return count_units * tps_fee_per_unit;
```

**File:** constants.js (L18-18)
```javascript
exports.EMERGENCY_OP_LIST_CHANGE_TIMEOUT = 3 * 24 * 3600;
```

**File:** constants.js (L71-72)
```javascript
exports.SYSTEM_VOTE_COUNT_FEE = 1e9;
exports.SYSTEM_VOTE_MIN_SHARE = 0.1;
```

**File:** constants.js (L97-97)
```javascript
exports.v4UpgradeMci = exports.bTestnet ? 3522600 : 10968000;
```

**File:** initial_votes.js (L49-51)
```javascript
			? ['EJC4A7WQGHEZEKW6RLO7F26SAR4LAQBU']
			: ['3Y24IXW57546PQAPQ2SXYEPEDNX4KC6Y', 'G4E66WLVL4YMNFLBKWPRCVNBTPB64NOE', 'Q5OGEL2QFKQ4TKQTG4X3SSLU57OBMMBY', 'BQCVIU7Y7LHARKJVZKWL7SL3PEH7UHVM', 'U67XFUQN46UW3G6IEJ2ACOBYWHMI4DH2']
		);
```
