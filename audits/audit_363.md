## Title
Testnet OP List Initialization Mismatch Causes Potential Consensus Divergence

## Summary
The testnet operator (OP) list initialization in `initial_votes.js` contains a critical inconsistency where line 42 uses a different 12-address list than the standardized list used in the bug fix (line 27) and hardcoded workaround (main_chain.js line 1773). Specifically, line 42 includes `WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR` but excludes `WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N`, while the standardized list has the opposite. This causes new testnet nodes to initialize with incorrect preloaded votes that can produce different OP list results during vote counting at MCIs outside the hardcoded workarounds, leading to consensus divergence.

## Impact
**Severity**: Critical  
**Category**: Unintended permanent chain split requiring hard fork

## Finding Description

**Location**: `byteball/ocore/initial_votes.js` (function `initSystemVarVotes()`, line 42 vs line 27) and `byteball/ocore/main_chain.js` (function `countVotes()`, line 1773)

**Intended Logic**: After a historical bug where some nodes had 13 OPs instead of 12, the codebase was fixed to standardize all nodes on a specific 12-OP list. The bug fix code updates existing nodes to this standardized list, and a hardcode workaround ensures consistency at specific problematic MCIs. All nodes should converge to the same OP list containing `WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N` as the 12th operator.

**Actual Logic**: New testnet nodes initializing with empty databases use line 42's array which contains `WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR` as the 12th OP instead of `WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N`. This creates a third variant that differs from both the original "correct" list and the standardized "buggy" list. When vote counting occurs at any MCI outside the three hardcoded exceptions (3547796, 3548896, 3548898), new nodes will produce different OP lists than existing nodes.

**Code Evidence**: [1](#0-0) [2](#0-1) [3](#0-2) 

**Exploitation Path**:

1. **Preconditions**: 
   - Testnet environment (`constants.bTestnet = true`)
   - New node starting with empty database (no existing `system_vars` rows)
   - Network MCI has progressed beyond 3548898

2. **Step 1 - Wrong Initialization**: New node calls `initSystemVarVotes()`. Since database is empty, rows.length === 0, so the bug fix code (lines 9-29) does NOT execute. Instead, lines 33-81 run, using line 42's `arrOPs` array containing `WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR`. Preloaded votes for address `'EJC4A7WQGHEZEKW6RLO7F26SAR4LAQBU'` are inserted into `op_votes` table with this incorrect list.

3. **Step 2 - Initial Sync**: Node syncs the DAG. At MCIs 3547796, 3548896, and 3548898, when `countVotes()` runs, the hardcode check on line 1772 triggers and forces `ops` to the correct list with `WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N`, so these specific MCIs match other nodes.

4. **Step 3 - Divergence Trigger**: At a different MCI X (where X ∉ {3547796, 3548896, 3548898}), any user submits a unit containing a `system_vote_count` message with payload `'op_list'`. This is validated and accepted per validation.js lines 1704-1714. [4](#0-3) 

5. **Step 4 - Consensus Divergence**: When MCI X becomes stable, `countVotes(conn, mci, 'op_list')` is called. It queries the `op_votes` table, which contains the wrong preloaded votes (with `WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR`). If the preloaded voter has sufficient balance and other votes are limited, the top 12 OPs selected include `WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR`. The hardcode check fails (MCI ≠ hardcoded values), so the wrong list is stored in `system_vars`. [5](#0-4) 

Meanwhile, old nodes with correct preloaded votes produce the list with `WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N`. Different nodes now have different `system_vars` entries for `op_list` at the same MCI → **consensus divergence**.

**Security Property Broken**: 
- Violates the fundamental requirement that all nodes must deterministically reach consensus on system state, including system parameters
- Breaks **Invariant #10 (AA Deterministic Execution)** if any AA queries system variables
- Creates non-deterministic governance outcomes where different nodes recognize different operators

**Root Cause Analysis**: The historical bug fix addressed nodes that were already running during the bug, but failed to update the initialization code for fresh nodes. Line 42 should have been updated to match line 27's standardized list, but instead retained a hybrid list that combines elements from both the "correct" and "buggy" variants.

## Impact Explanation

**Affected Assets**: System governance integrity, operator list consensus, system parameter determination

**Damage Severity**:
- **Quantitative**: All new testnet nodes initializing after the bug fix was deployed are affected
- **Qualitative**: Permanent consensus divergence on which 12 addresses are authorized operators

**User Impact**:
- **Who**: All testnet participants, developers testing against testnet
- **Conditions**: Automatically occurs when new nodes join and any vote count happens at non-hardcoded MCIs
- **Recovery**: Requires coordinated database reset or hard fork to restore consensus

**Systemic Risk**: 
- Different nodes will enforce different system parameters (fees, thresholds, TPS limits) based on different operator votes
- Testnet becomes unreliable for mainnet preparation
- If similar pattern exists in mainnet code, could cause catastrophic production failure
- Historical inconsistency suggests potential for future similar errors

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any testnet user (no privileges required)
- **Resources Required**: Ability to submit one testnet transaction
- **Technical Skill**: Minimal - just format a `system_vote_count` message

**Preconditions**:
- **Network State**: Testnet with MCI > 3548898 (already true)
- **Attacker State**: No special state required
- **Timing**: Anytime a new node joins testnet

**Execution Complexity**:
- **Transaction Count**: Single unit with `system_vote_count` message
- **Coordination**: None
- **Detection Risk**: Appears as legitimate governance activity

**Frequency**:
- **Repeatability**: Automatic for every new node that initializes
- **Scale**: Network-wide impact

**Overall Assessment**: **High likelihood** - This is not a deliberate exploit but an automatic failure that occurs whenever new nodes join testnet and vote counting happens, which is a normal governance process.

## Recommendation

**Immediate Mitigation**: 
1. Correct line 42 in `initial_votes.js` to use `WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N` instead of `WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR`
2. Add migration script to identify and fix any existing testnet nodes with incorrect preloaded votes
3. Extend hardcode workaround to cover any MCIs where vote counts may have already occurred with incorrect data

**Permanent Fix**: Update the testnet initialization array to match the standardized list

**Code Changes**:
The 12th address in line 42's array should be changed from `"WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR"` to `"WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"` to match lines 27 and main_chain.js line 1773.

**Additional Measures**:
- Add unit test asserting line 42 === line 27 === main_chain.js line 1773 for testnet
- Add startup validation comparing preloaded OP list against expected standardized list
- Audit mainnet initialization for similar inconsistencies
- Consider removing hardcode workaround after sufficient time ensuring all nodes are fixed

**Validation**:
- ✓ Fix prevents new nodes from initializing with wrong OP list
- ✓ No new vulnerabilities introduced (simple array correction)
- ✓ Backward compatible (only affects fresh database initialization)
- ✓ No performance impact

## Proof of Concept

**Test Environment Setup**:
```bash
git clone https://github.com/byteball/ocore.git
cd ocore
# Set testnet=1 in .env
npm install
```

**Exploit Demonstration**:

1. Start two testnet nodes: Node A (old, went through bug fix) and Node B (new, fresh initialization)
2. Node B's `op_votes` table contains votes for list with `WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR`
3. Submit `system_vote_count` message for `'op_list'` at MCI 4000000 (example)
4. When MCI 4000000 stabilizes and `countVotes()` runs:
   - Node A produces OP list: `[..., "WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"]`
   - Node B produces OP list: `[..., "WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR"]`
5. Query `SELECT value FROM system_vars WHERE subject='op_list' AND vote_count_mci=4000000` on both nodes
6. Results differ → consensus divergence confirmed

**Expected Output** (vulnerability present):
```
Node A system_vars.value: [...,"WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"]
Node B system_vars.value: [...,"WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR"]
ERROR: Consensus divergence detected!
```

**Expected Output** (after fix):
```
Node A system_vars.value: [...,"WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"]
Node B system_vars.value: [...,"WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"]
SUCCESS: Consensus maintained
```

## Notes

This vulnerability is particularly concerning because:

1. **Silent Failure**: The divergence only manifests when vote counting occurs at non-hardcoded MCIs, making it non-obvious during initial testing

2. **Historical Context**: The comment on line 26 ("changing the OP list to the buggy one") and the hardcode workaround indicate the developers were aware of the complexity but missed updating the initialization code

3. **Testnet Risk**: While this affects testnet, testnet is critical for mainnet validation, and similar patterns in mainnet code could be catastrophic

4. **Three-Way Inconsistency**: There are actually three different 12-OP lists in play:
   - Line 25: Original "correct" list without `2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX`, with both `WELOXP...` and `WMFLGI...` (13 total referenced)
   - Line 27 & main_chain.js: Standardized "buggy" list with `2FF7PSL7...` and `WMFLGI...`, without `WELOXP...`
   - Line 42: Incorrect variant with `2FF7PSL7...` and `WELOXP...`, without `WMFLGI...`

The security question's observation about the "13 OPs expected" was prescient - the historical bug involved an extra OP being added, and while the bug fix cleaned up most cases, it failed to standardize fresh initialization, creating an ongoing consensus risk.

### Citations

**File:** initial_votes.js (L25-28)
```javascript
			if (vote_count_mci === 3547796 && value === '["2GPBEZTAXKWEXMWCTGZALIZDNWS5B3V7","4H2AMKF6YO2IWJ5MYWJS3N7Y2YU2T4Z5","DFVODTYGTS3ILVOQ5MFKJIERH6LGKELP","ERMF7V2RLCPABMX5AMNGUQBAH4CD5TK4","F4KHJUCLJKY4JV7M5F754LAJX4EB7M4N","IOF6PTBDTLSTBS5NWHUSD7I2NHK3BQ2T","O4K4QILG6VPGTYLRAI2RGYRFJZ7N2Q2O","OPNUXBRSSQQGHKQNEPD2GLWQYEUY5XLD","PA4QK46276MJJD5DBOLIBMYKNNXMUVDP","RJDYXC4YQ4AZKFYTJVCR5GQJF5J6KPRI","WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR","WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"]') {
				console.log("changing the OP list to the buggy one");
				await conn.query(`UPDATE system_vars SET value='["2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX","2GPBEZTAXKWEXMWCTGZALIZDNWS5B3V7","4H2AMKF6YO2IWJ5MYWJS3N7Y2YU2T4Z5","DFVODTYGTS3ILVOQ5MFKJIERH6LGKELP","ERMF7V2RLCPABMX5AMNGUQBAH4CD5TK4","F4KHJUCLJKY4JV7M5F754LAJX4EB7M4N","IOF6PTBDTLSTBS5NWHUSD7I2NHK3BQ2T","O4K4QILG6VPGTYLRAI2RGYRFJZ7N2Q2O","OPNUXBRSSQQGHKQNEPD2GLWQYEUY5XLD","PA4QK46276MJJD5DBOLIBMYKNNXMUVDP","RJDYXC4YQ4AZKFYTJVCR5GQJF5J6KPRI","WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"]' WHERE subject='op_list' AND vote_count_mci=3547796`);
			}
```

**File:** initial_votes.js (L39-44)
```javascript
	const arrOPs = constants.bDevnet
		? ["ZQFHJXFWT2OCEBXF26GFXJU4MPASWPJT"]
		: (constants.bTestnet
			? ["2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX", "2GPBEZTAXKWEXMWCTGZALIZDNWS5B3V7", "4H2AMKF6YO2IWJ5MYWJS3N7Y2YU2T4Z5", "DFVODTYGTS3ILVOQ5MFKJIERH6LGKELP", "ERMF7V2RLCPABMX5AMNGUQBAH4CD5TK4", "F4KHJUCLJKY4JV7M5F754LAJX4EB7M4N", "IOF6PTBDTLSTBS5NWHUSD7I2NHK3BQ2T", "O4K4QILG6VPGTYLRAI2RGYRFJZ7N2Q2O", "OPNUXBRSSQQGHKQNEPD2GLWQYEUY5XLD", "PA4QK46276MJJD5DBOLIBMYKNNXMUVDP", "RJDYXC4YQ4AZKFYTJVCR5GQJF5J6KPRI", "WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR"]
			: ["2TO6NYBGX3NF5QS24MQLFR7KXYAMCIE5", "4GDZSXHEFVFMHCUCSHZVXBVF5T2LJHMU", "APABTE2IBKOIHLS2UNK6SAR4T5WRGH2J", "DXYWHSZ72ZDNDZ7WYZXKWBBH425C6WZN", "FAB6TH7IRAVHDLK2AAWY5YBE6CEBUACF", "FOPUBEUPBC6YLIQDLKL6EW775BMV7YOH", "GFK3RDAPQLLNCMQEVGGD2KCPZTLSG3HN", "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT", "JMFXY26FN76GWJJG7N36UI2LNONOGZJV", "JPQKPRI5FMTQRJF4ZZMYZYDQVRD55OTC", "TKT4UESIKTTRALRRLWS4SENSTJX6ODCW", "UE25S4GRWZOLNXZKY4VWFHNJZWUSYCQC"]
		);
```

**File:** main_chain.js (L1758-1779)
```javascript
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
```

**File:** validation.js (L1704-1714)
```javascript
		case "system_vote_count":
			if (objValidationState.last_ball_mci < constants.v4UpgradeMci && !constants.bDevnet)
				return callback("cannot count votes for system params yet");
			if (objValidationState.bAA)
				return callback("AA cannot trigger system vote count");
			if (objValidationState.bHasSystemVoteCount)
				return callback("can be only one system vote count");
			objValidationState.bHasSystemVoteCount = true;
			if (!["op_list", "threshold_size", "base_tps_fee", "tps_interval", "tps_fee_multiplier"].includes(payload))
				return callback("unknown subject in vote count: " + payload);
			return callback();
```
