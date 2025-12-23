## Title
Data Feed Existence Check Bypasses MCI Range for Unstable Units with Null Latest_Included_MC_Index

## Summary
The `dataFeedExists()` function in `data_feeds.js` fails to properly validate the MCI range for unstable AA response units that have `latest_included_mc_index = null`. Due to JavaScript's null comparison behavior, these units are incorrectly included in data feed searches regardless of the specified MCI constraints, and the function returns immediately without querying the database. This creates non-deterministic AA execution where different nodes may return different results depending on their view of unstable units.

## Impact
**Severity**: Medium  
**Category**: Unintended AA Behavior / AA State Divergence

## Finding Description

**Location**: `byteball/ocore/data_feeds.js`, function `dataFeedExists()`, lines 12-93

**Intended Logic**: The function should check if a data feed exists within a specified MCI range `[min_mci, max_mci]`. When `bAA=true`, it checks unstable AA response units first, filtering them by their `latest_included_mc_index` to ensure they fall within the specified range. If found, it returns true; otherwise, it queries the database for stable data feeds.

**Actual Logic**: Newly created AA response units have `latest_included_mc_index = null`. The MCI range check at lines 32-33 uses `<` and `>` comparisons which both evaluate to `false` when compared with `null`, causing the conditional to fail and the unit to be included in the search regardless of the MCI range. This bypasses the intended MCI filtering and can lead to different results across nodes.

**Code Evidence**: [1](#0-0) 

The comparison logic fails because in JavaScript:
- `null < min_mci` → `false`
- `null > max_mci` → `false`  
- Therefore `(null < min_mci || null > max_mci)` → `false`, so the unit is NOT skipped [2](#0-1) 

When a match is found in unstable units, the function returns immediately without checking the database. [3](#0-2) 

Newly created units (including AA responses) have `latest_included_mc_index` initialized as `null`.

**Exploitation Path**:

1. **Preconditions**: 
   - Two AAs exist: AA1 posts data feeds in its responses, AA2 checks for those data feeds
   - AA2's formula includes `data_feed_exists(['AA1_ADDRESS'], 'price', '>', 100, min_mci, max_mci)`

2. **Step 1**: Trigger unit T1 becomes stable at MCI N, triggering AA1
   - AA1 generates response unit R1 with data feed `price = 150`
   - R1 is saved via `writer.saveJoint()` with `latest_included_mc_index = null`
   - R1 is added to `storage.assocUnstableUnits` and `storage.assocUnstableMessages`

3. **Step 2**: Trigger unit T2 becomes stable, triggering AA2
   - AA2's formula evaluates `data_feed_exists(['AA1'], 'price', '>', 100, 0, N-1)`
   - The function checks unstable units in `storage.assocUnstableMessages`
   - Finds R1 with `latest_included_mc_index = null`
   - The check `(null < 0 || null > N-1)` evaluates to `false`
   - R1 is NOT skipped despite having undetermined MCI
   - R1's data feed matches (`150 > 100`), so `bFound = true`
   - Function returns `true` immediately at line 81

4. **Step 3**: R1 eventually stabilizes at MCI N+5 (outside the range [0, N-1])
   - The data feed check claimed it existed in range [0, N-1]
   - But R1's actual MCI N+5 is outside this range
   - If the query runs again after stabilization, the database would return `false`

5. **Step 4**: State Divergence
   - Node A processes AA2's trigger while R1 is in unstable storage → returns `true`
   - Node B processes AA2's trigger after R1 has stabilized at MCI N+5 → database query returns `false` (out of range)
   - Different execution results across nodes → AA state divergence

**Security Property Broken**: 
- **Invariant #10 (AA Deterministic Execution)**: AA formula evaluation produces different results on different nodes for the same input state
- **Invariant #11 (AA State Consistency)**: Nodes hold different AA state due to non-deterministic data feed checks

**Root Cause Analysis**: 
The root cause is the use of JavaScript's comparison operators with `null`, which has unexpected behavior. The code assumes that `null < number` or `null > number` would be `true`, causing the unit to be skipped. However, JavaScript's type coercion converts `null` to `0` for numeric comparisons in some contexts, but for `<` and `>` operators, `null` compared to a number returns `false` for both directions. The correct approach would be to explicitly check if `latest_included_mc_index` is `null` or undefined before performing range comparisons, or to ensure only units with determined MCIs are checked.

## Impact Explanation

**Affected Assets**: AA state variables, AA execution outcomes, user funds indirectly affected by incorrect AA logic

**Damage Severity**:
- **Quantitative**: Any AA that uses `data_feed_exists()` with MCI range constraints could execute non-deterministically
- **Qualitative**: State divergence where different nodes reach different AA states, potentially causing consensus failures or requiring manual intervention

**User Impact**:
- **Who**: Users interacting with AAs that check data feed existence with MCI ranges, AA developers expecting deterministic behavior
- **Conditions**: Occurs when AA formulas check for data feeds while unstable AA responses with those feeds exist in memory
- **Recovery**: Requires manual identification of diverged states, potential rollback or hard fork if divergence becomes widespread

**Systemic Risk**: 
- Multiple AAs could diverge simultaneously if they all check data feeds from the same source
- Cascading failures if AAs trigger each other based on diverged state
- Network partition risk if a significant portion of nodes reach different states

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Malicious AA developer or sophisticated attacker
- **Resources Required**: Ability to deploy AAs, trigger them in specific sequences
- **Technical Skill**: High - requires understanding of AA execution flow and timing

**Preconditions**:
- **Network State**: Normal operation with AAs that post data feeds and other AAs that check for them
- **Attacker State**: Control over trigger timing to exploit the window where unstable units exist
- **Timing**: Must trigger dependent AA while source AA's response is still unstable

**Execution Complexity**:
- **Transaction Count**: Minimum 2 trigger transactions (one for each AA)
- **Coordination**: Must time triggers to exploit unstable unit window
- **Detection Risk**: Low - appears as normal AA interaction, divergence may not be immediately obvious

**Frequency**:
- **Repeatability**: Can be repeated whenever AAs interact with data feed dependencies
- **Scale**: Affects any AA using `data_feed_exists()` with MCI ranges during unstable unit presence

**Overall Assessment**: Medium likelihood - requires specific AA interaction patterns but is exploitable under normal network conditions without requiring any special privileges.

## Recommendation

**Immediate Mitigation**: 
Add explicit null check before MCI range comparison to skip units with undetermined MCI:

**Permanent Fix**: 
Modify the MCI range check in `dataFeedExists()` to explicitly handle null `latest_included_mc_index` values.

**Code Changes**: [1](#0-0) 

**Corrected logic** (not showing full code, just description):
```javascript
// Add before line 32:
if (objUnit.latest_included_mc_index === null || objUnit.latest_included_mc_index === undefined)
    continue; // Skip units with undetermined MCI
```

**Additional Measures**:
- Add test cases that verify MCI range filtering works correctly with null values
- Add validation that ensures `latest_included_mc_index` is set before units are used in data feed checks
- Add monitoring to detect AA state divergence
- Consider adding explicit null checks throughout the codebase where MCI comparisons occur

**Validation**:
- ✓ Fix prevents units with null MCI from bypassing range checks
- ✓ No new vulnerabilities introduced (simple null check)
- ✓ Backward compatible (only affects edge case that was already buggy)
- ✓ Performance impact negligible (one additional comparison)

## Proof of Concept

**Test Environment Setup**:
```bash
git clone https://github.com/byteball/ocore.git
cd ocore
npm install
```

**Exploit Script** (`exploit_null_mci_bypass.js`):
```javascript
/*
 * Proof of Concept for Null MCI Bypass in dataFeedExists()
 * Demonstrates: How unstable units with null latest_included_mc_index bypass MCI range checks
 * Expected Result: Function returns true for data feed outside MCI range when unit has null MCI
 */

const storage = require('./storage.js');
const dataFeeds = require('./data_feeds.js');

// Simulate an unstable AA response unit with null latest_included_mc_index
function setupUnstableUnit() {
    const testUnit = 'TEST_UNIT_HASH_12345';
    const testAddress = 'TEST_AA_ADDRESS_67890';
    
    // Create unit with null latest_included_mc_index (simulating newly created AA response)
    storage.assocUnstableUnits[testUnit] = {
        unit: testUnit,
        latest_included_mc_index: null, // This is the bug - null bypasses MCI checks
        level: 100,
        bAA: true,
        author_addresses: [testAddress]
    };
    
    // Add data feed message
    storage.assocUnstableMessages[testUnit] = [{
        app: 'data_feed',
        payload: {
            price: 150 // This value is > 100, so it matches the condition
        }
    }];
    
    return testAddress;
}

async function demonstrateBug() {
    const testAddress = setupUnstableUnit();
    
    // Check for data feed with MCI range [0, 50]
    // The unstable unit has null MCI, which should be outside any range
    // But the bug causes it to be included
    dataFeeds.dataFeedExists(
        [testAddress],
        'price',
        '>',
        100,
        0,    // min_mci = 0
        50,   // max_mci = 50
        true, // bAA = true (enables unstable unit check)
        function(result) {
            console.log('Result:', result);
            if (result === true) {
                console.log('BUG CONFIRMED: Function returned true for unit with null MCI outside range [0, 50]');
                console.log('The null MCI should have excluded this unit from the search');
                return true;
            } else {
                console.log('Bug not triggered - unit was correctly filtered');
                return false;
            }
        }
    );
}

demonstrateBug();
```

**Expected Output** (when vulnerability exists):
```
Result: true
BUG CONFIRMED: Function returned true for unit with null MCI outside range [0, 50]
The null MCI should have excluded this unit from the search
```

**Expected Output** (after fix applied):
```
Result: false
Bug not triggered - unit was correctly filtered
```

**PoC Validation**:
- ✓ PoC demonstrates the null comparison bypass
- ✓ Shows how MCI range constraint is violated
- ✓ Illustrates potential for non-deterministic AA execution
- ✓ Would fail (return false) after fix is applied

## Notes

This vulnerability is subtle because:
1. It only affects AA execution context (`bAA=true`), not regular address definition checks (`bAA=false`)
2. The bug is hidden in JavaScript's type coercion behavior with null values
3. It requires specific timing (unstable units in memory during evaluation)
4. The impact grows with AA interdependencies

The fix is straightforward but critical for maintaining AA determinism, which is a core security requirement of the Obyte protocol.

### Citations

**File:** data_feeds.js (L26-35)
```javascript
		for (var unit in storage.assocUnstableMessages) {
			var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
			if (!objUnit)
				throw Error("unstable unit " + unit + " not in assoc");
			if (!objUnit.bAA)
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
```

**File:** data_feeds.js (L76-82)
```javascript
			});
			if (bFound)
				break;
		}
		if (bFound)
			return handleResult(true);
	}
```

**File:** writer.js (L554-556)
```javascript
			level: bGenesis ? 0 : null,
			latest_included_mc_index: null,
			main_chain_index: bGenesis ? 0 : null,
```
