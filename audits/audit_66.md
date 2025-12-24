# NoVulnerability found for this question.

## Analysis

After thorough code examination, this claim fundamentally misunderstands how the `first_unstable_mc_index` parameter works in the algorithm selection mechanism.

### Critical Misunderstanding

The claim assumes `first_unstable_mc_index` is a "node state variable" that differs across nodes, causing them to use different algorithms for the same stability decision. This is incorrect. [1](#0-0) 

The `first_unstable_mc_index` is **directly extracted from the unit being evaluated** - it IS the main_chain_index of the specific unit under consideration for stability, not a variable node state.

### Algorithm Selection is Deterministic [2](#0-1) 

The algorithm choice depends on whether `first_unstable_mc_index >= 3009824`. Since `first_unstable_mc_index` equals the MCI being evaluated:

- **Evaluating MCI 3009823**: `3009823 >= 3009824` = FALSE → OLD algorithm (all nodes)
- **Evaluating MCI 3009824**: `3009824 >= 3009824` = TRUE → NEW algorithm (all nodes)

All nodes evaluating the **same MCI** will have the **same** `first_unstable_mc_index` value and use the **same** algorithm.

### The Exploitation Scenario is Impossible

The claim states:
- Node A: `first_unstable_mc_index = 3009823` evaluating MCI 3009823
- Node B: `first_unstable_mc_index = 3009824` evaluating MCI 3009823

This is self-contradictory. If Node B is evaluating MCI 3009823, its `first_unstable_mc_index` MUST be 3009823 (the MCI being evaluated). Having `first_unstable_mc_index = 3009824` means Node B has already stabilized 3009823 and moved to evaluating 3009824. [3](#0-2) 

### This is Standard Upgrade Design [4](#0-3) 

The comment acknowledging the old SQL is "totally wrong" refers to a **backward-compatible protocol upgrade**:
- Historical units (MCI < 3009824): Use old algorithm to maintain consistency with past consensus
- New units (MCI ≥ 3009824): Use corrected algorithm

This is intentional design, not a vulnerability. The transition is deterministic and consensus-preserving.

### Validation Failures

- ❌ Misinterprets `first_unstable_mc_index` as variable node state rather than the MCI being evaluated
- ❌ Exploitation scenario is logically impossible
- ❌ Confuses backward-compatible upgrade pattern with consensus failure
- ❌ No demonstration of actual divergent behavior
- ❌ Ignores that algorithm selection is deterministic per MCI

### Citations

**File:** main_chain.js (L495-496)
```javascript
					var first_unstable_mc_unit = arrMcRows[0].unit;
					var first_unstable_mc_index = arrMcRows[0].main_chain_index;
```

**File:** main_chain.js (L556-560)
```javascript
									determineMaxAltLevel(
										conn, first_unstable_mc_index, first_unstable_mc_level, arrAltBestChildren, arrWitnesses,
										function(max_alt_level){
											if (min_mc_wl > max_alt_level)
												return advanceLastStableMcUnitAndTryNext();
```

**File:** main_chain.js (L703-716)
```javascript
	if (first_unstable_mc_index >= constants.altBranchByBestParentUpgradeMci){
		conn.query(
			"SELECT MAX(bpunits.level) AS max_alt_level \n\
			FROM units \n\
			CROSS JOIN units AS bpunits \n\
				ON units.best_parent_unit=bpunits.unit AND bpunits.witnessed_level < units.witnessed_level \n\
			WHERE units.unit IN("+arrAltBestChildren.map(db.escape).join(', ')+")",
			function(max_alt_rows){
				var max_alt_level = max_alt_rows[0].max_alt_level; // can be null
			//	console.log('===== min_mc_wl='+min_mc_wl+', max_alt_level='+max_alt_level+", first_unstable_mc_level="+first_unstable_mc_level);
				handleResult(max_alt_level || first_unstable_mc_level);
			}
		);
	}
```

**File:** main_chain.js (L718-718)
```javascript
		// this sql query is totally wrong but we still leave it for compatibility
```
