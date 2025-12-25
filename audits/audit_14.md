# NoVulnerability found for this question.

## Validation Analysis

I have thoroughly validated the security claim against the Obyte codebase and the Immunefi severity criteria. The analysis provided is **correct** - while there is a legitimate implementation bug, it does **not** meet Critical severity threshold.

### Bug Verification

The bug is **real and confirmed**:

1. **Cache Access Without Fallback**: [1](#0-0) 
   The code unconditionally accesses `storage.assocStableUnits[unit]` and throws if the unit is not in cache, with no fallback to load from database.

2. **Async Error Context**: [2](#0-1) 
   The error occurs inside an async callback, which will result in an unhandled promise rejection and crash the Node.js process.

3. **Cache Eviction Mechanism**: [3](#0-2) 
   The `shrinkCache()` function evicts old stable units from memory cache based on MCI threshold.

4. **Periodic Execution**: [4](#0-3) 
   Cache shrinking runs every 300 seconds (5 minutes), creating the race condition window.

5. **Trigger Processing Entry Points**: [5](#0-4) 
   On relay startup, `handleAATriggers()` processes any leftover triggers from previous runs, where the bug manifests.

### Severity Assessment Per Immunefi Scope

**Critical Criteria (ALL must be met - NONE are met here):**

❌ **Network Shutdown >24h**: Only affects individual nodes experiencing specific operational conditions (downtime + trigger backlog + cache eviction). Other nodes continue processing normally. Users can submit AA triggers to any other node.

❌ **Permanent Chain Split**: No consensus divergence. This is a node crash issue, not a validation disagreement. All nodes agree on the valid DAG state.

❌ **Direct Loss of Funds**: No theft mechanism. Funds remain in their addresses. AA balances are unchanged.

❌ **Permanent Fund Freeze**: AA triggers remain in the `aa_triggers` database table [6](#0-5) . They can be processed by other nodes or after node restart with a code fix. No permanent state corruption.

**Medium Criteria (Met):**

✅ **Temporary Transaction Delay ≥1 Hour**: The affected node crashes and cannot process AA triggers until manual restart and code fix, causing delays for users specifically connecting to that node.

✅ **Unintended AA Behavior Without Direct Fund Risk**: AA trigger processing halts on the affected node, but no funds are at risk and triggers are not lost.

### Conclusion

This is a **node-level operational availability issue**, not a **protocol-level security vulnerability**. The impact is:
- Limited to individual nodes under specific conditions
- Does not affect network consensus
- Causes no fund loss or permanent damage
- Recoverable through operational intervention

The bug qualifies as **Medium severity** per Immunefi criteria, not Critical. The claim's assessment that this "does not meet the Critical severity threshold" is accurate.

### Notes

The proper fix would be to either:
1. Check cache existence and load from database if missing
2. Populate cache before processing old triggers
3. Handle the error gracefully instead of crashing

This is a legitimate bug that should be addressed, but overstating it as "Critical" misrepresents the actual risk profile according to Immunefi's scope definitions.

### Citations

**File:** aa_composer.js (L97-98)
```javascript
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
```

**File:** aa_composer.js (L99-101)
```javascript
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
```

**File:** storage.js (L2146-2189)
```javascript
function shrinkCache(){
	if (Object.keys(assocCachedAssetInfos).length > MAX_ITEMS_IN_CACHE)
		assocCachedAssetInfos = {};
	console.log(Object.keys(assocUnstableUnits).length+" unstable units");
	var arrKnownUnits = Object.keys(assocKnownUnits);
	var arrPropsUnits = Object.keys(assocCachedUnits);
	var arrStableUnits = Object.keys(assocStableUnits);
	var arrAuthorsUnits = Object.keys(assocCachedUnitAuthors);
	var arrWitnessesUnits = Object.keys(assocCachedUnitWitnesses);
	if (arrPropsUnits.length < MAX_ITEMS_IN_CACHE && arrAuthorsUnits.length < MAX_ITEMS_IN_CACHE && arrWitnessesUnits.length < MAX_ITEMS_IN_CACHE && arrKnownUnits.length < MAX_ITEMS_IN_CACHE && arrStableUnits.length < MAX_ITEMS_IN_CACHE)
		return console.log('cache is small, will not shrink');
	var arrUnits = _.union(arrPropsUnits, arrAuthorsUnits, arrWitnessesUnits, arrKnownUnits, arrStableUnits);
	console.log('will shrink cache, total units: '+arrUnits.length);
	if (min_retrievable_mci === null)
		throw Error(`min_retrievable_mci no initialized yet`);
	readLastStableMcIndex(db, function(last_stable_mci){
		const top_mci = Math.min(min_retrievable_mci, last_stable_mci - constants.COUNT_MC_BALLS_FOR_PAID_WITNESSING - 10);
		for (var mci = top_mci-1; true; mci--){
			if (assocStableUnitsByMci[mci])
				delete assocStableUnitsByMci[mci];
			else
				break;
		}
		var CHUNK_SIZE = 500; // there is a limit on the number of query params
		for (var offset=0; offset<arrUnits.length; offset+=CHUNK_SIZE){
			// filter units that became stable more than 100 MC indexes ago
			db.query(
				"SELECT unit FROM units WHERE unit IN(?) AND main_chain_index<? AND main_chain_index!=0", 
				[arrUnits.slice(offset, offset+CHUNK_SIZE), top_mci], 
				function(rows){
					console.log('will remove '+rows.length+' units from cache');
					rows.forEach(function(row){
						delete assocKnownUnits[row.unit];
						delete assocCachedUnits[row.unit];
						delete assocBestChildren[row.unit];
						delete assocStableUnits[row.unit];
						delete assocCachedUnitAuthors[row.unit];
						delete assocCachedUnitWitnesses[row.unit];
					});
				}
			);
		}
	});
}
```

**File:** storage.js (L2190-2190)
```javascript
setInterval(shrinkCache, 300*1000);
```

**File:** network.js (L4075-4075)
```javascript
	await aa_composer.handleAATriggers(); // in case anything's left from the previous run
```

**File:** main_chain.js (L1622-1622)
```javascript
				conn.query("INSERT INTO aa_triggers (mci, unit, address) VALUES " + arrValues.join(', '), function () {
```
