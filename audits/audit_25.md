# NoVulnerability found for this question.

## Analysis Summary

While the reported issue identifies a real bug in the codebase, it **does not meet the Critical severity threshold** claimed in the report. After thorough validation, this issue qualifies as **Medium severity at most**, which significantly undermines the validity of a "Critical" classification.

## Key Findings

**Verified Bug**: The code at [1](#0-0)  does unconditionally access `storage.assocStableUnits[unit]` and throws if undefined, within an async callback that is not properly handled by the database wrapper at [2](#0-1) .

**Cache Eviction Confirmed**: The `shrinkCache()` function at [3](#0-2)  evicts units older than ~110 MCIs from the cache [4](#0-3) , running every 300 seconds [5](#0-4) .

**Scenario Realistic**: During node catchup after downtime, old AA triggers can remain queued while their units are evicted from cache, triggering the error.

## Why This Is NOT Critical

**Per Immunefi Obyte Scope Critical Criteria:**

1. **NOT Network Shutdown >24h**: Only affects individual nodes that experience specific downtime conditions, not network-wide consensus or transaction confirmation
2. **NOT Permanent Chain Split**: No consensus divergence; other nodes continue processing normally
3. **NOT Direct Loss of Funds**: No theft mechanism; funds remain safely in their addresses
4. **NOT Permanent Fund Freeze**: AA triggers remain in database queue; can be processed by other nodes or after node restart with code fix

**Actual Impact** (Medium severity):
- Temporary AA trigger processing halt on affected individual nodes
- Requires node restart + code patch for recovery  
- Does not prevent users from interacting with AAs via other nodes
- No permanent damage to funds or network state

## Critical Flaw in Severity Classification

The claim conflates **node-level operational issue** with **network-wide critical failure**. According to the Immunefi scope:
- **Critical** requires network-wide, >24h outages or permanent fund loss
- **Medium** covers temporary delays ≥1 hour and unintended AA behavior without fund risk

This is clearly Medium, not Critical. The framework explicitly states: *"Be ruthlessly skeptical. The bar for validity is EXTREMELY high."* Overstating severity by 2 levels (Medium → Critical) fails this standard.

## Notes

While this is a legitimate implementation bug that should be fixed (by checking cache existence before access or loading from database), it does not represent the catastrophic "Network Shutdown" vulnerability claimed. The issue affects node availability under specific operational conditions, not protocol security or fund safety.

### Citations

**File:** aa_composer.js (L99-101)
```javascript
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
```

**File:** sqlite_pool.js (L111-133)
```javascript
				new_args.push(function(err, result){
					//console.log("query done: "+sql);
					if (err){
						console.error("\nfailed query:", new_args);
						throw Error(err+"\n"+sql+"\n"+new_args[1].map(function(param){ if (param === null) return 'null'; if (param === undefined) return 'undefined'; return param;}).join(', '));
					}
					// note that sqlite3 sets nonzero this.changes even when rows were matched but nothing actually changed (new values are same as old)
					// this.changes appears to be correct for INSERTs despite the documentation states the opposite
					if (!bSelect && !bCordova)
						result = {affectedRows: this.changes, insertId: this.lastID};
					if (bSelect && bCordova) // note that on android, result.affectedRows is 1 even when inserted many rows
						result = result.rows || [];
					//console.log("changes="+this.changes+", affected="+result.affectedRows);
					var consumed_time = Date.now() - start_ts;
				//	var profiler = require('./profiler.js');
				//	if (!bLoading)
				//		profiler.add_result(sql.substr(0, 40).replace(/\n/, '\\n'), consumed_time);
					if (consumed_time > 25)
						console.log("long query took "+consumed_time+"ms:\n"+new_args.filter(function(a, i){ return (i<new_args.length-1); }).join(", ")+"\nload avg: "+require('os').loadavg().join(', '));
					self.start_ts = 0;
					self.currentQuery = null;
					last_arg(result);
				});
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
