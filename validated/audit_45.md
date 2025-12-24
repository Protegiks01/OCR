# NoVulnerability found for this question.

## Analysis Summary

After extensive code investigation of the Obyte codebase, this security claim fails validation on multiple critical points:

### 1. **Mischaracterization of Stability Advancement Process**

The claim assumes millions of units are marked `is_stable=1` in the database before `calcHeadersCommissions()` is called. However, examination of the actual code flow reveals: [1](#0-0) 

The `updateStableMcFlag()` function marks MCIs stable **one at a time** through recursive calls. Each call to `markMcIndexStable()` processes a single MCI: [2](#0-1) 

The database UPDATE statement explicitly targets only one MCI: `UPDATE units SET is_stable=1 WHERE is_stable=0 AND main_chain_index=?`

### 2. **Query Constraint Prevents Mass Fetching**

The SQLite query includes the constraint `WHERE punits.is_stable=1`: [3](#0-2) 

During incremental sync, when MCI N is marked stable, only units with MCI=N have `is_stable=1`. The query fetches only those newly-stable parenthoods, not millions of historical rows.

### 3. **No Exploit Path Exists**

The report fails to demonstrate:
- How a node would have millions of units marked `is_stable=1` while `max_spendable_mci=0`
- Any code path that marks multiple MCIs stable simultaneously before calling `calcHeadersCommissions()`
- A realistic scenario where the described memory exhaustion would occur

### 4. **Initialization Logic Works Correctly** [4](#0-3) 

For a new node, `initMaxSpendableMci()` returns 0 because the `headers_commission_outputs` table is empty. However, at this point, NO units are marked stable yet, so the query returns zero rows.

### 5. **Storage Cache Limitations**

The in-memory cache only stores recent stable units: [5](#0-4) 

With `COUNT_MC_BALLS_FOR_PAID_WITNESSING = 100`, only ~110 MCIs are kept in memory, not millions.

## Conclusion

The vulnerability description is based on a theoretical scenario (millions of stable units with `since_mc_index=0`) that **cannot occur** during normal node operation. The incremental, one-MCI-at-a-time stability advancement mechanism prevents the claimed unbounded memory exhaustion. This is a false positive resulting from misunderstanding the consensus flow.

### Citations

**File:** main_chain.js (L501-509)
```javascript
					function advanceLastStableMcUnitAndTryNext(){
						profiler.stop('mc-stableFlag');
						markMcIndexStable(conn, batch, first_unstable_mc_index, (count_aa_triggers) => {
							arrStabilizedMcis.push(first_unstable_mc_index);
							if (count_aa_triggers)
								bStabilizedAATriggers = true;
							updateStableMcFlag();
						});
					}
```

**File:** main_chain.js (L1212-1237)
```javascript
function markMcIndexStable(conn, batch, mci, onDone){
	profiler.start();
	let count_aa_triggers;
	var arrStabilizedUnits = [];
	if (mci > 0)
		storage.assocStableUnitsByMci[mci] = [];
	for (var unit in storage.assocUnstableUnits){
		var o = storage.assocUnstableUnits[unit];
		if (o.main_chain_index === mci && o.is_stable === 0){
			o.is_stable = 1;
			storage.assocStableUnits[unit] = o;
			storage.assocStableUnitsByMci[mci].push(o);
			arrStabilizedUnits.push(unit);
		}
	}
	arrStabilizedUnits.forEach(function(unit){
		delete storage.assocUnstableUnits[unit];
	});
	conn.query(
		"UPDATE units SET is_stable=1 WHERE is_stable=0 AND main_chain_index=?", 
		[mci], 
		function(){
			// next op
			handleNonserialUnits();
		}
	);
```

**File:** headers_commission.js (L70-84)
```javascript
				conn.cquery(
					// chunits is any child unit and contender for headers commission, punits is hc-payer unit
					"SELECT chunits.unit AS child_unit, punits.headers_commission, next_mc_units.unit AS next_mc_unit, punits.unit AS payer_unit \n\
					FROM units AS chunits \n\
					JOIN parenthoods ON chunits.unit=parenthoods.child_unit \n\
					JOIN units AS punits ON parenthoods.parent_unit=punits.unit \n\
					JOIN units AS next_mc_units ON next_mc_units.is_on_main_chain=1 AND next_mc_units.main_chain_index=punits.main_chain_index+1 \n\
					WHERE chunits.is_stable=1 \n\
						AND +chunits.sequence='good' \n\
						AND punits.main_chain_index>? \n\
						AND +punits.sequence='good' \n\
						AND punits.is_stable=1 \n\
						AND chunits.main_chain_index-punits.main_chain_index<=1 \n\
						AND next_mc_units.is_stable=1", 
					[since_mc_index],
```

**File:** headers_commission.js (L257-263)
```javascript
function initMaxSpendableMci(conn, onDone){
	conn.query("SELECT MAX(main_chain_index) AS max_spendable_mci FROM headers_commission_outputs", function(rows){
		max_spendable_mci = rows[0].max_spendable_mci || 0; // should be -1, we lose headers commissions paid by genesis unit
		if (onDone)
			onDone();
	});
}
```

**File:** storage.js (L2240-2242)
```javascript
		last_stable_mci = _last_stable_mci;
		let top_mci = Math.min(min_retrievable_mci, last_stable_mci - constants.COUNT_MC_BALLS_FOR_PAID_WITNESSING - 10);
		const last_tps_fees_mci = await getLastTpsFeesMci(conn);
```
