## Title
Stale Oracle Data Return Due to Premature Exit in Data Feed Query with Single Unstable Candidate

## Summary
The `readDataFeedValue()` function in `data_feeds.js` returns immediately when exactly one unstable data feed candidate is found with `ifseveral='last'`, completely bypassing the stable database query that might contain more recent stable feeds with higher MCI values. [1](#0-0) 

## Impact
**Severity**: Medium  
**Category**: Unintended AA Behavior / Potential Direct Fund Loss

## Finding Description

**Location**: `byteball/ocore/data_feeds.js` - `readDataFeedValue()` function, lines 224-230

**Intended Logic**: When `ifseveral='last'` is specified, the function should return the data feed with the highest MCI (Main Chain Index) among all matching feeds, representing the most recent oracle value. The function should check both unstable units in memory and stable units in the database, then compare their MCIs to determine which is truly "last".

**Actual Logic**: When exactly one unstable candidate is found, the function performs an early return without querying the stable database. [1](#0-0)  This prevents comparison with potentially more recent stable feeds that may have higher MCI values in the database. [2](#0-1) 

**Exploitation Path**:

1. **Preconditions**: 
   - Oracle address has posted multiple data feeds over time
   - One feed has become stable with MCI = 1500 (e.g., `BTC_USD=50000`)
   - Another feed remains unstable with `latest_included_mc_index=1200` (e.g., `BTC_USD=45000`)
   - The unstable feed was posted on a different DAG branch or at nearly the same time, resulting in a lower `latest_included_mc_index` despite being chronologically earlier

2. **Step 1**: Autonomous Agent executes formula containing `data_feed({oracles: ['ORACLE_ADDR'], feed_name: 'BTC_USD', ifseveral: 'last'})`

3. **Step 2**: The `readDataFeedValue()` function searches unstable messages in memory [3](#0-2)  and finds exactly one matching unstable feed with `latest_included_mc_index=1200`, value `45000`

4. **Step 3**: The early return condition triggers [1](#0-0)  and immediately returns the unstable feed without checking the stable database

5. **Step 4**: The stable database query that would have found the more recent feed at MCI 1500 is never executed [2](#0-1) , causing the AA to execute with stale price data ($45k instead of $50k)

**Security Property Broken**: Violates **Invariant #10 (AA Deterministic Execution)** - AAs should produce identical results across all nodes for the same input state, but different nodes may have different unstable units in their `storage.assocUnstableMessages`, potentially causing non-deterministic behavior. Additionally violates the semantic contract of the `ifseveral='last'` parameter.

**Root Cause Analysis**: The code assumes that when exactly one unstable candidate exists, it must be the most recent feed. However, this assumption is incorrect because an unstable unit's `latest_included_mc_index` only represents the highest stable MCI in its parent chain at the time it was posted, not its final position. A stable feed with a higher actual MCI could exist in the database. The comment at line 220 states `mci: max_mci // it doesn't matter`, which sets the unstable feed's MCI to the query's upper bound rather than its actual position, further indicating the comparison logic is incomplete. [4](#0-3) 

## Impact Explanation

**Affected Assets**: AAs that rely on oracle price feeds for financial decisions (DEX swaps, lending protocols, derivatives, prediction markets)

**Damage Severity**:
- **Quantitative**: Variable depending on price difference and transaction volume. A 10% price discrepancy on a $100k transaction results in $10k incorrect valuation.
- **Qualitative**: Oracle-dependent contracts execute with outdated data, potentially causing incorrect liquidations, unfavorable swaps, or wrong conditional logic execution.

**User Impact**:
- **Who**: Users interacting with AAs that use `data_feed(..., ifseveral: 'last')` for price-dependent operations
- **Conditions**: Occurs when oracle has posted multiple feeds where one is stable (higher MCI) and one is unstable (lower `latest_included_mc_index`), and AA queries during this window
- **Recovery**: If AA state is affected, may require manual intervention or be irreversible depending on AA design

**Systemic Risk**: Different nodes may have different sets of unstable units in memory, leading to non-deterministic AA execution results across the network. This could cause consensus failures when nodes attempt to validate each other's AA trigger results.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Sophisticated attacker monitoring oracle feed timing and AA execution patterns
- **Resources Required**: Ability to trigger AA execution (gas fees), real-time monitoring of network state
- **Technical Skill**: High - requires understanding of Obyte DAG structure, oracle timing, and AA execution flow

**Preconditions**:
- **Network State**: Oracle must have posted multiple feeds with one stable (higher MCI) and one unstable (lower `latest_included_mc_index`)
- **Attacker State**: Must be able to trigger or wait for AA execution during the vulnerability window
- **Timing**: Vulnerability window exists from when unstable feed arrives until it stabilizes or AA queries with different parameters

**Execution Complexity**:
- **Transaction Count**: 1 (trigger AA execution)
- **Coordination**: Low - attacker passively monitors and acts when conditions naturally occur
- **Detection Risk**: Low - appears as normal AA interaction

**Frequency**:
- **Repeatability**: Moderate - depends on oracle posting frequency and network confirmation times
- **Scale**: Limited to AAs using `ifseveral='last'` during specific network state windows

**Overall Assessment**: Medium likelihood - conditions occur naturally but require specific timing and network state

## Recommendation

**Immediate Mitigation**: Add warning in documentation about potential staleness when using `ifseveral='last'` with unstable feeds, or disable unstable feed inclusion for price-critical operations.

**Permanent Fix**: Modify the early return logic to always query the stable database and compare MCIs before returning:

**Code Changes**:
Remove the early return at line 230 and allow execution to continue to the stable DB query. Then modify the stable feed comparison logic to properly handle the case where an unstable feed already exists in `objResult`. The comparison at line 298 in `readDataFeedByAddress` should compare `latest_included_mc_index` from unstable feeds against actual MCI from stable feeds. [5](#0-4) 

Specifically:
1. Remove or modify the early return at line 230 to fall through to stable DB query
2. Ensure that when comparing feeds, the unstable feed's `latest_included_mc_index` is compared against stable feed's actual MCI
3. Return the feed with the highest MCI/`latest_included_mc_index` value

**Additional Measures**:
- Add integration test covering scenario with 1 unstable feed (lower `latest_included_mc_index`) and 1 stable feed (higher MCI)
- Add monitoring to detect when unstable feeds are returned over stable feeds in production
- Consider adding explicit MCI comparison logging for debugging

**Validation**:
- Fix ensures stable DB is always queried when `ifseveral='last'`
- No performance regression from additional DB query (async operation)
- Maintains backward compatibility for cases where no stable feed exists
- Prevents non-deterministic behavior across nodes

## Notes

The vulnerability is confirmed to exist as described in the security question. The early return at lines 224-230 definitively skips the stable database query at lines 255-264. While the oracle data itself is trusted, the bug causes the wrong (stale) feed to be selected when multiple legitimate feeds exist. This is particularly concerning for AA execution where deterministic behavior is critical. The severity is Medium rather than High because exploitation requires specific network state conditions that occur naturally but are not directly controllable by attackers, and the impact is limited to AAs using this specific parameter combination.

### Citations

**File:** data_feeds.js (L196-223)
```javascript
		var arrCandidates = [];
		for (var unit in storage.assocUnstableMessages) {
			var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
			if (!objUnit)
				throw Error("unstable unit " + unit + " not in assoc");
			if (!objUnit.bAA && !bIncludeAllUnstable)
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
			storage.assocUnstableMessages[unit].forEach(function (message) {
				if (message.app !== 'data_feed')
					return;
				var payload = message.payload;
				if (!ValidationUtils.hasOwnProperty(payload, feed_name))
					return;
				var feed_value = payload[feed_name];
				if (value === null || value === feed_value || value.toString() === feed_value.toString())
					arrCandidates.push({
						value: string_utils.getFeedValue(feed_value, bLimitedPrecision),
						latest_included_mc_index: objUnit.latest_included_mc_index,
						level: objUnit.level,
						unit: objUnit.unit,
						mci: max_mci // it doesn't matter
					});
			});
		}
```

**File:** data_feeds.js (L224-230)
```javascript
		if (arrCandidates.length === 1) {
			var feed = arrCandidates[0];
			objResult.value = feed.value;
			objResult.unit = feed.unit;
			objResult.mci = feed.mci;
			if (ifseveral === 'last')
				return handleResult(objResult);
```

**File:** data_feeds.js (L255-264)
```javascript
	async.eachSeries(
		arrAddresses,
		function(address, cb){
			readDataFeedByAddress(address, feed_name, value, min_mci, max_mci, ifseveral, objResult, cb);
		},
		function(err){ // err passed here if aborted because of several
			console.log('data feed by '+arrAddresses+' '+feed_name+', val='+value+': '+objResult.value+', dfv took '+(Date.now()-start_time)+'ms');
			handleResult(objResult);
		}
	);
```

**File:** data_feeds.js (L298-298)
```javascript
		if (objResult.value === undefined || ifseveral === 'last' && mci > objResult.mci){
```
