# NoVulnerability found for this question.

After thorough analysis of the codebase, I must conclude this claim represents a **threat model violation** that disqualifies it as a valid security finding.

## Critical Disqualification: Trusted Role Assumption

The vulnerability fundamentally requires assuming an **oracle behaves maliciously** by deliberately posting two sibling units to crash nodes. The validation framework explicitly states:

> "❌ Assumes compromised oracle data feed providers (oracles are trusted to provide correct data)"
> 
> "**Trusted Roles**: Witnesses post regular heartbeat units and vote on main chain; **oracles provide signed data feeds**; hub operators relay messages for light clients. **Do not assume these actors behave maliciously.**" [1](#0-0) 

While the technical analysis of the sort comparator is accurate (it does throw when two candidates have identical `latest_included_mc_index` and `level`), the exploitation scenario requires:

1. An oracle **deliberately** posting two sibling units with identical feed names
2. **Malicious intent** to crash validator nodes
3. Coordinated timing to trigger the crash

This constitutes malicious oracle behavior, which violates the trust assumption. The framework distinguishes between:
- **Data accuracy issues** (oracles providing incorrect prices) - explicitly excluded as trusted role
- **Protocol robustness** (system handling edge cases) - valid concern

However, **deliberately crafting sibling units to exploit a crash condition** is malicious behavior from a trusted actor, not a protocol robustness issue.

## Additional Considerations

Even if we considered the threat model acceptable, the report has critical deficiencies:

1. **No executable PoC provided** - framework requires "complete test using their test setup that must run"
2. **Impact overstated** - crash window only exists while units are unstable (~30-60 seconds), not truly ">24 hours network shutdown"
3. **Self-inflicted scenario** - attacker must deploy their own AA trusting their own oracle address [2](#0-1) 

The call path from AA execution to `readDataFeedValue()` is confirmed, but the fundamental premise violates the "do not assume oracles behave maliciously" requirement.

## Notes

While the code could benefit from defensive programming (adding a unit hash tie-breaker), this represents a hardening improvement rather than a critical vulnerability, given the trusted oracle assumption in Obyte's threat model.

### Citations

**File:** data_feeds.js (L237-246)
```javascript
			arrCandidates.sort(function (a, b) {
				if (a.latest_included_mc_index < b.latest_included_mc_index)
					return -1;
				if (a.latest_included_mc_index > b.latest_included_mc_index)
					return 1;
				if (a.level < b.level)
					return -1;
				if (a.level > b.level)
					return 1;
				throw Error("can't sort candidates "+a+" and "+b);
```

**File:** formula/evaluation.js (L588-605)
```javascript
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
					//	console.log(arrAddresses, feed_name, value, min_mci, ifseveral);
					//	console.log('---- objResult', objResult);
						if (objResult.bAbortedBecauseOfSeveral)
							return cb("several values found");
						if (objResult.value !== undefined){
							if (what === 'unit')
								return cb(null, objResult.unit);
							if (type === 'string')
								return cb(null, objResult.value.toString());
							return cb(null, (typeof objResult.value === 'string') ? objResult.value : createDecimal(objResult.value));
						}
						if (params.ifnone && params.ifnone.value !== 'abort'){
						//	console.log('===== ifnone=', params.ifnone.value, typeof params.ifnone.value);
							return cb(null, params.ifnone.value); // the type of ifnone (string, decimal, boolean) is preserved
						}
						cb("data feed " + feed_name + " not found");
					});
```
