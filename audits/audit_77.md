# NoVulnerability found for this question.

## Validation Analysis

I performed a thorough analysis of this claim about MySQL connection pool temporary table state leakage. While the report identifies some accurate code patterns, it fails critical validation checks:

### Fatal Flaws in the Claim

**1. Connection Leak vs. Dirty Connection Return**

The claim states: "Connection #1 returned to pool WITH `voter_balances` table still existing"

However, examining the actual code flow: [1](#0-0) 

When `countVotes()` throws an exception at line 1569, the code at lines 1187-1188 (`COMMIT` and `conn.release()`) is **never executed**. The connection is **leaked**, not returned to the pool. A leaked connection remains in the "in use" state and is not available for reuse. The MySQL connection pool does not automatically reclaim leaked connections and return them with dirty state.

**2. Uncaught Exception Would Crash Node.js**

The query wrapper in mysql_pool.js throws errors: [2](#0-1) 

When using async/await (no callback provided), the Promise is created at lines 28-31 with only a `resolve` handler, no `reject`. When an error occurs at line 47, the `throw err` happens inside the MySQL callback, **outside the Promise executor context**. This creates an uncaught exception that would crash the Node.js process, closing all connections and dropping temporary tables.

**3. Known Issue Already Addressed** [3](#0-2) 

The workaround at line 1772 for specific testnet MCIs demonstrates this issue was already encountered and patched, indicating it's not an active vulnerability.

**4. Deterministic Exceptions, Not Non-Deterministic**

The exceptions at lines 1770, 1686, 1691, 1809, and 1814 are **deterministic** - all nodes processing the same database state would hit identical errors. For consensus divergence, different nodes must behave differently on the same input. The claim's scenario requires:
- First: All nodes hit exception (deterministic)  
- Then: Some nodes get dirty connections, others don't (non-deterministic)

But if connections aren't returned (they're leaked), there's no second phase.

**5. No Proof of Concept**

The claim provides no runnable code demonstrating:
- How to trigger the initial exception
- How the leaked connection returns to the pool
- How the second CREATE TEMPORARY TABLE fails
- How this causes consensus divergence

### Conclusion

The claim fundamentally misunderstands the difference between a **leaked connection** (not released, unavailable for reuse) and a **dirty connection returned to pool** (released but with persistent state). The code shows the former, not the latter. Combined with deterministic exceptions and the existing workaround, this does not constitute a valid vulnerability.

### Citations

**File:** main_chain.js (L1166-1188)
```javascript
			let conn = await db.takeConnectionFromPool();
			await conn.query("BEGIN");
			storage.readLastStableMcIndex(conn, function(last_stable_mci){
				if (last_stable_mci >= constants.v4UpgradeMci && !(constants.bTestnet && last_stable_mci === 3547801))
					throwError(`${earlier_unit} not stable in db but stable in later units ${arrLaterUnits.join(', ')} in v4`);
				storage.readUnitProps(conn, earlier_unit, function(objEarlierUnitProps){
					var new_last_stable_mci = objEarlierUnitProps.main_chain_index;
					if (new_last_stable_mci <= last_stable_mci) // fix: it could've been changed by parallel tasks - No, our SQL transaction doesn't see the changes
						return throwError("new last stable mci expected to be higher than existing");
					var mci = last_stable_mci;
					var batch = kvstore.batch();
					advanceLastStableMcUnitAndStepForward();

					function advanceLastStableMcUnitAndStepForward(){
						mci++;
						if (mci <= new_last_stable_mci)
							markMcIndexStable(conn, batch, mci, advanceLastStableMcUnitAndStepForward);
						else{
							batch.write({ sync: true }, async function(err){
								if (err)
									throw Error("determineIfStableInLaterUnitsAndUpdateStableMcFlag: batch write failed: "+err);
								await conn.query("COMMIT");
								conn.release();
```

**File:** main_chain.js (L1772-1773)
```javascript
			if (constants.bTestnet && [3547796, 3548896, 3548898].includes(mci)) // workaround a bug
				ops = ["2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX", "2GPBEZTAXKWEXMWCTGZALIZDNWS5B3V7", "4H2AMKF6YO2IWJ5MYWJS3N7Y2YU2T4Z5", "DFVODTYGTS3ILVOQ5MFKJIERH6LGKELP", "ERMF7V2RLCPABMX5AMNGUQBAH4CD5TK4", "F4KHJUCLJKY4JV7M5F754LAJX4EB7M4N", "IOF6PTBDTLSTBS5NWHUSD7I2NHK3BQ2T", "O4K4QILG6VPGTYLRAI2RGYRFJZ7N2Q2O", "OPNUXBRSSQQGHKQNEPD2GLWQYEUY5XLD", "PA4QK46276MJJD5DBOLIBMYKNNXMUVDP", "RJDYXC4YQ4AZKFYTJVCR5GQJF5J6KPRI", "WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"];
```

**File:** mysql_pool.js (L34-47)
```javascript
		new_args.push(function(err, results, fields){
			if (err){
				console.error("\nfailed query: "+q.sql);
				/*
				//console.error("code: "+(typeof err.code));
				if (false && err.code === 'ER_LOCK_DEADLOCK'){
					console.log("deadlock, will retry later");
					setTimeout(function(){
						console.log("retrying deadlock query "+q.sql+" after timeout ...");
						connection_or_pool.original_query.apply(connection_or_pool, new_args);
					}, 100);
					return;
				}*/
				throw err;
```
