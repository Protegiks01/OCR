# Analysis: Race Condition in `my_witnesses.js`

After thorough investigation of the `replaceWitness()` and `readMyWitnesses()` functions, I must report that **the specific scenario described in the security question cannot happen as stated**, though there is a related but different race condition vulnerability present.

## The Question's Scenario Analysis

The question asks if an external `readMyWitnesses()` call can happen after a DELETE in `replaceWitness`'s nested call but before the UPDATE, causing "replacement to fail with 'old witness not known'".

**This scenario cannot occur because:**

If the DELETE at line 17 triggers within `replaceWitness`'s nested `readMyWitnesses()` call, the function immediately sets `arrWitnesses = []` at line 18. [1](#0-0) 

When `arrWitnesses` is empty and `actionIfEmpty` is undefined (as it is in `replaceWitness`'s call), the code throws an error at line 32: `"wrong number of my witnesses: " + arrWitnesses.length` [2](#0-1) 

This means `replaceWitness` would **fail before reaching the UPDATE at line 47** with "wrong number of my witnesses: 0", NOT "old witness not known".

## Actual TOCTOU Vulnerability Found

However, there **is** a real race condition in `replaceWitness()`, just not the one described:

**The vulnerability:** `replaceWitness()` uses a check-then-act pattern without database transaction isolation. [3](#0-2) 

The UPDATE callback at line 47-49 does not check whether any rows were actually affected. The database layer returns `affectedRows` in the result object [4](#0-3) , but `replaceWitness` ignores this and calls `handleResult()` with no error even when UPDATE affects 0 rows.

**Exploitation scenario:**
1. Thread A: `replaceWitness(W1, W2)` validates W1 exists (lines 41-45)
2. Thread B: `replaceWitness(W1, W3)` validates W1 exists (lines 41-45)  
3. Thread A: UPDATE W1→W2 succeeds
4. Thread B: UPDATE W1→W3 affects 0 rows (W1 already replaced)
5. Thread B: Callback invoked with **no error** despite silent failure

This violates **Invariant #21 (Transaction Atomicity)** - witness replacement should be atomic and correctly reported.

**Impact:** Medium severity - can cause inconsistent witness state across nodes if multiple concurrent replacements occur, particularly during witness list upgrades triggered by network.js [5](#0-4) 

## Notes

The specific race condition described in the question involving the DELETE operation cannot happen because the error is thrown before reaching the UPDATE. However, `replaceWitness()` does contain a TOCTOU vulnerability due to lack of transaction isolation and missing `affectedRows` validation, which could lead to silent failures during concurrent witness replacements.

The fix would require wrapping the read-check-update sequence in a database transaction using `db.executeInTransaction()` [6](#0-5)  and verifying `affectedRows` equals 1 after the UPDATE.

### Citations

**File:** my_witnesses.js (L17-18)
```javascript
			db.query("DELETE FROM my_witnesses");
			arrWitnesses = [];
```

**File:** my_witnesses.js (L31-32)
```javascript
		if (arrWitnesses.length !== constants.COUNT_WITNESSES)
			throw Error("wrong number of my witnesses: "+arrWitnesses.length);
```

**File:** my_witnesses.js (L41-49)
```javascript
	readMyWitnesses(function(arrWitnesses){
		if (arrWitnesses.indexOf(old_witness) === -1)
			return handleResult("old witness not known");
		if (arrWitnesses.indexOf(new_witness) >= 0)
			return handleResult("new witness already present");
		var doReplace = function(){
			db.query("UPDATE my_witnesses SET address=? WHERE address=?", [new_witness, old_witness], function(){
				handleResult();
			});
```

**File:** sqlite_pool.js (L119-120)
```javascript
					if (!bSelect && !bCordova)
						result = {affectedRows: this.changes, insertId: this.lastID};
```

**File:** network.js (L1910-1918)
```javascript
			for (let i = 0; i < diff1.length; i++) {
				const old_witness = diff1[i];
				const new_witness = diff2[i];
				console.log(`replacing witness ${old_witness} with ${new_witness}`);
				myWitnesses.replaceWitness(old_witness, new_witness, err => {
					if (err)
						throw Error(`failed to replace witness ${old_witness} with ${new_witness}: ${err}`);
				});
			}
```

**File:** db.js (L25-37)
```javascript
function executeInTransaction(doWork, onDone){
	module.exports.takeConnectionFromPool(function(conn){
		conn.query("BEGIN", function(){
			doWork(conn, function(err){
				conn.query(err ? "ROLLBACK" : "COMMIT", function(){
					conn.release();
					if (onDone)
						onDone(err);
				});
			});
		});
	});
}
```
