# NoVulnerability found for this question.

**Rationale:**

This claim fails multiple critical validation checks from the Obyte Protocol Validation Framework:

## 1. **Threat Model Violation - Not an Attacker Scenario**

The claim explicitly states this is "not an external attack" but rather "legitimate node operators trigger this accidentally" with "node operator with database access running maintenance script" as the attacker profile.

The validation framework requires: **"Unprivileged attacker can execute via realistic unit submission or AA trigger"**. [1](#0-0) 

A node operator with database access running maintenance scripts is a **trusted insider managing their own infrastructure**, not an unprivileged attacker. This violates the fundamental threat model which defines **Untrusted Actors** as: "Any user submitting units, AA developers deploying smart contracts, malicious peers in P2P network" - not node operators performing administrative tasks.

## 2. **Impact Misclassification - Not Network Shutdown**

The claim categorizes this as **Critical - Network Shutdown**, but explicitly states: "**Single affected node** becomes completely non-functional."

The Immunefi scope defines **Network Shutdown (Critical)** as: "Network unable to confirm new transactions for >24 hours" and "**All nodes** halt or reject valid units."

This is **per-node operational failure**, not network-wide shutdown. The network continues operating normally - only nodes that misuse this maintenance script are affected. [2](#0-1) 

## 3. **Self-Inflicted Operational Error**

The scenario involves a node operator breaking their own node by running a maintenance script with incorrect preconditions. This is similar to the framework's disqualification criterion: "Requires attacker to already possess the funds they seek to steal (self-draining is not an exploit)."

The proper API exists: [3](#0-2)  - the `replaceWitness()` function properly validates old witness existence, new witness validity, and prevents duplicates. The issue is bypassing this API with raw SQL scripts.

## 4. **No Valid Severity Category**

The Immunefi scope provides no category for "per-node operational failures from misusing administrative tools." All defined impacts require either:
- Network-wide effects (all nodes affected)
- Direct fund loss/theft
- Permanent chain splits

A single node operator breaking their own node through script misuse fits none of these categories.

## Conclusion

This is an **operational/DevOps issue** about defensive programming in administrative tooling, not a security vulnerability in the Obyte consensus protocol. The core protocol correctly validates witness counts [2](#0-1)  and provides proper APIs for witness management [4](#0-3) . 

Per the validation framework: "False positives harm credibility more than missed findings. Assume claims are invalid until overwhelming evidence proves otherwise."

### Citations

**File:** tools/replace_ops.js (L22-33)
```javascript
async function replace_OPs() {
	await asyncForEach(order_providers, async function(replacement) {
		if (replacement.old && replacement.new) {
			let result = await db.query("UPDATE my_witnesses SET address = ? WHERE address = ?;", [replacement.new, replacement.old]);
			console.log(result);
		}
	});
	db.close(function() {
		console.log('===== done');
		process.exit();
	});
}
```

**File:** my_witnesses.js (L31-32)
```javascript
		if (arrWitnesses.length !== constants.COUNT_WITNESSES)
			throw Error("wrong number of my witnesses: "+arrWitnesses.length);
```

**File:** my_witnesses.js (L38-68)
```javascript
function replaceWitness(old_witness, new_witness, handleResult){
	if (!ValidationUtils.isValidAddress(new_witness))
		return handleResult("new witness address is invalid");
	readMyWitnesses(function(arrWitnesses){
		if (arrWitnesses.indexOf(old_witness) === -1)
			return handleResult("old witness not known");
		if (arrWitnesses.indexOf(new_witness) >= 0)
			return handleResult("new witness already present");
		var doReplace = function(){
			db.query("UPDATE my_witnesses SET address=? WHERE address=?", [new_witness, old_witness], function(){
				handleResult();
			});
		};
	//	if (conf.bLight) // absent the full database, there is nothing else to check
			return doReplace();
		// these checks are no longer required in v4
	/*	db.query(
			"SELECT 1 FROM unit_authors CROSS JOIN units USING(unit) WHERE address=? AND sequence='good' AND is_stable=1 LIMIT 1", 
			[new_witness], 
			function(rows){
				if (rows.length === 0)
					return handleResult("no stable messages from the new witness yet");
				storage.determineIfWitnessAddressDefinitionsHaveReferences(db, [new_witness], function(bHasReferences){
					if (bHasReferences)
						return handleResult("address definition of the new witness has or had references");
					doReplace();
				});
			}
		);*/
	});
}
```
