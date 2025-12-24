# NoVulnerability found for this question.

**Reason for Rejection:**

While the technical analysis of the code structure is accurate, this claim fails a critical validation requirement: **the vulnerability cannot actually be exploited as described**.

## Why This Is Not Exploitable

The claim states that an attacker can create a unit with a deeply nested AA definition (~15,000 levels, ~90KB) that will cause stack overflow during payload size calculation. However, there's a critical flaw in this exploit scenario:

**The unit cannot be created in the first place.** 

Before any unit reaches the network validation at line 138, it must first be:

1. **Constructed by the composer** - The `composer.js` module itself would call `objectLength.getTotalPayloadSize()` when calculating fees [1](#0-0) 

2. **Hash calculated** - The `objectHash.getUnitHash()` function processes the entire unit structure, which would encounter the same deeply nested structure [2](#0-1) 

3. **Parsed by receiving nodes** - JSON.parse() in Node.js has its own recursion limits

The stack overflow would occur **during unit construction**, not during network validation. This means:
- The attacker's own node would crash when trying to create the malicious unit
- The malicious unit would never be successfully created, signed, or broadcast
- Other nodes would never receive it

## Additional Issues with the Claim

1. **No actual PoC provided**: The claim lacks runnable test code demonstrating the exploit. Per the framework requirements, a valid PoC must "be implementable in Node.js/JavaScript" and "actually compile and run."

2. **Unrealistic attack assumption**: The claim assumes the attacker can somehow bypass `getLength()` recursion during unit creation but then trigger it during validation. This is inconsistent - the same function is called in both contexts.

3. **Missing try-catch analysis incomplete**: While line 138 lacks direct try-catch, the claim doesn't analyze whether errors would propagate to higher-level handlers in the event loop or be caught by validation callback mechanisms [3](#0-2) 

**Mental Checklist Failed:**
- ❌ Can the PoC actually be implemented without modifying source files? (No - attacker cannot create the malicious unit)
- ❌ Is the exploit realistic and achievable? (No - unit creation fails before network propagation)

The vulnerability **may exist in theory** (unbounded recursion in `getLength()`), but the exploit path described is **not feasible in practice**, making this claim invalid for bug bounty purposes.

### Citations

**File:** object_length.js (L61-67)
```javascript
function getTotalPayloadSize(objUnit) {
	if (objUnit.content_hash)
		throw Error("trying to get payload size of stripped unit");
	var bWithKeys = (objUnit.version !== constants.versionWithoutTimestamp && objUnit.version !== constants.versionWithoutKeySizes);
	const { temp_data_length, messages_without_temp_data } = extractTempData(objUnit.messages);
	return Math.ceil(temp_data_length * constants.TEMP_DATA_PRICE) + getLength({ messages: messages_without_temp_data }, bWithKeys);
}
```

**File:** validation.js (L64-71)
```javascript
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}
```

**File:** network.js (L1027-1053)
```javascript
			validation.validate(objJoint, {
				ifUnitError: function(error){
					console.log(objJoint.unit.unit+" validation failed: "+error);
					callbacks.ifUnitError(error);
					if (constants.bDevnet)
						throw Error(error);
					unlock();
					purgeJointAndDependenciesAndNotifyPeers(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
					if (ws && error !== 'authentifier verification failed' && !error.match(/bad merkle proof at path/) && !bPosted)
						writeEvent('invalid', ws.host);
					if (objJoint.unsigned)
						eventBus.emit("validated-"+unit, false);
				},
				ifJointError: function(error){
					callbacks.ifJointError(error);
				//	throw Error(error);
					unlock();
					joint_storage.saveKnownBadJoint(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
					if (ws)
						writeEvent('invalid', ws.host);
					if (objJoint.unsigned)
						eventBus.emit("validated-"+unit, false);
				},
```
