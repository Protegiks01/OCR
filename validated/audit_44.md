# NoVulnerability found for this question.

## Reasoning

After thorough code analysis, I found that while there IS a legitimate memory leak in the code, the security claim **severely mischaracterizes the impact severity**, causing it to fail the Immunefi validation criteria.

### Code Evidence Confirms Memory Leak Exists

The claim's technical analysis is **partially correct**:

1. **Listener Registration**: wallet.js does register an event listener that expects cleanup [1](#0-0) 

2. **Missing Event Emissions**: In network.js handleJoint function, certain validation error callbacks do NOT emit the "validated-" event for unsigned joints:
   - `ifTransientError` callback [2](#0-1) 
   - `ifNeedParentUnits` callback [3](#0-2) 

3. **Pairing Requirement Confirmed**: The "sign" message type requires device pairing (not whitelisted) [4](#0-3) 

4. **Some Callbacks DO Emit**: `ifUnitError` and `ifJointError` correctly emit the event [5](#0-4) 

### Critical Flaw: Impact Mischaracterization

The claim states:

> **Severity**: Critical  
> **Category**: Network Shutdown  
> **Impact**: "Network not being able to confirm new transactions (total shutdown >24 hours)"

According to Immunefi's Critical severity definition for Network Shutdown, this requires: **"Network unable to confirm new transactions for >24 hours"** - meaning network-wide impact.

**Actual Impact:**
- Only affects **individual nodes** paired with the attacker
- **Network continues operating normally** - other nodes confirm transactions
- Users can connect to different hubs/nodes
- No consensus impact whatsoever
- No chain split, no transaction validity issues

### Correct Severity Assessment

This should be classified as:
- **MEDIUM** severity: "Temporary Transaction Delay ≥1 Day" (for users of affected node only)
- Or potentially **LOW** given the strict pairing precondition requiring user consent

### Why This Fails Validation

Per the Final Decision Matrix requirement:

> "Impact meets Critical, High, or Medium severity per Immunefi Obyte scope"

The claim fails because:
1. It asserts **Critical** "Network Shutdown" 
2. Actual impact is **individual node DoS**, not network-wide
3. Does not meet "Network unable to confirm new transactions" threshold
4. The network AS A WHOLE continues confirming transactions normally

### Notes

- The memory leak bug itself is real and should be fixed
- However, security bounty programs require accurate severity classification
- Overstating impact from "individual node DoS" to "network-wide shutdown" is a fundamental mischaracterization
- The pairing requirement (one-time user consent via QR code) is a significant attack barrier not adequately weighted in the claim's likelihood assessment

### Citations

**File:** wallet.js (L321-334)
```javascript
							eventBus.once("validated-"+objUnit.unit, function(bValid){
								if (!bValid){
									console.log("===== unit in signing request is invalid");
									return;
								}
								// This event should trigger a confirmation dialog.
								// If we merge coins from several addresses of the same wallet, we'll fire this event multiple times for the same unit.
								// The event handler must lock the unit before displaying a confirmation dialog, then remember user's choice and apply it to all
								// subsequent requests related to the same unit
								eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
							});
							// if validation is already under way, handleOnlineJoint will quickly exit because of assocUnitsInWork.
							// as soon as the previously started validation finishes, it will trigger our event handler (as well as its own)
							network.handleOnlineJoint(ws, objJoint);
```

**File:** network.js (L1028-1053)
```javascript
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

**File:** network.js (L1054-1066)
```javascript
				ifTransientError: function(error){
				//	throw Error(error);
					console.log("############################## transient error "+error);
					callbacks.ifTransientError ? callbacks.ifTransientError(error) : callbacks.ifUnitError(error);
					process.nextTick(unlock);
					joint_storage.removeUnhandledJointAndDependencies(unit, function(){
					//	if (objJoint.ball)
					//		db.query("DELETE FROM hash_tree_balls WHERE ball=? AND unit=?", [objJoint.ball, objJoint.unit.unit]);
						delete assocUnitsInWork[unit];
					});
					if (error.includes("last ball just advanced"))
						setTimeout(rerequestLostJoints, 10 * 1000, true);
				},
```

**File:** network.js (L1076-1079)
```javascript
				ifNeedParentUnits: function(arrMissingUnits){
					callbacks.ifNeedParentUnits(arrMissingUnits);
					unlock();
				},
```

**File:** device.js (L189-206)
```javascript
			db.query("SELECT hub, is_indirect FROM correspondent_devices WHERE device_address=?", [from_address], function(rows){
				if (rows.length > 0){
					if (json.device_hub && json.device_hub !== rows[0].hub) // update correspondent's home address if necessary
						db.query("UPDATE correspondent_devices SET hub=? WHERE device_address=?", [json.device_hub, from_address], function(){
							handleMessage(rows[0].is_indirect);
						});
					else
						handleMessage(rows[0].is_indirect);
				}
				else{ // correspondent not known
					var arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"];
					if (arrSubjectsAllowedFromNoncorrespondents.indexOf(json.subject) === -1){
						respondWithError("correspondent not known and not whitelisted subject");
						return;
					}
					handleMessage(false);
				}
			});
```
