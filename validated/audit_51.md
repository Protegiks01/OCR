# TOCTOU Race Condition in Arbiter Contract Status Updates

## Summary

The `respond()` function in `arbiter_contract.js` contains a Time-of-Check Time-of-Use (TOCTOU) race condition where contract status is checked at line 115 but updated only after asynchronous operations complete at line 127. This allows concurrent `revoke()` operations or peer messages to change the status during the async window, which then gets silently overwritten, causing permanent state inconsistency between contract parties. [1](#0-0) 

## Impact

**Severity**: Medium  
**Category**: Unintended Contract Behavior Without Direct Fund Risk

Contract parties can have permanently inconsistent views of contract state (one showing "accepted", the other "revoked"). However, this does not result in permanent fund freeze because the arbiter can resolve disputes through data feed transactions, and payment completion requires cooperation from both parties anyway.

## Finding Description

**Location**: `byteball/ocore/arbiter_contract.js`, functions `respond()` (lines 112-148), `revoke()` (lines 150-159), `setField()` (lines 76-87)

**Intended Logic**: The arbiter contract system should enforce atomic state transitions. The status check at line 115 is meant to ensure only valid transitions occur before proceeding with the acceptance flow.

**Actual Logic**: Due to Node.js's asynchronous event loop and lack of transaction protection, a race condition exists:

1. Status check passes at line 115 [2](#0-1) 
2. Asynchronous operations execute at lines 135-141 [3](#0-2) 
3. During this multi-second window, concurrent operations can change the status
4. Line 127 unconditionally overwrites status via `setField()` [4](#0-3) 

**Code Evidence**:

The `setField()` function performs an unconditional UPDATE without checking current status in the WHERE clause: [5](#0-4) 

The `revoke()` function has the same vulnerable check-then-act pattern: [6](#0-5) 

**Exploitation Path**:

1. **Preconditions**: Alice creates contract offer for Bob (status: "pending")

2. **Step 1 (T=0)**: Bob calls `respond(hash, "accepted", signedMsg, signer, callback)`
   - Status check at line 115 passes (status is "pending")
   - Async operations begin: `device.getOrGeneratePermanentPairingInfo()` followed by `composer.composeAuthorsAndMciForAddresses()`
   - Control returns to event loop

3. **Step 2 (T=1)**: Alice calls `revoke(hash)` on her node
   - Alice's database updated: status → "revoked"  
   - Alice sends `arbiter_contract_update` message to Bob [7](#0-6) 

4. **Step 3 (T=2)**: Bob's wallet receives Alice's message
   - Message handler validates transition "pending" → "revoked" is allowed [8](#0-7) 
   - Bob's database updated: status → "revoked"

5. **Step 4 (T=3)**: Bob's async operations complete
   - `setField()` executes at line 127, unconditionally setting status = "accepted"
   - Bob's database now shows "accepted", overwriting the "revoked" status

6. **Step 5 (T=4)**: Bob sends `arbiter_contract_response` to Alice
   - Alice's handler checks if transition "revoked" → "accepted" is valid
   - Validation at wallet.js:729 rejects this transition [9](#0-8) 
   - Alice's database remains "revoked"

**Final State**:
- Bob's database: status = "accepted"
- Alice's database: status = "revoked"  
- Permanent inconsistency - messages rejected by both parties' validation logic
- Contract cannot proceed to completion without manual reconciliation

**Security Property Broken**: State Consistency - distributed wallet databases must maintain consistent contract state across parties.

**Root Cause Analysis**:

1. **No Database Transactions**: The codebase has `db.executeInTransaction()` available but it is not used in `respond()` or `revoke()` [10](#0-9) 

2. **No Mutex Locks**: Confirmed via grep - no mutex protection in `arbiter_contract.js`

3. **Unconditional UPDATE**: The `setField()` function performs `UPDATE wallet_arbiter_contracts SET status=? WHERE hash=?` without validating current status in WHERE clause

4. **Large Timing Window**: Two sequential async operations create multi-second race window

## Impact Explanation

**Affected Assets**: Arbiter contract state consistency in wallet databases (not on-chain consensus state)

**Damage Severity**:
- **Quantitative**: Per-contract impact. State inconsistency affects contract parties' ability to proceed with standard flow.
- **Qualitative**: Requires manual reconciliation or arbiter intervention. However, funds are NOT permanently frozen because:
  - Shared address definition includes arbiter resolution paths [11](#0-10) 
  - Arbiter can post data feed to unlock funds unilaterally
  - Payment completion requires both parties' cooperation anyway

**User Impact**:
- **Who**: Both contract parties (offerer and acceptor)
- **Conditions**: Occurs when operations overlap in time during async window (1-5 seconds)
- **Recovery**: Requires arbiter intervention or manual state reconciliation, but funds remain accessible

**Systemic Risk**:
- Limited to arbiter contract feature, not core protocol consensus
- Similar pattern may exist in other state transition functions
- Automatic payment detection at line 680 could auto-transition to "paid" [12](#0-11) 

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Either contract party with normal wallet access
- **Resources Required**: Standard Obyte wallet
- **Technical Skill**: Low - can occur accidentally (rapid clicking) or deliberately

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Active arbiter contract in "pending" state
- **Timing**: Operations must overlap within async window (typically 1-5 seconds)

**Execution Complexity**:
- **Transaction Count**: Two concurrent operations (respond + revoke)
- **Coordination**: Single party changing mind quickly, or natural concurrent actions
- **Detection Risk**: Low - appears as normal contract operations

**Frequency**:
- **Repeatability**: Can occur naturally or be deliberately triggered
- **Scale**: Per-contract impact

**Overall Assessment**: Medium likelihood. The async window is substantial (several seconds), making both accidental and intentional races realistic.

## Recommendation

**Immediate Mitigation**:

Wrap status updates in database transactions with status validation in WHERE clause:

```javascript
// In arbiter_contract.js setField()
db.query("UPDATE wallet_arbiter_contracts SET " + field + "=? WHERE hash=? AND status=?", 
    [value, hash, expected_current_status], function(res) {
    if (res.affectedRows === 0) {
        return cb("Status changed during operation");
    }
    // ...
});
```

**Permanent Fix**:

Use `db.executeInTransaction()` to wrap the check-update sequence:

```javascript
function respond(hash, status, signedMessageBase64, signer, cb) {
    db.executeInTransaction(function(conn, done) {
        conn.query("SELECT * FROM wallet_arbiter_contracts WHERE hash=?", [hash], function(rows) {
            if (rows[0].status !== "pending" && rows[0].status !== "accepted")
                return done("contract is in non-applicable status");
            // Perform async operations
            // Update status
            done();
        });
    }, cb);
}
```

**Additional Measures**:
- Add test case verifying concurrent respond/revoke operations maintain consistency
- Add optimistic locking with version field in database schema
- Re-check status before final update

## Notes

**Severity Justification**: This is classified as **Medium** severity, not High/Critical as claimed, because:

1. **Not Permanent Fund Freeze**: The arbiter can resolve by posting a data feed transaction [11](#0-10) . This allows winner to withdraw funds unilaterally. Immunefi defines "Permanent Freezing" as "funds locked with no transaction able to unlock them" - this does not apply here.

2. **Payment Unlikely Without Cooperation**: The `createSharedAddressAndPostUnit()` function requires both parties to sign the unit sent from the shared address [13](#0-12) , preventing Bob from unilaterally locking funds.

3. **Wallet-Level Issue**: This affects wallet state synchronization, not core DAG consensus. Each party maintains their own local contract database.

4. **Immunefi Alignment**: Per Immunefi Obyte scope, this matches "Unintended AA/Contract Behavior Without Direct Fund Risk (Medium)" rather than "Permanent Freezing of Funds (High/Critical)".

The vulnerability is real and should be fixed, but the impact is operational disruption requiring manual intervention, not permanent fund loss.

### Citations

**File:** arbiter_contract.js (L76-87)
```javascript
function setField(hash, field, value, cb, skipSharing) {
	if (!["status", "shared_address", "unit", "my_contact_info", "peer_contact_info", "peer_pairing_code", "resolution_unit", "cosigners"].includes(field)) {
		throw new Error("wrong field for setField method");
	}
	db.query("UPDATE wallet_arbiter_contracts SET " + field + "=? WHERE hash=?", [value, hash], function(res) {
		if (!skipSharing)
			shareUpdateToCosigners(hash, field);
		if (cb) {
			getByHash(hash, cb);
		}
	});
}
```

**File:** arbiter_contract.js (L112-148)
```javascript
function respond(hash, status, signedMessageBase64, signer, cb) {
	cb = cb || function(){};
	getByHash(hash, function(objContract){
		if (objContract.status !== "pending" && objContract.status !== "accepted")
			return cb("contract is in non-applicable status");
		var send = function(authors, pairing_code) {
			var response = {hash: objContract.hash, status: status, signed_message: signedMessageBase64, my_contact_info: objContract.my_contact_info};
			if (authors) {
				response.authors = authors;
			}
			if (pairing_code) {
				response.my_pairing_code = pairing_code;
			}
			device.sendMessageToDevice(objContract.peer_device_address, "arbiter_contract_response", response);

			setField(objContract.hash, "status", status, function(objContract) {
				if (status === "accepted") {
					shareContractToCosigners(objContract.hash);
				};
				cb(null, objContract);
			});
		};
		if (status === "accepted") {
			device.getOrGeneratePermanentPairingInfo(function(pairingInfo){
				var pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
				composer.composeAuthorsAndMciForAddresses(db, [objContract.my_address], signer, function(err, authors) {
					if (err) {
						return cb(err);
					}
					send(authors, pairing_code);
				});
			});
		} else {
			send();
		}
	});
}
```

**File:** arbiter_contract.js (L150-159)
```javascript
function revoke(hash, cb) {
	getByHash(hash, function(objContract){
		if (objContract.status !== "pending")
			return cb("contract is in non-applicable status");
		setField(objContract.hash, "status", "revoked", function(objContract) {
			shareUpdateToPeer(objContract.hash, "status");
			cb(null, objContract);
		});
	});
}
```

**File:** arbiter_contract.js (L410-417)
```javascript
				        ["address", contract.my_address],
				        ["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", contract.my_address]]
				    ]],
				    ["and", [
				        ["address", contract.peer_address],
				        ["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", contract.peer_address]]
				    ]]
				]];
```

**File:** arbiter_contract.js (L516-517)
```javascript
								arrSigningDeviceAddresses: contract.cosigners.length ? contract.cosigners.concat([contract.peer_device_address, device.getMyDeviceAddress()]) : [],
								signing_addresses: [shared_address],
```

**File:** arbiter_contract.js (L680-681)
```javascript
					setField(contract.hash, "status", "paid", function(objContract) {
						eventBus.emit("arbiter_contract_update", objContract, "status", "paid", row.unit);
```

**File:** wallet.js (L618-639)
```javascript
						if (body.field === "status") {
							var isOK = false;
							switch (objContract.status) {
								case "pending":
									if (body.value === "revoked" || body.value === "accepted")
										isOK = true;
									break;
								case "paid":
									if (body.value === "in_dispute" || body.value === "cancelled" || body.value === "completed")
										isOK = true;
									break;
								case "dispute_resolved":
									if (body.value === "in_appeal")
										isOK = true;
									break;
								case "in_appeal":
									if (objContract.arbstore_device_address === from_address && (body.value === 'appeal_approved' || body.value === 'appeal_declined'))
										isOK = true;
									break;
							}
							if (!isOK)
								return callbacks.ifError("wrong status for contract supplied");
```

**File:** wallet.js (L729-731)
```javascript
						var isAllowed = objContract.status === "pending" || (objContract.status === 'accepted' && body.status === 'accepted');
						if (!isAllowed)
							return callbacks.ifError("contract is not active, current status: " + objContract.status);
```

**File:** db.js (L25-39)
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

module.exports.executeInTransaction = executeInTransaction;
```
