## Title
Information Disclosure in prosaic_contract.share() Function - Missing Authorization Check

## Summary
The `share()` function in `prosaic_contract.js` lacks authorization checks before retrieving and transmitting contract data, allowing unauthorized access to confidential contract details in multi-user deployment scenarios. However, this vulnerability has **limited exploitability** and falls below the Critical/High/Medium severity threshold.

## Impact
**Severity**: Low (Below Immunefi Scope Threshold)  
**Category**: Information Disclosure (Not directly covered by Immunefi categories)

## Finding Description

**Location**: `byteball/ocore/prosaic_contract.js`, function `share()` [1](#0-0) 

**Intended Logic**: The function should verify that the caller has permission to share the contract before retrieving and transmitting it to another device.

**Actual Logic**: The function retrieves any contract by hash and sends it to any specified device address without authorization checks.

**Code Evidence**:

The `share()` function performs no authorization: [1](#0-0) 

The underlying `getByHash()` function queries without wallet-based filtering: [2](#0-1) 

Database schema shows multi-wallet support but contracts lack wallet field: [3](#0-2) 

**Exploitation Path**:

**Preconditions**: 
- Multi-user/multi-wallet deployment (multiple wallets sharing same database)
- User A has contracts in the database
- User B knows or guesses User A's contract hash
- User B has code execution access to call the share() function

**Steps**:
1. User B (attacker) calls `prosaic_contract.share(victim_contract_hash, attacker_device_address)`
2. Function calls `getByHash()` which queries database without wallet filtering
3. Database returns victim's contract (title, text, cosigners, addresses, status)
4. Function transmits full contract to attacker's device via `prosaic_contract_shared` message
5. Attacker receives contract data

**Defense-in-Depth Mitigation (Present but Bypassable)**:

The receiving handler validates ownership before storage: [4](#0-3) 

However, this client-side validation:
- Only prevents storage, not message reception
- Can be bypassed by custom message handlers
- Doesn't prevent information disclosure during transmission

**Security Property Broken**: None of the 24 critical invariants are directly violated, as this is an application-layer access control issue rather than a consensus or fund integrity violation.

**Root Cause Analysis**: The function was designed assuming single-user deployments where all contracts in the database belong to the node owner. Multi-user scenarios were not considered during implementation.

## Why This Falls Below Immunefi Severity Threshold

**Limited Exploitability**:

1. **Deployment Requirement**: Only affects multi-user/multi-wallet deployments, which are uncommon for ocore
2. **Access Requirement**: Attacker needs code execution privileges to call the function
3. **Hash Knowledge**: Attacker must know victim's contract hash
4. **No Direct Financial Impact**: Information disclosure only - no fund theft, freezing, or network disruption

**Typical Deployment (Not Vulnerable to External Attackers)**:
- Standard ocore nodes run single-user wallets
- Contracts in database belong to that user
- External attackers cannot call share() without first compromising the node
- If node is compromised, attacker has direct database access anyway

**Immunefi Category Mismatch**:
- ❌ NOT "Direct loss of funds"
- ❌ NOT "Permanent freezing of funds" 
- ❌ NOT "Network shutdown or chain split"
- ❌ NOT "Temporary freezing of transactions"
- ❌ NOT "Unintended AA behavior"

This is a **data privacy issue** requiring specific deployment conditions and elevated access, placing it outside the scope of Critical/High/Medium severity findings per the provided Immunefi criteria.

## Recommendation

**For Multi-User Deployments**:

Add wallet-based authorization to `share()` and `getByHash()`: [2](#0-1) 

Recommended fix:
```javascript
function getByHash(hash, wallet, cb) {
    // If wallet is provided, filter by wallet ownership
    if (wallet) {
        db.query(
            "SELECT pc.* FROM prosaic_contracts pc \
            JOIN my_addresses ma ON pc.my_address = ma.address \
            WHERE pc.hash=? AND ma.wallet=?", 
            [hash, wallet], 
            function(rows){
                if (!rows.length) return cb(null);
                cb(decodeRow(rows[0]));
            }
        );
    } else {
        // Backward compatibility for single-user
        db.query("SELECT * FROM prosaic_contracts WHERE hash=?", [hash], function(rows){
            if (!rows.length) return cb(null);
            cb(decodeRow(rows[0]));
        });
    }
}
```

**For Production Applications**:
- Implement application-layer access control before exposing share()
- Never expose share() as public API without authorization
- Consider the function internal-only for single-user wallets

## Conclusion

While this is a **valid information disclosure vulnerability**, it:
- Requires multi-user deployment and code execution access
- Has no direct financial impact
- Doesn't meet the Critical/High/Medium severity criteria
- Is mitigated by client-side validation (though bypassable)
- Primarily affects custom multi-user applications, not standard ocore deployments

**This finding is documented for completeness but falls below the Immunefi scope threshold for this audit.**

---

**Notes:**

The vulnerability exists in the code but has **limited real-world exploitability** due to:
1. Most ocore deployments are single-user (not vulnerable to external attackers)
2. Multi-user deployments are custom applications expected to implement their own access control
3. Exploitation requires code execution privileges (already significant compromise)
4. No direct protocol-level or financial impact

Applications building on ocore should be aware of this limitation and implement proper authorization layers when exposing prosaic contract functionality in multi-tenant scenarios.

### Citations

**File:** prosaic_contract.js (L21-28)
```javascript
function getByHash(hash, cb) {
	db.query("SELECT * FROM prosaic_contracts WHERE hash=?", [hash], function(rows){
		if (!rows.length)
			return cb(null);
		var contract = rows[0];
		cb(decodeRow(contract));			
	});
}
```

**File:** prosaic_contract.js (L93-97)
```javascript
function share(hash, device_address) {
	getByHash(hash, function(objContract){
		device.sendMessageToDevice(device_address, "prosaic_contract_shared", objContract);
	})
}
```

**File:** initial-db/byteball-sqlite.sql (L784-799)
```sql
CREATE TABLE prosaic_contracts (
	hash CHAR(44) NOT NULL PRIMARY KEY,
	peer_address CHAR(32) NOT NULL,
	peer_device_address CHAR(33) NOT NULL,
	my_address  CHAR(32) NOT NULL,
	is_incoming TINYINT NOT NULL,
	creation_date TIMESTAMP NOT NULL,
	ttl REAL NOT NULL DEFAULT 168, -- 168 hours = 24 * 7 = 1 week
	status TEXT CHECK (status IN('pending', 'revoked', 'accepted', 'declined')) NOT NULL DEFAULT 'active',
	title VARCHAR(1000) NOT NULL,
	`text` TEXT NOT NULL,
	shared_address CHAR(32),
	unit CHAR(44),
	cosigners VARCHAR(1500),
	FOREIGN KEY (my_address) REFERENCES my_addresses(address)
);
```

**File:** wallet.js (L448-456)
```javascript
				db.query("SELECT 1 FROM my_addresses \n\
						JOIN wallet_signing_paths USING(wallet)\n\
						WHERE my_addresses.address=? AND wallet_signing_paths.device_address=?",[body.my_address, from_address],
					function(rows) {
						if (!rows.length)
							return callbacks.ifError("contract does not contain my address");
						prosaic_contract.store(body);
						callbacks.ifOk();
					}
```
