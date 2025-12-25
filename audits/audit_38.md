# NoVulnerability found for this question.

## Validation Analysis

After thorough code examination and framework validation, I **concur with the submission's assessment**. The reported behavior is technically accurate, but does not meet Immunefi's severity threshold for a valid vulnerability claim.

## Code Behavior Verified

The following technical facts are confirmed through codebase analysis:

1. **Event Listener Registration Without Cleanup**: [1](#0-0) 
   The code registers an event listener that waits for a unit to be saved.

2. **Missing Cleanup on Unit Not Found**: [2](#0-1) 
   When the unit is not found, the function returns successfully but leaves the listener attached indefinitely.

3. **Correct Pattern Exists Elsewhere**: [3](#0-2) 
   The proper cleanup pattern (removing the listener on error) is demonstrated in other parts of the codebase.

## Critical Precondition Barrier

The attack requires correspondent authorization: [4](#0-3) 

Only devices in the `correspondent_devices` table can send `payment_notification` messages. Non-correspondents are restricted to: `["pairing", "my_xpubkey", "wallet_fully_approved"]`. This means:

- **Regular users**: Attacker must socially engineer device pairing
- **Merchants/bots**: Attack works if device address is publicly published [5](#0-4) 

While the code acknowledges addresses "can be public," it notes this is not the normal/recommended practice.

## Why This Does Not Meet Immunefi Threshold

### Impact Scope: Node-Level, Not Network-Level

Per Immunefi Obyte scope, **Critical** requires: "Network shutdown - Network unable to confirm new transactions for more than 24 hours"

This memory leak attack:
- Crashes **individual nodes** (the specific node being attacked)
- Does **NOT** prevent the network from confirming transactions
- Does **NOT** affect DAG consensus, main chain advancement, or witness voting
- Does **NOT** impact transaction validation or fund security on other nodes

Even if all hub nodes were targeted, light clients could reconnect to different hubs, and full nodes would continue operating normally.

### No Protocol Invariant Violation

This is a **resource management issue** in device messaging (application layer), not a violation of core protocol security properties:
- ✅ Balance conservation intact
- ✅ Double-spend prevention intact
- ✅ Main chain monotonicity intact
- ✅ Witness compatibility intact
- ✅ Consensus determinism intact

### Severity Classification

- **Critical**: ❌ Not a network shutdown
- **High**: ❌ No fund freezing
- **Medium**: ❌ Not a network-wide transaction delay (≥1 hour)

The correct classification is **Low/Informational** (resource leak in device messaging), which is below Immunefi's Medium threshold.

## Notes

This is a **legitimate code quality issue** that should be fixed by adding cleanup similar to `private_profile.js`:

```javascript
// In wallet.js, lines 404-407, should add:
ifNotFound: function(){
    eventBus.removeListener('saved_unit-'+unit, emitPn); // Add this
    console.log("received payment notification for unit "+unit+" which is not known yet, will wait for it");
    callbacks.ifOk();
},
```

However, it does not constitute a valid Critical/High/Medium severity vulnerability per Immunefi's Obyte bug bounty program requirements. The submission correctly applies "ruthless skepticism" and accurately distinguishes between a code quality issue and a protocol-level security vulnerability.

### Citations

**File:** wallet.js (L388-390)
```javascript
				// note that since the payments are public, an evil user might notify us about a payment sent by someone else 
				// (we'll be fooled to believe it was sent by the evil user).  It is only possible if he learns our address, e.g. if we make it public.
				// Normally, we generate a one-time address and share it in chat session with the future payer only.
```

**File:** wallet.js (L402-402)
```javascript
				eventBus.once('saved_unit-'+unit, emitPn);
```

**File:** wallet.js (L404-407)
```javascript
					ifNotFound: function(){
						console.log("received payment notification for unit "+unit+" which is not known yet, will wait for it");
						callbacks.ifOk();
					},
```

**File:** private_profile.js (L80-82)
```javascript
					if (err) {
						eventBus.removeListener('saved_unit-'+objPrivateProfile.unit, handleJoint);
						return onDone(err);
```

**File:** device.js (L198-204)
```javascript
				else{ // correspondent not known
					var arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"];
					if (arrSubjectsAllowedFromNoncorrespondents.indexOf(json.subject) === -1){
						respondWithError("correspondent not known and not whitelisted subject");
						return;
					}
					handleMessage(false);
```
