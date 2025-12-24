# NoVulnerability found for this question.

After thorough analysis of the codebase, I must conclude that while the reported code behavior is technically accurate, it **does not meet the Immunefi severity threshold** for a valid vulnerability claim.

## Analysis Summary

**Code Behavior Confirmed:**
- ✅ Line 402 registers event listener without timeout [1](#0-0) 
- ✅ Lines 404-407 return without cleanup when unit not found [2](#0-1) 
- ✅ EventEmitter allows unlimited listeners (setMaxListeners is warning-only) [3](#0-2) 
- ✅ Other code (private_profile.js) shows correct cleanup pattern [4](#0-3) 

**Critical Disqualifying Factors:**

1. **Severity Threshold Not Met**: Per Immunefi Obyte scope, **Critical** requires "Network shutdown - Network unable to confirm new transactions for more than 24 hours". This attack affects **individual nodes**, not the network's ability to confirm transactions.

2. **Precondition Barrier**: Attack requires either:
   - Device pairing (social engineering for private users)
   - OR victim publishes device address (only merchants/bots)
   - Comment acknowledges addresses "can be public" but doesn't recommend it [5](#0-4) 

3. **Impact Scope**: Even if all hub nodes were targeted, this would be **infrastructure availability** issue, not a protocol-level vulnerability. The DAG consensus, transaction validation, and fund security remain intact.

4. **Not a Security Invariant Violation**: This is a **resource management issue** in device messaging (off-chain), not a violation of any of the 24 DAG/consensus invariants. It doesn't affect:
   - Balance conservation
   - Double-spend prevention  
   - MC monotonicity
   - Witness compatibility
   - Consensus determinism

## Notes

This is a legitimate **code quality issue** that should be fixed (add cleanup like private_profile.js does), but it's a **DoS vulnerability against individual nodes**, not a Critical network security flaw. The correct classification would be **Low/Informational** severity for a resource leak, which is below Immunefi's Medium threshold (≥1 hour transaction delay for the network).

The framework requires "ruthless skepticism" and that findings must "withstand scrutiny from Obyte core developers and Immunefi judges." A memory leak affecting individual nodes that requires pairing or public address exposure does not meet the Critical severity bar.

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

**File:** event_bus.js (L8-8)
```javascript
eventEmitter.setMaxListeners(40);
```

**File:** private_profile.js (L80-82)
```javascript
					if (err) {
						eventBus.removeListener('saved_unit-'+objPrivateProfile.unit, handleJoint);
						return onDone(err);
```
