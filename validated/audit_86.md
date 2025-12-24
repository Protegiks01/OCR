# NoVulnerability found for this question.

## Analysis

While the technical observation is **accurate** that expensive `_.cloneDeep()` operations occur before size validation, this claim **fails** to meet the Immunefi Medium severity threshold for the following reasons:

### 1. Impact Does Not Meet Medium Severity Requirement

The Immunefi Obyte scope explicitly requires for Medium severity:
- **"Temporary Transaction Delay ≥1 Hour"** OR
- **"Temporary Transaction Delay ≥1 Day"**

The report's own calculations demonstrate:
- 1000 units × 200ms per unit = **~3.3 minutes** per attack wave

This is **18× below** the minimum 1-hour threshold required for Medium severity. [1](#0-0) 

### 2. Code Evidence is Accurate But Impact is Insufficient

The expensive cloning operations are confirmed:
- `objectHash.getUnitHash()` at validation.js:66 triggers `getNakedUnit()` which performs `_.cloneDeep(objUnit)` [2](#0-1) 
- `objectLength.getHeadersSize()` at validation.js:136 performs `_.cloneDeep(objUnit)` [3](#0-2) 
- Size check occurs later at validation.js:140 [4](#0-3) 
- Global mutex `['handleJoint']` serializes validation [5](#0-4) 

However, the **maximum unit size is 5MB** [6](#0-5) , and even with multiple clones, the demonstrated delay of ~3 minutes per 1000 units does not constitute a valid Medium severity finding.

### 3. Sustained Attack Requirements Are Unrealistic

To reach ≥1 hour delay, the attacker would need:
- **Continuous flooding** with 5MB units at 5 units/second = 25 MB/s = **200 Mbps sustained bandwidth**
- **Continuous operation** for over 1 hour without operator mitigation
- **No economic incentive** (attack provides no financial gain)

The report acknowledges this: "attacker can repeat indefinitely" - but this is **speculative** without demonstration that operators couldn't mitigate via IP blocking, rate limiting, or other network-level defenses.

### 4. No Runnable Proof of Concept

No actual test code is provided demonstrating:
- Sustained >1 hour validation delay
- Actual node blocking in practice
- Inability of operators to mitigate

### 5. Missing Severity Component

Per the validation framework, a valid finding must have:
- "Impact meets Critical, High, or **Medium** severity per Immunefi Obyte scope"

The demonstrated impact of **3.3 minutes << 1 hour** means this does NOT meet the explicitly stated Medium threshold.

## Notes

This is an interesting **performance optimization opportunity** rather than a security vulnerability. The validation architecture could be improved by checking unit size earlier before expensive operations. However, without demonstrating **≥1 hour** of transaction delay per the Immunefi criteria, this does not qualify as a valid Medium severity finding.

The MAX_UNIT_LENGTH check at line 140 ensures the protocol enforces size limits - the expensive operations are part of the designed validation flow for calculating commissions. While the order could be optimized, the current behavior does not meet the severity threshold for a valid security finding.

### Citations

**File:** validation.js (L66-66)
```javascript
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
```

**File:** validation.js (L140-141)
```javascript
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis)
			return callbacks.ifUnitError("unit too large");
```

**File:** object_hash.js (L29-30)
```javascript
function getNakedUnit(objUnit){
	var objNakedUnit = _.cloneDeep(objUnit);
```

**File:** object_length.js (L42-45)
```javascript
function getHeadersSize(objUnit) {
	if (objUnit.content_hash)
		throw Error("trying to get headers size of stripped unit");
	var objHeader = _.cloneDeep(objUnit);
```

**File:** network.js (L1026-1026)
```javascript
		mutex.lock(['handleJoint'], function(unlock){
```

**File:** constants.js (L58-58)
```javascript
exports.MAX_UNIT_LENGTH = process.env.MAX_UNIT_LENGTH || 5e6;
```
