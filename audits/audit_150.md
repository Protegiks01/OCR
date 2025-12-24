# NoVulnerability found for this question.

## Detailed Analysis:

After thorough code examination, this claim fails critical validation requirements:

### 1. **Standard API Always Includes Version**
The standard `signMessage()` function mandates version inclusion: [1](#0-0) 

This is a **defense layer** that prevents the claimed vulnerability through normal protocol usage.

### 2. **No Realistic Exploit Path**
The claim states: "The attacker crafts a signing request that produces a message WITHOUT the `version` field"

**Critical flaw**: The attacker cannot control what the victim's wallet produces. When users sign messages through standard Obyte APIs, version is automatically included. The exploit would require:
- Victim using custom non-standard code to manually construct signed messages, OR
- Social engineering to trick victim into using attacker's custom signing library

Both scenarios fall outside the threat model per the framework: "Relies on social engineering, phishing, key theft, or user operational security failures" ❌

### 3. **Optional Version is Intentional Design**
Evidence of backward compatibility design decision: [2](#0-1) 

The commented-out strict version check indicates developers explicitly chose to allow optional version for backward compatibility, not a security oversight.

### 4. **Validation Exists But Doesn't Prove Vulnerability**
While validation conditionally checks version: [3](#0-2) 

This permissiveness alone doesn't constitute a vulnerability when the standard API provides protection.

### 5. **Regular Units DO Have Network Binding**
Regular units enforce network-specific `alt` field: [4](#0-3) [5](#0-4) 

Signed messages intentionally use a different model (version-based) for compatibility.

### 6. **Test Evidence Shows Standard Practice**
The test suite demonstrates proper usage with version included: [6](#0-5) 

## Framework Violations:

Per the validation framework, this claim fails:
- **Section E**: "Depends on calling internal functions not exposed through any public API" - Creating messages without version requires bypassing standard API
- **Section B**: "Relies on social engineering... or user operational security failures" - Requires victim to use non-standard code
- **Phase 5**: "A report ignoring these protections is likely invalid" - Ignores that standard API includes version

## Notes:

The protocol's permissiveness of version-optional messages appears to be a **backward compatibility feature**, not a security vulnerability. The actual security boundary is the standard API, which consistently includes version. Claims requiring users to deviate from standard protocol APIs do not constitute valid protocol vulnerabilities.

### Citations

**File:** signed_message.js (L36-40)
```javascript
	var objUnit = {
		version: constants.version,
		signed_message: message,
		authors: [objAuthor]
	};
```

**File:** signed_message.js (L128-129)
```javascript
	if ("version" in objSignedMessage && constants.supported_versions.indexOf(objSignedMessage.version) === -1)
		return handleResult("unsupported version: " + objSignedMessage.version);
```

**File:** wallet.js (L513-514)
```javascript
					//	if (objSignedMessage.version !== constants.version)
					//		return callbacks.ifError("wrong version in signed message: " + objSignedMessage.version);
```

**File:** validation.js (L150-151)
```javascript
	if (objUnit.alt !== constants.alt)
		return callbacks.ifUnitError("wrong alt");
```

**File:** constants.js (L24-25)
```javascript
exports.version = exports.bTestnet ? '4.0t' : '4.0';
exports.alt = exports.bTestnet ? '2' : '1';
```

**File:** test/formula.test.js (L1724-1732)
```javascript
			signed_package: {
				signed_message: {
					order: 11,
					pair: "GB/USD",
					amount: 1.23,
					price: 42.3
				},
				version: '2.0',
				last_ball_unit: 'oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=',
```
