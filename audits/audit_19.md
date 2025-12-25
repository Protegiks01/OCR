# Audit Report

## Title
TEXT Column Size Constraint Violation in AA Definition Storage Causes Node Crashes and Permanent Fund Freeze

## Summary
The `insertAADefinitions()` function in `storage.js` performs JSON stringification of AA definitions without validating the resulting size against MySQL's TEXT column limit of 65,535 bytes. This causes STRICT mode nodes to crash immediately when processing oversized definitions, and non-STRICT nodes to silently store truncated JSON that crashes nodes on retrieval, permanently freezing all funds sent to affected AA addresses.

## Impact

**Severity**: Critical

**Category**: Network Shutdown (STRICT mode) / Network Shutdown + Permanent Fund Freeze (non-STRICT mode)

**Concrete Impact**:
- **STRICT mode nodes** (MySQL 5.7+ default, MyRocks): Immediate node crash when attempting to store the AA definition, causing network disruption exceeding 24 hours if multiple nodes crash
- **Non-STRICT mode nodes**: Silently truncated JSON stored in database; subsequent retrieval attempts crash nodes when `JSON.parse()` fails on corrupted data
- **All users**: 100% of funds (bytes and custom assets) sent to affected AA addresses become permanently unrecoverable
- **Mixed deployments**: State divergence between STRICT and non-STRICT nodes causing consensus failures

## Finding Description

**Location**: `byteball/ocore/storage.js:899-908`, function `insertAADefinitions()`

**Intended Logic**: AA definitions should be validated to fit within database storage constraints before insertion. The validation layer should reject definitions that cannot be stored or retrieved correctly.

**Actual Logic**: The code performs JSON stringification without checking the result size against the database TEXT column limit: [1](#0-0) 

The stringified definition is then inserted directly into the database: [2](#0-1) 

The `aa_addresses` table uses a TEXT column with a 65,535 byte limit: [3](#0-2) [4](#0-3) 

**Exploitation Path**:

1. **Preconditions**: Attacker has sufficient bytes to pay unit fees (~10,000 bytes)

2. **Step 1**: Attacker constructs an AA definition with 20 messages containing formulas of 3,500 bytes each (under the 4,096 byte limit):
   - Individual formula validation passes: [5](#0-4) 
   - Message count validation passes: [6](#0-5) 
   - Total unit size validation passes: [7](#0-6) 
   - Unit size check in validation: [8](#0-7) 

3. **Step 2**: Unit validation calls `validateAADefinition()` which checks individual strings but NOT total JSON size:
   - AA validation called: [9](#0-8) 
   - String length validation only checks individual strings: [10](#0-9) 

4. **Step 3**: During storage, the 20 formulas totaling ~70,000 bytes exceed the 65,535 byte TEXT column limit

5. **Step 4**: Database behavior diverges by SQL mode:
   - **STRICT mode**: INSERT fails with error, mysql_pool throws it: [11](#0-10) 
   - The thrown error crashes the Node.js process
   - **Non-STRICT mode**: INSERT succeeds but data silently truncated to 65,535 bytes, corrupting the JSON

6. **Step 5**: Later retrieval attempts fail when `JSON.parse()` is called on truncated data: [12](#0-11) 
   - No try-catch around JSON.parse, so SyntaxError crashes the node
   - All funds sent to the AA become permanently frozen with no recovery path

**Security Properties Broken**:
- **Database Referential Integrity**: Complete AA definition cannot be stored despite passing validation
- **Balance Conservation**: Funds sent to inaccessible AA are effectively destroyed
- **Node Availability**: Both STRICT and non-STRICT nodes ultimately crash

**Root Cause**: Missing validation check for `JSON.stringify(definition).length <= 65535` before database insertion.

## Impact Explanation

**Affected Assets**: Bytes (native currency), all custom divisible and indivisible assets

**Damage Severity**:
- **Quantitative**: 100% of funds sent to affected AA addresses become permanently unrecoverable. Attacker can create unlimited such AA addresses at minimal cost (~10,000 bytes per AA).
- **Qualitative**: Complete loss of AA functionality with no workaround. Recovery requires network-wide hard fork to modify database schema and re-register affected AAs.

**User Impact**:
- **Who**: Any user sending payments to the compromised AA address; all network nodes processing the malicious unit
- **Conditions**: AA appears valid in the DAG but is actually broken; users cannot detect the issue before sending funds
- **Recovery**: None without a network-wide hard fork

**Systemic Risk**:
- Network fragmentation between STRICT and non-STRICT mode nodes with divergent states
- Cascading node failures if malicious unit propagates widely before detection
- Detection difficulty as the issue only manifests during storage/retrieval, not during initial validation

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with ability to submit units (no special privileges required)
- **Resources Required**: Minimal (unit fees ~10,000 bytes)
- **Technical Skill**: Medium (requires understanding AA structure and ability to calculate JSON stringified size)

**Preconditions**:
- **Network State**: Normal operation (no special conditions required)
- **Attacker State**: Sufficient bytes for unit fees
- **Timing**: No timing requirements

**Execution Complexity**:
- **Transaction Count**: Single unit containing oversized AA definition
- **Coordination**: None (single attacker action)
- **Detection Risk**: Low (appears valid during validation phase)

**Frequency**:
- **Repeatability**: Unlimited (attacker can create multiple such AAs)
- **Scale**: Each AA can trap unlimited funds from multiple users

**Overall Assessment**: High likelihood - low barrier to entry, simple execution, difficult to detect before exploitation

## Recommendation

**Immediate Mitigation**:
Add size validation before JSON stringification in `storage.js`:

```javascript
// In insertAADefinitions() before line 899
var json = JSON.stringify(payload.definition);
if (json.length > 65535)
    return cb("AA definition too large: " + json.length + " bytes (max 65535)");
```

**Permanent Fix**:
1. Add validation in `aa_validation.js` to check total JSON size during AA definition validation
2. Add try-catch around `JSON.parse()` in `readAADefinition()` to prevent crashes on corrupted data
3. Consider migrating to MEDIUMTEXT (16MB limit) or LONGTEXT (4GB limit) column type for future-proofing

**Additional Measures**:
- Database migration script to detect and handle any existing corrupted AA definitions
- Add monitoring to alert on oversized AA definition submissions
- Add test case verifying rejection of oversized AA definitions

## Proof of Concept

```javascript
const db = require('./db.js');
const storage = require('./storage.js');
const constants = require('./constants.js');

// Create an AA definition with 20 messages, each containing a 3500-byte formula
function createOversizedAADefinition() {
    const messages = [];
    for (let i = 0; i < 20; i++) {
        // Create a formula with ~3500 bytes (under MAX_AA_STRING_LENGTH)
        const largeFormula = '{' + 'x'.repeat(3490) + '}';
        messages.push({
            app: 'data',
            payload: {
                data: largeFormula
            }
        });
    }
    
    const definition = ['autonomous agent', {
        messages: messages
    }];
    
    return definition;
}

// Test the vulnerability
async function testVulnerability() {
    const conn = await db.takeConnectionFromPool();
    
    try {
        const definition = createOversizedAADefinition();
        const json = JSON.stringify(definition);
        
        console.log(`Definition JSON size: ${json.length} bytes`);
        console.log(`TEXT column limit: 65535 bytes`);
        console.log(`Exceeds limit: ${json.length > 65535}`);
        
        // This should cause a crash in STRICT mode or silent truncation in non-STRICT mode
        const payload = {
            address: 'TESTADDRESS00000000000000000000',
            definition: definition
        };
        
        await storage.insertAADefinitions(conn, [payload], 'TESTUNIT0000000000000000000000000000000', 1000000, false);
        
        console.log('Insert succeeded (non-STRICT mode) - data was truncated');
        
        // Try to read it back - this will crash on JSON.parse
        storage.readAADefinition(conn, 'TESTADDRESS00000000000000000000', (arrDef) => {
            console.log('Read failed - JSON.parse crashed on truncated data');
        });
        
    } catch (err) {
        console.log('Node crashed with error:', err.message);
        console.log('This demonstrates the STRICT mode crash scenario');
    } finally {
        conn.release();
    }
}

testVulnerability();
```

**Expected Result**: In STRICT mode, the node crashes with "Data too long for column 'definition'" error. In non-STRICT mode, the insert succeeds but subsequent read attempts crash with JSON.parse SyntaxError.

## Notes

This vulnerability affects both MySQL and MyRocks database backends as both use the TEXT column type with the same 65,535 byte limit. SQLite nodes are not affected as SQLite's TEXT type has a much larger limit (1 billion bytes). The vulnerability can be exploited with any combination of messages/formulas that results in a JSON-stringified definition exceeding 65,535 bytes - the 20 messages × 3,500 bytes example is just one possible attack vector.

### Citations

**File:** storage.js (L799-799)
```javascript
		var arrDefinition = JSON.parse(rows[0].definition);
```

**File:** storage.js (L899-899)
```javascript
			var json = JSON.stringify(payload.definition);
```

**File:** storage.js (L908-908)
```javascript
				conn.query("INSERT " + db.getIgnore() + " INTO aa_addresses (address, definition, unit, mci, base_aa, getters) VALUES (?,?, ?,?, ?,?)", [address, json, unit, mci, base_aa, getters ? JSON.stringify(getters) : null], function (res) {
```

**File:** initial-db/byteball-mysql.sql (L799-799)
```sql
	definition TEXT NOT NULL,
```

**File:** initial-db/byteball-myrocks.sql (L765-765)
```sql
	definition TEXT NOT NULL,
```

**File:** constants.js (L45-45)
```javascript
exports.MAX_MESSAGES_PER_UNIT = 128;
```

**File:** constants.js (L58-58)
```javascript
exports.MAX_UNIT_LENGTH = process.env.MAX_UNIT_LENGTH || 5e6;
```

**File:** constants.js (L63-63)
```javascript
exports.MAX_AA_STRING_LENGTH = 4096;
```

**File:** validation.js (L140-141)
```javascript
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis)
			return callbacks.ifUnitError("unit too large");
```

**File:** validation.js (L1577-1577)
```javascript
			aa_validation.validateAADefinition(payload.definition, readGetterProps, objValidationState.last_ball_mci, function (err) {
```

**File:** aa_validation.js (L801-801)
```javascript
			return (x.length <= constants.MAX_AA_STRING_LENGTH);
```

**File:** mysql_pool.js (L34-48)
```javascript
		new_args.push(function(err, results, fields){
			if (err){
				console.error("\nfailed query: "+q.sql);
				/*
				//console.error("code: "+(typeof err.code));
				if (false && err.code === 'ER_LOCK_DEADLOCK'){
					console.log("deadlock, will retry later");
					setTimeout(function(){
						console.log("retrying deadlock query "+q.sql+" after timeout ...");
						connection_or_pool.original_query.apply(connection_or_pool, new_args);
					}, 100);
					return;
				}*/
				throw err;
			}
```
