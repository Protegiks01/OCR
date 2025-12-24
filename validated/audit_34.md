# Audit Report

## Title
TEXT Column Size Constraint Violation in AA Definition Storage Causes Node Crashes and Permanent Fund Freeze

## Summary
The `aa_addresses` table stores AA definitions in a MySQL TEXT column (65,535 byte limit), but validation only checks individual strings (4,096 bytes) and total unit size (5MB), not the JSON-stringified definition size. When an attacker submits an AA definition exceeding 65,535 bytes after JSON stringification, MySQL STRICT mode nodes crash immediately, while non-STRICT nodes silently truncate the data, making the AA permanently inaccessible and freezing all funds sent to it.

## Impact

**Severity**: Critical

**Category**: Network Shutdown (STRICT mode) / Permanent Fund Freeze (non-STRICT mode)

**Concrete Impact**:
- **STRICT mode nodes** (MySQL 5.7+ default, MyRocks): Node crashes when processing the unit, causing network-wide disruption potentially exceeding 24 hours if multiple nodes crash simultaneously [1](#0-0) 
- **Non-STRICT mode nodes**: AA definition silently truncated to 65,535 bytes, creating invalid JSON that causes parsing failures on retrieval, permanently freezing all funds sent to the AA address [2](#0-1) 
- **Mixed deployments**: State divergence between STRICT and non-STRICT nodes causing consensus failures

**Affected Parties**: All network nodes processing the malicious unit; all users sending payments to the compromised AA address

**Quantifiable Loss**: Unlimited - all bytes and custom assets sent to affected AA addresses become permanently unrecoverable without a hard fork

## Finding Description

**Location**: `byteball/ocore/storage.js:899-908`, function `insertAADefinitions()`

**Intended Logic**: AA definitions should be validated to ensure they fit within database storage constraints before insertion. Any definition passing validation should be storable and retrievable without data loss.

**Actual Logic**: The validation layer checks individual string lengths against `MAX_AA_STRING_LENGTH` (4,096 bytes) [3](#0-2)  and overall unit size against `MAX_UNIT_LENGTH` (5MB) [4](#0-3) , but does NOT validate the JSON-stringified size of the complete AA definition against the database TEXT column limit of 65,535 bytes.

**Exploitation Path**:

1. **Preconditions**: Attacker has sufficient bytes to pay unit fees (~10,000 bytes)

2. **Step 1**: Attacker constructs an AA definition with 20 messages, each containing formulas of 3,500 bytes (under the 4,096 byte `MAX_AA_STRING_LENGTH` limit [5](#0-4) )
   - Unit passes `validation.js` checks: 20 messages ≤ 128 maximum [6](#0-5) , total unit size under 5MB limit [7](#0-6) 
   - AA validation passes: each individual string ≤ 4,096 bytes

3. **Step 2**: During storage, `insertAADefinitions()` executes JSON stringification without size validation [8](#0-7) 
   - The 20 formulas totaling ~70,000 bytes plus JSON overhead exceeds 65,535 byte TEXT column limit [9](#0-8) 

4. **Step 3**: Database behavior diverges by SQL mode
   - **STRICT mode**: INSERT fails with "Data too long for column" error, triggering unhandled exception that crashes the node
   - **Non-STRICT mode**: INSERT succeeds but silently truncates definition to 65,535 bytes, corrupting the JSON

5. **Step 4**: Later retrieval attempts fail
   - Truncated JSON causes `JSON.parse()` to throw SyntaxError, making AA completely inaccessible
   - All funds sent to this AA address become permanently frozen with no recovery mechanism

**Security Properties Broken**:
- **Database Referential Integrity**: Complete AA definition cannot be stored despite passing validation
- **Balance Conservation**: Funds sent to inaccessible AA are effectively destroyed
- **Node Availability**: STRICT mode nodes crash, causing network disruption

**Root Cause**: Missing validation check for `JSON.stringify(definition).length <= 65535` before database insertion at the storage layer.

## Impact Explanation

**Affected Assets**: Bytes (native currency), all custom divisible and indivisible assets

**Damage Severity**:
- **Quantitative**: 100% of funds sent to affected AA addresses become permanently unrecoverable. Attacker can create unlimited such AA addresses at minimal cost.
- **Qualitative**: Complete loss of AA functionality with no workaround short of a network hard fork to change database schema and re-register the AA.

**User Impact**:
- **Who**: Any user sending payments to the compromised AA address post-registration
- **Conditions**: AA appears valid in the DAG but is actually broken; users cannot detect the issue before sending funds
- **Recovery**: None without a network-wide hard fork

**Systemic Risk**:
- Network fragmentation between STRICT and non-STRICT mode nodes with divergent states
- Cascading node failures if malicious unit propagates widely before detection
- Detection difficulty as the issue only manifests during storage/retrieval, not during initial validation

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with ability to submit units (no special privileges required)
- **Resources**: Minimal (unit fees ~10,000 bytes)
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
Add validation check for JSON-stringified definition size before database insertion:

```javascript
// File: byteball/ocore/storage.js
// Function: insertAADefinitions()
// After line 899

var json = JSON.stringify(payload.definition);
if (json.length > 65535)
    return cb("AA definition too large: " + json.length + " bytes (maximum 65535)");
```

**Permanent Fix**:
Change database schema to use MEDIUMTEXT (16MB limit) or LONGTEXT (4GB limit) to accommodate definitions up to the `MAX_UNIT_LENGTH` constraint:

```sql
-- In sqlite_migrations.js
ALTER TABLE aa_addresses MODIFY COLUMN definition MEDIUMTEXT NOT NULL;
```

**Additional Measures**:
- Add validation in `aa_validation.js` to check total stringified size early in validation pipeline
- Add test case verifying oversized AA definitions are rejected
- Implement monitoring to detect and alert on near-limit AA definitions
- Document the 65,535 byte limit in AA developer documentation until schema migration completes

## Proof of Concept

```javascript
// Test: Large AA Definition Exceeds TEXT Column Limit
// File: test/aa_text_column_overflow.test.js

const test = require('ava');
const db = require('../db');
const storage = require('../storage');

test.serial('AA definition exceeding 65535 bytes causes storage failure', async t => {
    // Create AA definition with 20 messages, each with 3500-byte formula
    const largeFormula = 'a'.repeat(3500);
    const messages = [];
    for (let i = 0; i < 20; i++) {
        messages.push({
            app: 'payment',
            payload: {
                asset: 'base',
                outputs: [
                    { address: '{trigger.address}', amount: '{trigger.output[[asset=base]] - 1000}' }
                ],
                init: largeFormula  // 3500 bytes each
            }
        });
    }
    
    const aaDefinition = ['autonomous agent', {
        messages: messages,
        bounce_fees: { base: 10000 }
    }];
    
    // Calculate JSON stringified size
    const jsonString = JSON.stringify(aaDefinition);
    t.true(jsonString.length > 65535, 'JSON string should exceed TEXT limit');
    
    // Attempt to insert - this should fail in STRICT mode or truncate in non-STRICT
    const payload = {
        address: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        definition: aaDefinition
    };
    
    await new Promise((resolve, reject) => {
        db.takeConnectionFromPool(conn => {
            storage.insertAADefinitions(conn, [payload], 'test_unit', 1, false, err => {
                if (err) {
                    // STRICT mode: error thrown
                    t.true(err.message.includes('Data too long') || err.message.includes('too large'));
                    resolve();
                } else {
                    // Non-STRICT mode: check if data was truncated
                    conn.query('SELECT definition FROM aa_addresses WHERE address=?', 
                        [payload.address], 
                        (rows) => {
                            if (rows.length > 0) {
                                const stored = rows[0].definition;
                                t.true(stored.length <= 65535, 'Stored definition truncated');
                                t.not(stored, jsonString, 'Data was corrupted');
                                // Verify JSON.parse fails on truncated data
                                t.throws(() => JSON.parse(stored), 'Corrupted JSON should fail parsing');
                            }
                            resolve();
                        }
                    );
                }
            });
        });
    });
});
```

**Notes**:
- The vulnerability exists due to a mismatch between validation layer constraints (5MB unit size, 4,096 byte individual strings) and database layer constraints (65,535 byte TEXT column)
- MySQL TEXT column limit of 65,535 bytes is a well-documented MySQL data type constraint
- The attack is practical: an AA with 20 messages (well under the 128 message limit) each containing 3,500-byte formulas (under the 4,096 byte string limit) produces ~75,000-80,000 bytes after JSON stringification
- SQLite uses TEXT type with no size limit, so the vulnerability primarily affects MySQL and MyRocks deployments [10](#0-9)

### Citations

**File:** mysql_pool.js (L47-47)
```javascript
				throw err;
```

**File:** aa_addresses.js (L129-129)
```javascript
			var arrDefinition = JSON.parse(row.definition);
```

**File:** aa_validation.js (L801-801)
```javascript
			return (x.length <= constants.MAX_AA_STRING_LENGTH);
```

**File:** validation.js (L140-140)
```javascript
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis)
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

**File:** storage.js (L899-908)
```javascript
			var json = JSON.stringify(payload.definition);
			var base_aa = payload.definition[1].base_aa;
			var bAlreadyPostedByUnconfirmedAA = false;
			var readGetterProps = function (aa_address, func_name, cb) {
				if (conf.bLight)
					return cb({ complexity: 0, count_ops: 0, count_args: null });
				readAAGetterProps(conn, aa_address, func_name, cb);
			};
			aa_validation.determineGetterProps(payload.definition, readGetterProps, function (getters) {
				conn.query("INSERT " + db.getIgnore() + " INTO aa_addresses (address, definition, unit, mci, base_aa, getters) VALUES (?,?, ?,?, ?,?)", [address, json, unit, mci, base_aa, getters ? JSON.stringify(getters) : null], function (res) {
```

**File:** initial-db/byteball-mysql.sql (L799-799)
```sql
	definition TEXT NOT NULL,
```

**File:** initial-db/byteball-sqlite.sql (L818-818)
```sql
	definition TEXT NOT NULL,
```
