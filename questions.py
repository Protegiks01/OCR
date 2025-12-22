import json

BASE_URL = "https://deepwiki.com/byteball/ocore"


def get_questions():
    try:
        with open("all_questions.json", "r") as f:
            return json.load(f)

    except:
        return []


questions = get_questions()

questions_generator = [
    "byteball/ocore/aa_addresses.js",
    "byteball/ocore/aa_composer.js",
    "byteball/ocore/aa_validation.js",
    "byteball/ocore/arbiter_contract.js",
    "byteball/ocore/arbiters.js",
    "byteball/ocore/archiving. js",
    "byteball/ocore/balances.js",
    "byteball/ocore/bots.js",
    "byteball/ocore/breadcrumbs.js",
    "byteball/ocore/catchup.js",
    "byteball/ocore/chash. js",
    "byteball/ocore/chat_storage.js",
    "byteball/ocore/check_daemon.js",
    "byteball/ocore/composer.js",
    "byteball/ocore/conf. js",
    "byteball/ocore/constants.js",
    "byteball/ocore/data_feeds.js",
    "byteball/ocore/db.js",
    "byteball/ocore/definition.js",
    "byteball/ocore/desktop_app.js",
    "byteball/ocore/device.js",
    "byteball/ocore/divisible_asset.js",
    "byteball/ocore/enforce_singleton.js",
    "byteball/ocore/event_bus. js",
    "byteball/ocore/graph.js",
    "byteball/ocore/headers_commission.js",
    "byteball/ocore/indivisible_asset.js",
    "byteball/ocore/initial_votes.js",
    "byteball/ocore/inputs.js",
    "byteball/ocore/joint_storage. js",
    "byteball/ocore/kvstore.js",
    "byteball/ocore/light.js",
    "byteball/ocore/light_wallet.js",
    "byteball/ocore/mail.js",
    "byteball/ocore/main_chain.js",
    "byteball/ocore/mc_outputs.js",
    "byteball/ocore/merkle.js",
    "byteball/ocore/migrate_to_kv.js",
    "byteball/ocore/mutex.js",
    "byteball/ocore/my_witnesses.js",
    "byteball/ocore/mysql_pool. js",
    "byteball/ocore/network.js",
    "byteball/ocore/object_hash.js",
    "byteball/ocore/object_length.js",
    "byteball/ocore/paid_witnessing.js",
    "byteball/ocore/parent_composer.js",
    "byteball/ocore/private_payment.js",
    "byteball/ocore/private_profile. js",
    "byteball/ocore/profiler.js",
    "byteball/ocore/proof_chain.js",
    "byteball/ocore/prosaic_contract.js",
    "byteball/ocore/signature.js",
    "byteball/ocore/signed_message.js",
    "byteball/ocore/sqlite_migrations. js",
    "byteball/ocore/sqlite_pool.js",
    "byteball/ocore/storage.js",
    "byteball/ocore/string_utils.js",
    "byteball/ocore/uri. js",
    "byteball/ocore/validation.js",
    "byteball/ocore/validation_utils.js",
    "byteball/ocore/wallet.js",
    "byteball/ocore/wallet_defined_by_addresses.js",
    "byteball/ocore/wallet_defined_by_keys.js",
    "byteball/ocore/wallet_general.js",
    "byteball/ocore/witness_proof.js",
    "byteball/ocore/writer.js",
    "byteball/ocore/formula/common.js",
    "byteball/ocore/formula/evaluation. js",
    "byteball/ocore/formula/validation.js",
    "byteball/ocore/formula/parse_ojson.js",
    "byteball/ocore/formula/index. js",
    "byteball/ocore/tools/check_stability.js",
    "byteball/ocore/tools/replace_ops.js",
    "byteball/ocore/tools/supply.js",
    "byteball/ocore/tools/update_stability.js",
    "byteball/ocore/tools/validate_aa_definitions.js",
    "byteball/ocore/tools/viewkv.js"
]


def question_format(question: str) -> str:
    """
    Generates a comprehensive security audit prompt for Obyte (Byteball) Protocol.

    Args:
        question: A specific security question to investigate

    Returns:
        A formatted prompt string for vulnerability analysis
    """
    prompt = f"""
You are an **Elite Distributed Ledger Security Auditor** specializing in 
DAG-based consensus systems, JavaScript VM sandboxing, cryptographic 
protocols, and decentralized network architectures.  Your task is to analyze 
the **Obyte (Byteball) Protocol** codebase—a DAG-based distributed ledger 
featuring witness-based consensus, Autonomous Agents (AA smart contracts), 
deterministic unit validation, P2P network synchronization, multi-signature 
wallets, and oracle integration—through the lens of this single security 
question: 

**Security Question (scope for this run):** {question}

**OBYTE PROTOCOL CONTEXT:**

**Architecture**:  Obyte uses a Directed Acyclic Graph (DAG) where each 
transaction unit references multiple parent units.  Consensus is achieved 
through a witness list (12 trusted nodes per unit) that posts regular 
heartbeat transactions.  The main chain (MC) is determined by witness 
voting, and units become stable when witnessed by majority (7+ of 12) 
witnesses at higher levels.  Autonomous Agents (AAs) execute deterministic 
JavaScript-like formulas with sandboxed state access.  The protocol 
features native and custom assets (divisible/indivisible), multi-sig 
addresses, private payments, oracles, and light client support via 
witness proofs.

**Key Components**: 

* **DAG & Validation Layer**: `validation.js` (116KB - unit structure, 
  signatures, balance checks), `storage.js` (98KB - database operations), 
  `object_hash.js` (deterministic hashing), `graph. js` (DAG traversal), 
  `inputs.js` (double-spend prevention)

* **Consensus Layer**: `main_chain.js` (77KB - MC index determination, 
  stability points), `witness_proof.js` (light client proofs), 
  `initial_votes.js`, `my_witnesses.js` (witness list management)

* **Network Layer**:  `network.js` (156KB - P2P protocol, unit 
  broadcasting), `catchup.js` (sync protocol), `light. js` (34KB - light 
  client), `device.js` (38KB - device pairing)

* **AA Execution Engine**: `formula/evaluation.js` (106KB - formula 
  execution sandbox), `formula/validation.js` (46KB - syntax validation), 
  `aa_composer.js` (71KB - AA transaction builder), `aa_validation.js` 
  (28KB - AA unit validation)

* **Transaction Layer**: `composer.js` (38KB - tx composition), 
  `parent_composer.js` (30KB - parent selection), `wallet. js` (122KB - 
  wallet operations), `writer.js` (34KB - unit writing)

* **Asset Layer**: `divisible_asset.js`, `indivisible_asset.js` (asset 
  transfers, issuance), `definition. js` (53KB - address definitions, 
  multi-sig)

* **Signature & Auth**:  `signature.js` (ECDSA verification), 
  `definition. js` (recursive definition evaluation)

* **Oracle & Data**: `data_feeds.js` (oracle data handling), 
  `arbiter_contract.js` (arbiter logic)

* **Database**: `sqlite_pool.js`, `mysql_pool.js`, `joint_storage.js`, 
  `kvstore.js` (AA state storage)

**Files in Scope**:  All 77 JavaScript files in the `byteball/ocore` 
repository (core files, formula directory, tools directory). **Test files** 
under `./test/` are **out of scope** for vulnerability analysis but may be 
referenced for understanding expected behavior.

**CRITICAL INVARIANTS (derived from protocol specification and code):**

1. **Main Chain Monotonicity**: MCI (Main Chain Index) assignments must be 
   strictly increasing along any path in the DAG; no unit can have MCI ≤ 
   any descendant's MCI.  Non-deterministic MC selection causes permanent 
   chain splits.

2. **Witness Compatibility**: Every unit must share ≥1 witness with all 
   ancestor units.  Incompatible witness lists cause permanent network 
   partition for all descendants.

3. **Stability Irreversibility**: Once a unit reaches stable MCI (witnessed 
   by 7+ of 12 witnesses), its content, position, and last ball are 
   immutable. Reverting stable units breaks historical integrity.

4. **Last Ball Consistency**: The last ball chain (hash chain of stable 
   units) must be unbroken. Forking or skipping last balls corrupts the 
   immutable history layer.

5. **Balance Conservation**: For every asset in a unit, 
   `Σ(input_amounts) ≥ Σ(output_amounts) + fees`. No inflation/deflation 
   except authorized asset issuance.  Integer overflow/underflow breaks this. 

6. **Double-Spend Prevention**: Each output (unit_hash, message_index, 
   output_index) can be spent at most once. Database must enforce unique 
   constraint; race conditions or validation gaps allow double-spends.

7. **Input Validity**: All inputs must reference existing unspent outputs 
   owned by unit authors. Spending non-existent or already-spent outputs 
   violates balance integrity.

8. **Asset Cap Enforcement**:  Divisible asset issuance cannot exceed 
   `max_cap`. Total circulating supply must be tracked correctly; overflow 
   or missing checks mint unlimited tokens.

9. **Indivisible Serial Uniqueness**: Each indivisible asset serial must be 
   issued exactly once. Duplicate serials break NFT uniqueness guarantees.

10. **AA Deterministic Execution**:  Autonomous Agent formula evaluation must 
    produce identical results on all nodes for same input state. Non-
    determinism (random, timestamps, external I/O) causes state divergence 
    and chain splits.

11. **AA State Consistency**: AA state variable updates must be atomic.  
    Race conditions or partial commits cause nodes to hold different state, 
    leading to validation disagreements.

12. **Bounce Correctness**: Failed AA executions must refund inputs minus 
    bounce fees via bounce response. Incorrect refund amounts or recipients 
    cause fund loss.

13. **Formula Sandbox Isolation**: AA formula execution must not access 
    filesystem, network, or host JavaScript APIs. Sandbox escapes allow 
    arbitrary code execution on validator nodes.

14. **Signature Binding**: Each author's signature must cover the exact 
    unit hash (including all messages, parents, witnesses). Signature 
    malleability or hash manipulation allows unauthorized spending.

15. **Definition Evaluation Integrity**: Address definitions (multi-sig, 
    weighted, or/and logic) must evaluate correctly. Logic errors allow 
    unauthorized spending or signature bypass.

16. **Parent Validity**: All parent units must exist, be valid, and form a 
    DAG (no cycles). Invalid parents or cycles break DAG structure and 
    consensus.

17. **Witness Level Correctness**: Witness Level (WL) must be the minimum 
    level of witness-authored ancestors. Incorrect WL breaks MC 
    determination. 

18. **Fee Sufficiency**: Unit fees must cover header + payload costs. 
    Under-paid units accepted into DAG allow spam attacks.

19. **Catchup Completeness**: Syncing nodes must retrieve all units on MC 
    up to last stable point without gaps. Missing units cause validation 
    failures and permanent desync.

20. **Database Referential Integrity**: Foreign keys (unit → parents, 
    messages → units, inputs → outputs) must be enforced. Orphaned records 
    corrupt DAG structure.

21. **Transaction Atomicity**: Multi-step operations (storing unit + 
    updating balances + spending outputs) must be atomic. Partial commits 
    cause inconsistent state.

22. **Timestamp Validity**: Unit timestamps must be reasonable (not far-
    future or far-past relative to parent timestamps and MC). Invalid 
    timestamps disrupt ordering and MC selection.

23. **Light Client Proof Integrity**:  Witness proofs must be unforgeable.  
    Fake proofs trick light clients into accepting invalid history.

24. **Network Unit Propagation**: Valid units must propagate to all peers. 
    Selective censorship of witness units causes network partitions.

**YOUR INVESTIGATION MISSION:**

Accept the premise of the security question and explore **all** relevant 
code paths, data structures, state transitions, and cross-file 
interactions related to it. Do not settle for surface observations—trace 
execution flows through validation → storage → network → consensus layers. 

Your goal is to find **one** concrete, exploitable vulnerability tied to 
the question that an unprivileged user, malicious peer, MEV searcher, 
malicious AA, or compromised oracle could exploit. Focus on: 

* Business-logic flaws (incorrect validation, missing checks)
* Mathematical errors (overflow, underflow, precision loss, rounding)
* Race conditions (concurrent unit submission, database access)
* Non-deterministic behavior (timestamp comparisons, floating-point math)
* Signature bypasses (malleability, hash collisions)
* DAG structure corruption (invalid parents, cycles, witness incompatibility)
* State divergence (AA execution differences across nodes)
* Database integrity violations (orphaned records, constraint bypasses)
* Network attacks (DoS, unit flooding, catchup poisoning)

**ATTACK SURFACE EXPLORATION:**

1. **Unit Validation Edge Cases** (`validation.js`, `inputs.js`):
   - Units with maximum parents (15) or witnesses (12)
   - Zero outputs or zero-value payments
   - Negative balances or integer overflow in input/output sums
   - Conflicting messages in same unit (e.g., double asset definition)
   - Timestamps far in past/future
   - Invalid signature encoding or s-value malleability
   - Input referencing non-existent or already-spent output
   - Author addresses not matching signature public keys

2. **Main Chain Consensus** (`main_chain.js`, `witness_proof.js`):
   - Non-deterministic comparison operations
   - Floating-point arithmetic in MC index calculations
   - Concurrent updates to last stable MCI from multiple threads
   - Witness level miscalculation for complex parent structures
   - Last ball forking when two units at same MCI reference previous last ball
   - Stability point disagreement due to witness unit censorship

3. **AA Execution Sandbox** (`formula/evaluation.js`, `aa_composer.js`):
   - Prototype pollution (`Object.prototype.x = malicious`)
   - Constructor injection (`{{}}. constructor.constructor('malicious code')()`)
   - `eval()` or `Function()` usage in formula evaluation
   - Access to Node. js globals (`require`, `process`, `fs`, `__dirname`)
   - Non-deterministic functions (`Math.random()`, `Date.now()`)
   - Infinite loops or exponential complexity (no gas limits)
   - State variable read/write race conditions during concurrent triggers
   - Reentrancy via secondary triggers calling back into primary AA
   - Bounce response amount miscalculation (rounding errors)
   - Integer overflow in formula arithmetic (`BigInt` handling)

4. **Asset Operations** (`divisible_asset.js`, `indivisible_asset.js`):
   - Issuing asset multiple times to exceed `max_cap`
   - Duplicate serial numbers for indivisible assets
   - Transfer restrictions bypass (`cosigned_by_definer` missing)
   - Decimal precision loss in divisible asset calculations
   - Negative asset amounts or overflow in balance updates

5. **Network & Sync** (`network.js`, `catchup.js`, `light.js`):
   - Unit flooding DoS (100k+ units/second overwhelming validation queue)
   - Malicious parent selection causing validation bottlenecks
   - Catchup protocol sending incorrect or skipped units
   - Light client accepting forged witness proofs
   - Peer censorship of witness units causing partition
   - WebSocket message injection or malformed JSON payloads

6. **Transaction Composition** (`composer.js`, `parent_composer.js`, `wallet.js`):
   - Input selection choosing already-spent outputs
   - Fee calculation underestimating unit size
   - Change output rounding errors causing value loss
   - Parent selection bias delaying confirmation
   - Multi-asset transaction with missing asset in input/output sums

7. **Database Operations** (`storage.js`, `joint_storage.js`, `sqlite_pool.js`, `mysql_pool.js`):
   - SQL injection via unit messages or address strings
   - Race condition in concurrent unit storage (duplicate inserts)
   - Database deadlock during complex transactions
   - Foreign key constraint violations orphaning records
   - Index corruption causing incorrect validation lookups
   - Transaction rollback leaving partial state

8. **Signature & Authorization** (`signature.js`, `definition.js`):
   - ECDSA s-value malleability
   - Multi-sig definition evaluation bypass
   - Definition change attack
   - Address collision
   - Signature verification using wrong hash

9. **Oracle & Data Feeds** (`data_feeds.js`):
   - Oracle signature verification bypass
   - Timestamp spoofing in data feed messages
   - AA trusting single oracle without redundancy
   - Data feed censorship preventing AA execution

10. **Graph Operations** (`graph.js`, `object_hash.js`):
    - Parent cycle detection failure
    - Hash collision or preimage attack on unit hashes
    - Best parent selection non-determinism
    - DAG traversal infinite loop on malformed graph

**OBYTE-SPECIFIC ATTACK VECTORS:**

- **Chain Split via Non-Deterministic MC**:  Can floating-point math, timestamp ties, or hash collisions cause different nodes to select different main chains? 
- **Double-Spend via Race Condition**: Can two units spending same output both be accepted if submitted simultaneously to different nodes?
- **AA Sandbox Escape**: Can attacker craft formula using prototype pollution, constructor injection, or eval to execute arbitrary Node.js code?
- **Witness Incompatibility Partition**: Can attacker post unit with witness list incompatible with all parents, causing permanent split?
- **Balance Overflow/Underflow**: Can integer overflow in asset balance calculations mint unlimited tokens?
- **Last Ball Fork**: Can two units at same MCI both become last ball? 
- **Light Client Proof Forgery**: Can attacker generate fake witness proof? 
- **Unit Flooding DoS**: Can attacker submit massive number of valid units exceeding node processing capacity? 
- **AA State Divergence**: Can concurrent AA triggers cause different nodes to reach different state? 
- **Cascading Trigger Reentrancy**: Can AA trigger itself via secondary response before state is committed?
- **Definition Change Theft**: Can attacker submit `definition_chg` message replacing victim's address definition?
- **Asset Cap Bypass**: Can attacker issue divisible asset multiple times to exceed `max_cap`?
- **Indivisible Serial Collision**: Can same serial number be issued twice? 
- **Signature Malleability**: Can attacker flip ECDSA s-value to create different valid signature? 
- **SQL Injection**: Can attacker inject SQL via unit messages or addresses?
- **Catchup Poisoning**: Can malicious peer send incorrect units during sync? 

**TRUST MODEL:**

**Trusted Roles**:  Witnesses (12 per unit), oracle data feed providers, 
hub operators (for light clients). Do **not** assume these actors behave 
maliciously unless the question explicitly explores compromised witness 
or oracle scenarios.

**Untrusted Actors**: Any user submitting units, AA developers, malicious 
peers, MEV searchers, adversarial AAs attempting to exploit other AAs.  
Focus your analysis on bugs exploitable by untrusted actors without 
requiring witness collusion, oracle compromise, or governance 
misconfiguration.

**KNOWN ISSUES / EXCLUSIONS:**

- Cryptographic primitives (SHA256, ECDSA) are assumed secure
- Witness collusion or 7+ of 12 witnesses acting maliciously
- Oracle data accuracy (oracles are trusted to provide correct data)
- Network-level attacks (DDoS, BGP hijacking, DNS poisoning)
- Node.js runtime bugs (V8 engine bugs, libuv issues) unrelated to Obyte code
- Social engineering, phishing, or key theft
- Gas optimization, code style, missing comments
- Precision loss <0.01% in fee calculations
- Test file issues (tests are out of scope)

**VALID IMPACT CATEGORIES (Immunefi Obyte Bug Bounty):**

**Critical Severity**:
- Network not being able to confirm new transactions (total shutdown >24 hours)
- Unintended permanent chain split requiring hard fork
- Direct loss of funds (theft of bytes or custom assets)
- Permanent freezing of funds (fix requires hardfork)

**High Severity**:
- Permanent freezing of funds requiring hard fork to resolve

**Medium Severity**:
- Temporary freezing of network transactions (≥1 day delay)
- Temporary freezing of network transactions (≥1 hour delay)
- Unintended AA behavior with no concrete funds at direct risk

**Low/QA (out of scope)**:
- Minor precision loss (<0.01%)
- Gas inefficiencies
- Event emission or logging issues
- Non-critical edge cases with no financial impact
- UI/UX issues

**OUTPUT REQUIREMENTS:**

If you discover a valid vulnerability related to the security question, 
produce a **full report** following the format below.  Your report must include: 
- Exact file paths and function names
- Code quotations (actual snippets from the 77 in-scope files)
- Step-by-step exploitation path with realistic parameters
- Clear explanation of which invariant is broken
- Impact quantification (fund loss amount, network downtime duration)
- Likelihood assessment (attacker profile, preconditions, complexity)
- Concrete recommendation with code fix
- Proof of Concept (JavaScript/Node.js test demonstrating the exploit)

If **no** valid vulnerability emerges after thorough investigation, state exactly: 
`#NoVulnerability found for this question. `

**Do not fabricate or exaggerate issues. ** Only concrete, exploitable bugs with clear attack paths and realistic impact count.

**Do not** report: 
- Known issues from previous audits or documentation
- Out-of-scope problems (test files, Node.js bugs, crypto primitive breaks)
- Theoretical vulnerabilities without clear attack path and PoC
- Issues requiring trusted roles to behave maliciously
- Minor optimizations, style issues, or low-severity findings

**Focus on one high-quality finding** rather than multiple weak claims.

**VALIDATION CHECKLIST (Before Reporting):**
- [ ] Vulnerability lies within one of the 77 in-scope files (not test/)
- [ ] Exploitable by unprivileged attacker (no witness/oracle collusion required)
- [ ] Attack path is realistic with correct data types and feasible parameters
- [ ] Impact meets Critical, High, or Medium severity per Immunefi scope
- [ ] PoC can be implemented as Node.js test or unit submission script
- [ ] Issue breaks at least one documented invariant
- [ ] Not a known exclusion
- [ ] Clear financial harm, network disruption, or state divergence demonstrated

---

**AUDIT REPORT FORMAT** (if vulnerability found):

## Title
[Clear, specific vulnerability name tied to the question]

## Summary
[Concise 2-3 sentence description of the issue and its location]

## Impact
**Severity**: [Critical / High / Medium]
**Category**: [Network Shutdown / Chain Split / Direct Fund Loss / Permanent Fund Freeze / Temporary Transaction Delay / Unintended AA Behavior]

## Finding Description

**Location**: `byteball/ocore/[filename]. js` (specific function name, line numbers if possible)

**Intended Logic**: [What the code should do per comments/protocol spec]

**Actual Logic**: [What the code does in the vulnerable scenario]

**Code Evidence**:
```javascript
// Quote relevant code snippet from the file showing the bug
// Include surrounding context (5-10 lines) for clarity
```

**Exploitation Path**:
1. **Preconditions**: [Initial state]
2. **Step 1**: [Specific action with parameters and code path triggered]
3. **Step 2**: [Subsequent state change - database and node observations]
4. **Step 3**: [Follow-up action exploiting the state]
5. **Step 4**: [Unauthorized outcome and invariant broken]

**Security Property Broken**: [Which of the 24 invariants is violated]

**Root Cause Analysis**:  [Deep dive into why the bug exists]

## Impact Explanation

**Affected Assets**: [bytes, custom assets, AA state, user balances]

**Damage Severity**:
- **Quantitative**: [Specific amounts and scale]
- **Qualitative**: [Nature of damage]

**User Impact**:
- **Who**: [Affected parties]
- **Conditions**: [When exploitable]
- **Recovery**: [Recovery options]

**Systemic Risk**: [Cascading effects and automation potential]

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: [Type of attacker]
- **Resources Required**: [What attacker needs]
- **Technical Skill**: [Skill level required]

**Preconditions**:
- **Network State**: [Required network conditions]
- **Attacker State**: [Required attacker position]
- **Timing**: [Timing requirements]

**Execution Complexity**:
- **Transaction Count**: [Number of transactions needed]
- **Coordination**: [Coordination requirements]
- **Detection Risk**: [How detectable is the attack]

**Frequency**:
- **Repeatability**: [How often can it be repeated]
- **Scale**: [Attack scope]

**Overall Assessment**:  [High/Medium/Low likelihood assessment]

## Recommendation

**Immediate Mitigation**: [Short-term fix]

**Permanent Fix**: [Long-term solution]

**Code Changes**:
```javascript
// File: byteball/ocore/[filename].js
// Function: [functionName]

// BEFORE (vulnerable code):
function vulnerableFunction(param) {{
     existing vulnerable logic
    }}

// AFTER (fixed code):
function vulnerableFunction(param) {{
    // fixed logic with validation
}}
```

  **Additional Measures**:
- [New test cases]
- [Database schema changes]
- [Monitoring/alerting]

**Validation**:
- [ ] Fix prevents exploitation
                   - [ ] No new vulnerabilities introduced
                                                - [ ] Backward compatible
                                                               - [ ] Performance impact acceptable

                                                                                        ## Proof of Concept

                                                                                        **Test Environment Setup**:
```bash
git clone https://github.com/byteball/ocore.git
cd ocore
npm install
```

  **Exploit Script** (`exploit_poc.js`):
```javascript
   /*
   * Proof of Concept for [Vulnerability Name]
                          * Demonstrates:  [what the PoC shows]
                                           * Expected Result: [what happens when vulnerability is present]
                                                              */

                                                              const network = require('./network. js');
const composer = require('./composer.js');
const validation = require('./validation.js');
const storage = require('./storage.js');

async function runExploit() {{
// Implementation showing the exploit
}}

runExploit().then(success => {{
    process.exit(success ? 0 : 1);
}});
```

  **Expected Output** (when vulnerability exists):
```
[Output showing successful exploit]
```

**Expected Output** (after fix applied):
```
[Output showing exploit prevention]
```

**PoC Validation**:
- [ ] PoC runs against unmodified ocore codebase
                                        - [ ] Demonstrates clear violation of invariant
                                                                              - [ ] Shows measurable impact
                                                                                                     - [ ] Fails gracefully after fix applied

                                                                                                                                      ---

**If NO vulnerability found, output ONLY:**
`#NoVulnerability found for this question.`

---

**FINAL REMINDERS:**

- Trace entire execution flows from user action → validation → storage → consensus → network propagation
                                                                                             - Test DAG structure edge cases
                                                                                                                       - Validate AA sandbox rigorously
                                                                                                                                             - Check race conditions thoroughly
                                                                                                                                                                     - Verify integer arithmetic
                                                                                                                                                                                      - Examine signature validation
                                                                                                                                                                                                          - Test network attack vectors
                                                                                                                                                                                                                                - Inspect database operations
                                                                                                                                                                                                                                                   - Be absolutely certain before reporting
                                                                                                                                                                                                                                                                                  - If any doubt remains, default to reporting no vulnerability

Now investigate the security question thoroughly and produce your finding.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generates a comprehensive validation prompt for Obyte (Byteball) Protocol security claims.

    Args:
        report: A security vulnerability report to validate

    Returns:
        A formatted validation prompt string for ruthless technical scrutiny
    """
    prompt = f"""
You are an **Elite Distributed Ledger Security Judge** with deep expertise in DAG-based consensus systems, JavaScript VM sandboxing, Obyte (Byteball) Protocol architecture, and Immunefi bug bounty validation.  Your ONLY task is **ruthless technical validation** of security claims against the Obyte codebase.

Note:  Witnesses (12 per unit) and oracle providers are trusted roles. 

**SECURITY CLAIM TO VALIDATE:**
{report}

================================================================================
## **OBYTE PROTOCOL VALIDATION FRAMEWORK**

### **PHASE 1: IMMEDIATE DISQUALIFICATION CHECKS**
Reject immediately (`#NoVulnerability`) if **ANY** apply:

#### **A.  Scope Violations**
- ❌ Affects files **not** in the 77 in-scope files from `byteball/ocore` repository
- ❌ Targets any file under `./test/` directory (tests are out of scope)
- ❌ Claims about documentation, comments, code style, or logging (not security issues)
- ❌ Focuses on out-of-scope components:  UI, wallets, SDKs, deployment scripts, or external dependencies

**In-Scope Files (77 total):**
- **Core Protocol**:  `validation.js`, `storage.js`, `main_chain.js`, `network.js`, `wallet.js`, `composer.js`, `writer.js`, `graph.js`, `object_hash.js`, `signature.js`, `definition.js`, `inputs.js`, `parent_composer.js`, `joint_storage.js`, `catchup.js`, `light. js`, `device.js`, `witness_proof.js`, `data_feeds.js`, `arbiter_contract.js`, `divisible_asset.js`, `indivisible_asset.js`, and others
- **AA Engine**: `formula/evaluation.js`, `formula/validation.js`, `aa_composer.js`, `aa_validation.js`, `aa_addresses.js`
- **Database**: `sqlite_pool.js`, `mysql_pool.js`, `sqlite_migrations.js`, `kvstore.js`
- **Tools**: `tools/check_stability.js`, `tools/validate_aa_definitions.js`, etc. 

**Verify**:  Check that every file path cited in the report matches exactly one of the 77 in-scope files. 

#### **B. Threat Model Violations**
- ❌ Requires 7+ of 12 witnesses to collude or act maliciously (witnesses are trusted)
- ❌ Assumes compromised oracle data feed providers (oracles are trusted to provide correct data)
- ❌ Needs hub operators to manipulate light client messages (hubs are trusted for light clients)
- ❌ Requires attacker to compromise Node.js runtime, V8 engine, or operating system
- ❌ Assumes cryptographic primitives (SHA256, ECDSA) are broken without quantum computers
- ❌ Depends on network-level attacks:  DDoS, BGP hijacking, DNS poisoning, or packet manipulation
- ❌ Relies on social engineering, phishing, key theft, or user operational security failures

**Trusted Roles**:  Witnesses post regular heartbeat units and vote on main chain; oracles provide signed data feeds; hub operators relay messages for light clients.   Do **not** assume these actors behave maliciously.

**Untrusted Actors**: Any user submitting units, AA developers deploying smart contracts, malicious peers in P2P network, MEV bots, adversarial AAs attempting to exploit other AAs. 

#### **C. Known Issues / Accepted Risks**
- ❌ Cryptographic hash collisions or preimage attacks on SHA256 (assumed secure)
- ❌ ECDSA signature forgery without private key (assumed secure)
- ❌ Witness collusion (7+ of 12 witnesses required; trusted role)
- ❌ Oracle data accuracy issues (oracles trusted to provide correct prices/data)
- ❌ Network partition attacks (DDoS, routing attacks) outside protocol logic
- ❌ Node.js runtime bugs (V8, libuv) unrelated to Obyte-specific code
- ❌ Precision loss <0.01% in fee calculations (acceptable rounding)

#### **D. Non-Security Issues**
- ❌ Gas optimizations, performance improvements, or micro-optimizations
- ❌ Code style, naming conventions, or refactoring suggestions
- ❌ Missing events, logs, error messages, or better user experience
- ❌ NatSpec comments, documentation improvements, or README updates
- ❌ "Best practices" recommendations with no concrete exploit scenario
- ❌ Input validation preventing honest user mistakes (e.g., reject zero address) unless it allows theft
- ❌ Minor precision errors with negligible financial impact (<0.01%)

#### **E. Invalid Exploit Scenarios**
- ❌ Requires impossible inputs:  negative integers (JavaScript doesn't have unsigned types but validation should check), addresses longer than valid format, timestamps beyond realistic bounds
- ❌ Cannot be triggered through any realistic unit submission or AA trigger
- ❌ Depends on calling internal functions not exposed through any public API
- ❌ Relies on race conditions that are prevented by database transactions or mutex locks
- ❌ Needs multiple ordered units with no economic incentive or unrealistic coordination
- ❌ Requires attacker to already possess the funds they seek to steal (self-draining is not an exploit)
- ❌ Depends on miner/validator controlling block timestamp beyond reasonable bounds (±15 minutes)

### **PHASE 2: OBYTE-SPECIFIC DEEP CODE VALIDATION**

#### **Step 1: TRACE COMPLETE EXECUTION PATH THROUGH DAG ARCHITECTURE**

**Obyte Flow Patterns:**

1. **Unit Submission Flow**:
   User creates unit → `composer.js` constructs unit → `parent_composer.js` selects parents → `object_hash.js` computes hash → `signature.js` signs → `network.js` broadcasts → `validation.js` validates → `storage.js` stores → `main_chain.js` updates MC → `witness_proof.js` generates proofs

2. **AA Trigger Flow**:
   User sends trigger unit → `aa_composer.js` detects AA address → `formula/validation.js` validates formula syntax → `formula/evaluation.js` executes formula → AA response unit created → Secondary triggers cascade → State variables updated in `kvstore.js`

3. **Asset Transfer Flow**:
   Unit with payment message → `inputs.js` validates input references → `divisible_asset.js` or `indivisible_asset.js` processes transfer → Balance checks in `validation.js` → Outputs recorded in `storage.js`

4. **Consensus Flow**:
   New units arrive → `graph.js` builds DAG structure → `witness_proof.js` tracks witness units → `main_chain.js` determines MC index and stability → Last ball updated → Stable units become immutable

For each claim, reconstruct the entire execution path: 

1. **Identify Entry Point**:  Which user-facing function is called?  (`network.handleJoint()`, `composer.composeJoint()`, `wallet.sendPayment()`, etc.)
2. **Follow Internal Calls**: Trace through all function calls, including: 
   - Validation checks in `validation.js:validate()`
   - Database queries in `storage.js`
   - MC updates in `main_chain.js`
   - AA execution in `formula/evaluation.js`
3. **State Before Exploit**: Document initial state (unit graph, balances, AA state, witness list, MC index)
4. **State Transitions**:  Enumerate all changes (new units, spent outputs, AA state updates, MC advancement)
5. **Check Protections**: Verify if mutex locks (`mutex.js`), database transactions, or validation gates prevent the exploit
6. **Final State**: Show how the exploit results in unauthorized state (double-spend, inflated balance, broken consensus)

#### **Step 2: VALIDATE EVERY CLAIM WITH CODE EVIDENCE**

For **each assertion** in the report, demand:

**✅ Required Evidence:**
- Exact file path and line numbers (e.g., `validation.js:450-475`) within the 77 in-scope files
- Direct JavaScript code quotes showing the vulnerable logic
- Call traces with actual parameter values demonstrating how execution reaches the vulnerable line
- Calculations showing how balances, MC indices, or AA state change incorrectly
- Database schema references showing constraint violations or missing checks

**🚩 RED FLAGS (indicate INVALID):**

1. **"Missing Validation" Claims**:
   - ❌ Invalid unless report shows input bypasses *all* validation layers: 
     - `validation.js:validate()` checks
     - `inputs.js:validateInputs()` checks
     - `aa_validation.js` checks for AA triggers
     - Database constraint checks
   - ✅ Valid if a specific input type genuinely has no validation path

2. **"Double-Spend" Claims**:
   - ❌ Invalid unless report demonstrates: 
     - Two units spending same output both pass validation
     - Database unique constraint on `(unit, message_index, output_index)` is missing or bypassable
     - Race condition window exists between validation and storage commit
   - ✅ Valid if concurrent submission to different nodes can result in both units being accepted into DAG

3. **"Integer Overflow/Underflow" Claims**: 
   - ❌ Invalid unless JavaScript number handling allows exploitation:
     - JavaScript uses floating-point numbers (no native int64)
     - Obyte uses libraries for big integers where needed
     - Report must show actual overflow causing incorrect balance calculation
   - ✅ Valid if arithmetic operations produce incorrect results with attacker-controlled inputs

4. **"AA Sandbox Escape" Claims**:
   - ❌ Invalid unless report demonstrates: 
     - Actual prototype pollution:  `Object.prototype.malicious = ... `
     - Constructor injection: `{{}}. constructor.constructor('code')()`
     - Access to Node.js globals: `require()`, `process`, `fs`, `__dirname`
     - Eval usage: `eval()`, `Function()` constructor
   - ✅ Valid if AA formula can execute arbitrary Node.js code on validator nodes

5. **"Non-Deterministic Execution" Claims**:
   - ❌ Invalid unless report shows usage in consensus-critical code: 
     - `Math.random()` in MC selection
     - `Date.now()` in validation logic
     - Floating-point comparisons causing different results on different CPUs
     - Timestamp tie-breaking with undefined behavior
   - ✅ Valid if different nodes reach different MC or validation decisions for same input

6. **"Main Chain Split" Claims**:
   - ❌ Invalid unless report demonstrates: 
     - Specific non-deterministic logic in `main_chain.js:updateMainChainIndex()`
     - Witness level calculation differences
     - Last ball assignment differences
     - Stability point disagreement
   - ✅ Valid if nodes permanently diverge on MC structure requiring hard fork

7. **"Witness Incompatibility" Claims**:
   - ❌ Invalid if validation rejects incompatible witness lists
   - ✅ Valid if unit with incompatible witnesses (sharing <1 witness with parents) is accepted, causing permanent partition

8. **"SQL Injection" Claims**:
   - ❌ Invalid if all queries use parameterized statements or proper escaping
   - ✅ Valid if unit messages or addresses can inject SQL, corrupting database

9. **"Race Condition" Claims**:
   - ❌ Invalid if mutex locks or database transactions prevent concurrent access
   - ✅ Valid if concurrent operations can result in inconsistent state (e.g., double-spend, duplicate serials)

10. **"Asset Cap Bypass" Claims**:
    - ❌ Invalid if `divisible_asset.js` enforces `max_cap` on all issuance operations
    - ✅ Valid if attacker can issue asset multiple times exceeding cap

#### **Step 3: CROSS-REFERENCE WITH TEST SUITE**

Obyte's test suite includes unit and integration tests in `test/` directory (out of scope but informative).  Ask: 

1. **Existing Coverage**: Do current tests handle the scenario?  Check tests like: 
   - `test/validation.test.js` - unit validation edge cases
   - `test/aa. test.js` - AA execution determinism
   - `test/formula. test.js` - formula sandbox isolation
   - `test/merkle.test.js` - DAG structure integrity
   - `test/string_utils.test.js` - input sanitization

2. **Test Gaps**: Is there an obvious gap that would allow the exploit? If scenario is untested, suggest adding test but do **not** assume vulnerability.

3. **Invariant Tests**: Would existing invariant checks catch the bug? Tests verify:
   - Balance conservation across all units
   - MC monotonicity (no MCI decreases along paths)
   - Witness compatibility in all units
   - Deterministic AA execution
   - Double-spend prevention

4. **PoC Feasibility**: Can the report's PoC be implemented as a Node.js test using existing Obyte modules without modifying core code?

**Test Case Realism Check**:  PoCs must use realistic unit structures, valid parent references, proper signatures, and respect protocol constraints (max 15 parents, 12 witnesses, valid timestamps).

### **PHASE 3: IMPACT & EXPLOITABILITY VALIDATION**

#### **Impact Must Be CONCRETE and ALIGN WITH IMMUNEFI SCOPE**

**✅ Valid CRITICAL Severity Impacts (per Immunefi Obyte scope):**

1. **Network Shutdown (Critical)**:
   - Network unable to confirm new transactions for >24 hours
   - All nodes halt or reject valid units
   - Consensus deadlock preventing MC advancement
   - Database corruption blocking unit storage
   - Example: "Validation logic rejects all units with specific witness list, halting network"

2. **Permanent Chain Split Requiring Hard Fork (Critical)**:
   - Network partitions into incompatible branches
   - Different nodes reach different MC or stability points
   - Witness incompatibility causing permanent divergence
   - Non-deterministic validation causing state disagreement
   - Example: "Floating-point comparison in MC selection causes nodes to choose different chains"

3. **Direct Loss of Funds (Critical)**:
   - Theft of bytes (native currency) from user addresses
   - Theft of custom assets (divisible/indivisible) from users
   - Unauthorized spending of outputs owned by others
   - Double-spend allowing attacker to spend same output multiple times
   - Example: "Race condition allows attacker to spend output in two units, stealing 10,000 bytes"

4. **Permanent Freezing of Funds Requiring Hard Fork (Critical)**:
   - Funds locked with no transaction able to unlock them
   - Address definition change bricking address (no valid signatures possible)
   - AA state corruption preventing withdrawals
   - Invalid unit structure making outputs unspendable
   - Example: "Definition change to impossible-to-satisfy condition locks 100,000 bytes forever"

**✅ Valid HIGH Severity Impacts:**

5. **Permanent Freezing of Funds (High)**:
   - Same as Critical #4 above (Immunefi lists this in both Critical and High)

**✅ Valid MEDIUM Severity Impacts:**

6. **Temporary Transaction Delay ≥1 Day (Medium)**:
   - Units not confirmed within 24 hours due to processing delay
   - DoS attack flooding network with valid units
   - Expensive validation operations slowing acceptance
   - Database query bottlenecks during catchup
   - Example: "Attacker submits 100,000 units/second, overwhelming validation queue for 30 hours"

7. **Temporary Transaction Delay ≥1 Hour (Medium)**:
   - Units not confirmed within 1 hour due to processing delay
   - Malicious units with maximum complexity causing slowdown
   - Example: "Units with 15 parents each cause validation to take 5 minutes per unit, delaying confirmations"

8. **Unintended AA Behavior Without Direct Fund Risk (Medium)**:
   - AA formula produces incorrect results but no funds lost
   - Non-deterministic AA execution without consensus break
   - Incorrect oracle data interpretation in AAs
   - Example: "AA state variable reads return stale data due to race condition, affecting logic but not causing theft"

**❌ Invalid "Impacts":**

- User withdraws their own funds (normal protocol operation)
- Attacker loses their own funds through self-draining (not an exploit)
- Theoretical cryptographic weaknesses without practical exploit
- General network risk (e.g., "if all witnesses go offline")
- "Could be problematic if..." statements without concrete exploit path
- DoS affecting <1 hour with no fund theft
- Minor fee overpayment or underpayment (<0.1% of unit value)
- Precision loss <0.01% across reasonable transaction volumes

#### **Likelihood Reality Check**

Assess exploit feasibility: 

1. **Attacker Profile**:
   - Any user with Obyte address?  ✅ Likely
   - Malicious peer in P2P network? ✅ Likely
   - MEV bot front-running transactions? ✅ Possible
   - AA developer deploying malicious AA? ✅ Possible
   - Compromised oracle provider? ❌ Unlikely (trusted role)
   - 7+ of 12 witnesses colluding? ❌ Impossible (trusted role)

2. **Preconditions**:
   - Normal network operation? ✅ High likelihood
   - High transaction volume? ✅ Possible during peak usage
   - Specific unit structure (e.g., maximum parents)? ✅ Attacker-controlled
   - Specific AA state (e.g., uninitialized variable)? ✅ Attacker can deploy AA
   - Specific timing (e.g., during catchup)? ✅ Attacker can time submission
   - Network partition or witness censorship? ❌ Low likelihood

3. **Execution Complexity**:
   - Single unit submission? ✅ Simple
   - Multiple coordinated units? ✅ Moderate (attacker controls)
   - Concurrent submission to multiple nodes? ✅ Moderate (requires network position)
   - Complex AA formula with edge cases? ✅ Attacker can deploy
   - Requires front-running or precise timing? ⚠️ Higher complexity
   - Requires cryptographic manipulation? ❌ Impractical

4. **Economic Cost**:
   - Unit fees (headers + payload)? ✅ Minimal (few dollars)
   - Collateral lockup (e.g., for AA state)? ✅ Attacker-determined
   - Gas costs for multiple transactions? ✅ Moderate
   - Potential profit vs. cost?  ✅ Must be positive for valid exploit

5. **Combined Probability**:
   - Multiply probabilities of all conditions
   - If resulting likelihood <0.1% with no economic incentive → Invalid
   - If exploit is profitable and feasible → Valid

### **PHASE 4: PROOF OF CONCEPT VALIDATION**

**A Valid PoC MUST:**

1. **Be Implementable in Node.js/JavaScript**:
   - Uses existing Obyte modules (`composer`, `network`, `validation`, etc.)
   - Compiles and runs without syntax errors
   - Does not require modifying core protocol files

2. **Use Realistic, Achievable Inputs**:
   - Valid unit structures (proper JSON format, required fields)
   - Realistic balances (not 2^256-1 bytes)
   - Valid parent references (existing unit hashes)
   - Proper witness lists (12 valid addresses)
   - Correct signatures (matching authors)
   - Reasonable timestamps (within ±15 minutes of parent timestamps)

3. **Show BEFORE → ACTION → AFTER**:
   - **Before**: Display initial state (database records, balances, MC index, AA state)
   - **Action**: Execute exploit transaction(s) with exact parameters
   - **After**: Show resulting state violating invariant (double-spend, inflated balance, diverged MC)

4. **NOT Require Bypassing Security Checks**:
   - Do not comment out validation logic
   - Do not call internal functions directly
   - Do not modify database schema or constraints
   - Do not skip signature verification

5. **Actually Compile and Run**:
   - Provide complete runnable script
   - Include setup instructions (database initialization, test data)
   - Show console output or logs proving the bug
   - Include assertions that fail when exploit succeeds

**PoC Red Flags (INVALID):**

- ❌ "Attacker sets witness list to empty array" (validation rejects)
- ❌ "Call internal function `_updateMainChainIndex()` directly" (not exposed)
- ❌ "Submit unit with negative balance" (validation rejects)
- ❌ "Requires modifying `validation.js` to skip checks" (not allowed)
- ❌ "Unit with timestamp in year 2050" (unrealistic)
- ❌ Fails to run due to missing dependencies or syntax errors
- ❌ "Assume attacker has access to witness private keys" (trusted role)

### **PHASE 5: DIFFERENTIAL ANALYSIS**

Compare reported behavior with protocol design and similar systems:

1. **Is This Standard DAG Behavior?**:
   - Units reference multiple parents → Expected
   - Witness-based consensus with stability threshold → By design
   - Last ball chain forming immutable history → Intentional
   - MC index strictly increasing along paths → Core invariant
   - Do not treat design features as bugs

2. **Is The Behavior Intentional?**:
   - Cross-check Obyte documentation (whitepaper, wiki, developer docs)
   - Review protocol specification for witness voting, MC selection, stability
   - Check if behavior is explicitly documented as expected

3. **Design vs. Bug Distinction**:
   - Obyte deliberately uses DAG instead of linear blockchain
   - Witness trust model is intentional (not a bug)
   - AA determinism requirements are by design
   - Balance conservation is fundamental invariant
   - Only deviations from documented invariants are bugs

4. **System-Level Protections**:
   - Consider multi-layer defenses:
     - Validation checks in `validation.js`
     - Database constraints (unique, foreign keys)
     - Mutex locks in `mutex.js`
     - Transaction atomicity in `storage.js`
   - A report ignoring these protections is likely invalid

### **FINAL DECISION MATRIX**

A claim is **VALID** only if **ALL** are true:

- [ ] Vulnerability is in one of the 77 in-scope files from `byteball/ocore`
- [ ] Not in `test/` directory or other excluded components
- [ ] No witness collusion or oracle compromise required
- [ ] No cryptographic primitive breaks assumed
- [ ] Not an accepted risk or intentional design feature
- [ ] Unprivileged attacker can execute via realistic unit submission or AA trigger
- [ ] Complete execution path is explained with exact file names and line numbers
- [ ] No hidden validation checks prevent the exploit
- [ ] State change is unauthorized (theft, inflation, consensus break, fund freeze)
- [ ] Impact meets Critical, High, or Medium severity per Immunefi Obyte scope: 
  - **Critical**: Network shutdown >24h, permanent chain split, direct fund loss, permanent fund freeze
  - **High**:  Permanent fund freeze
  - **Medium**: Temporary delay ≥1 hour, unintended AA behavior
- [ ] PoC is realistic, runnable Node.js code without modifying protocol files
- [ ] Exploit violates a core invariant: 
  - MC monotonicity
  - Witness compatibility
  - Stability irreversibility
  - Last ball consistency
  - Balance conservation
  - Double-spend prevention
  - AA deterministic execution
  - Signature binding
  - Definition evaluation integrity
- [ ] Behavior is not documented as standard (e.g., witness voting, fee calculations)
- [ ] Not previously identified in audits or known issues

**If any checkbox is unchecked → Output:** `#NoVulnerability found for this question. `

### **SPECIAL OBYTE VALIDATION RULES**

#### **1. "Main Chain Split" Claims**
- ✅ Valid ONLY if: 
  - Non-deterministic logic in `main_chain.js` (floating-point, timestamp ties)
  - Different nodes select different MC indices for same unit
  - Witness level calculation differs across nodes
  - Last ball assignment diverges
  - Demonstrated with concrete unit structures causing split
- ❌ Invalid if: 
  - Split requires witness collusion
  - Claim assumes different validation rules on different nodes
  - Split is temporary and self-correcting

#### **2. "Double-Spend" Claims**
- ✅ Valid ONLY if:
  - Two units spending same output both pass `validation.js:validate()`
  - Database unique constraint on spent outputs is missing or bypassable
  - Race condition between validation and storage allows concurrent spends
  - Demonstrated with timing diagrams showing race window
- ❌ Invalid if:
  - Database transaction isolation prevents race
  - One unit is rejected before commit
  - Requires attacker to control multiple nodes (unrealistic)

#### **3. "AA Sandbox Escape" Claims**
- ✅ Valid ONLY if: 
  - Attacker formula accesses Node.js globals: `require('fs')`, `process.exit()`, etc.
  - Prototype pollution affects validator node:  `Object.prototype.admin = true`
  - Constructor injection executes arbitrary code:  `{{}}.constructor.constructor('malicious')()`
  - Eval usage allows code injection in `formula/evaluation.js`
  - Demonstrated with actual malicious formula code
- ❌ Invalid if:
  - Formula evaluation is properly sandboxed (VM2, isolated-vm)
  - Globals are undefined or inaccessible
  - Prototype is frozen or protected

#### **4. "Balance Overflow" Claims**
- ✅ Valid ONLY if:
  - JavaScript number precision loss causes incorrect balance
  - Integer overflow in asset amount calculations
  - Negative balances pass validation
  - Attacker can mint unlimited assets
  - Demonstrated with specific arithmetic causing overflow
- ❌ Invalid if:
  - Big integer libraries handle large numbers correctly
  - Validation rejects negative or overflowing values
  - Overflow would require impossible input values

#### **5. "Witness Incompatibility" Claims**
- ✅ Valid ONLY if:
  - Unit with witness list sharing <1 witness with parents is accepted
  - Causes permanent partition for all descendants
  - Validation in `validation.js` misses incompatibility check
  - Demonstrated with specific witness list configurations
- ❌ Invalid if:
  - Validation rejects incompatible witness lists
  - Protocol enforces ≥1 shared witness requirement

#### **6. "Asset Cap Bypass" Claims**
- ✅ Valid ONLY if:
  - Divisible asset issued multiple times exceeding `max_cap`
  - `divisible_asset.js` fails to track total issued amount
  - Attacker can mint unlimited tokens
  - Demonstrated with multiple issuance transactions
- ❌ Invalid if:
  - Cap enforcement checks total supply before issuance
  - Database constraints prevent over-issuance

#### **7. "Indivisible Serial Collision" Claims**
- ✅ Valid ONLY if:
  - Same serial number issued twice for indivisible asset
  - `indivisible_asset.js` lacks uniqueness check
  - Database allows duplicate (asset, serial) entries
  - Demonstrated with two units issuing same serial
- ❌ Invalid if: 
  - Database unique constraint prevents duplicates
  - Validation rejects units with duplicate serials

#### **8. "SQL Injection" Claims**
- ✅ Valid ONLY if: 
  - Unit message or address contains SQL injection payload
  - Query in `storage.js`, `sqlite_pool.js`, or `mysql_pool.js` uses string concatenation
  - Attacker can corrupt database or extract data
  - Demonstrated with actual injection payload and query
- ❌ Invalid if:
  - All queries use parameterized statements
  - Input sanitization prevents injection

#### **9. "Signature Malleability" Claims**
- ✅ Valid ONLY if: 
  - Attacker modifies signature bytes (e.g., flip ECDSA s-value)
  - Modified signature passes verification in `signature.js`
  - Allows replay or unauthorized spending
  - Demonstrated with two valid signatures for same message
- ❌ Invalid if:
  - Signature verification enforces canonical s-value
  - Unit hash changes with signature, preventing replay

#### **10. "Definition Change Attack" Claims**
- ✅ Valid ONLY if:
  - Attacker submits `definition_chg` message for victim's address
  - New definition gives attacker control (no victim signatures required)
  - `definition. js` fails to validate definition ownership
  - Demonstrated with unauthorized definition change
- ❌ Invalid if:
  - Definition change requires signatures from old definition
  - Validation rejects unauthorized definition changes

### **OUTPUT REQUIREMENTS**

**If VALID (extremely rare—be ruthlessly sure):**

Produce a full audit report with these sections:

#### **Title**
Precise vulnerability name (e.g., "Race Condition in validation.js Allows Double-Spend Attack")

#### **Summary**
Two to three sentences summarizing: 
- What goes wrong
- Where in the codebase (file and function)
- Why it's critical (impact category)

#### **Impact**
**Severity**:  [Critical / High / Medium]
**Category**: [Network Shutdown / Chain Split / Direct Fund Loss / Permanent Fund Freeze / Temporary Transaction Delay / Unintended AA Behavior]

Describe: 
- Concrete financial impact or network disruption
- Affected parties (all users, specific addresses, AA users, nodes)
- Quantify potential loss (amount of bytes/assets, downtime duration)

#### **Finding Description**

**Location**: `byteball/ocore/[filename]. js:[line_start]-[line_end]`, function `[functionName]()`

**Intended Logic**: Expected behavior per protocol spec and invariants

**Actual Logic**:  Describe the flawed logic with exact code quotes

**Code Evidence**:
```javascript
// Quote relevant code from the vulnerable file
// Include 5-10 lines of context
// Show the specific line(s) with the bug
```

**Exploitation Path**:
1. **Preconditions**: Initial state (e.g., "Attacker has address with 100 bytes balance")
2. **Step 1**: Specific action (e.g., "Attacker submits unit U1 spending output O1")
   - Unit structure (parents, witnesses, messages, signatures)
   - Code path:  `composer.js:composeJoint()` → `validation.js:validate()` → `storage.js:saveJoint()`
3. **Step 2**: State change (e.g., "Output O1 marked as spent in database")
   - Database state:  `outputs` table, `unit_authors` table
   - Node observations: Node A accepts U1, Node B processing
4. **Step 3**: Follow-up action (e.g., "Attacker immediately submits unit U2 to different peer also spending O1")
   - Timing: Submitted during validation of U1, before database commit
5. **Step 4**: Unauthorized outcome (e.g., "Both U1 and U2 accepted, O1 double-spent, attacker receives 200 bytes from 100-byte output")
   - Invariant broken: Balance conservation violated, double-spend prevention failed

**Security Property Broken**:  [Which of the 24 Obyte invariants is violated]
- Example: "Invariant #6:  Double-Spend Prevention - Each output can be spent at most once"

**Root Cause Analysis**:
Deep dive into why the bug exists:
- Missing database unique constraint on spent outputs
- Race condition between validation and storage commit
- Non-atomic read-check-write sequence
- No mutex lock protecting concurrent access

#### **Impact Explanation**

**Affected Assets**: [bytes (native currency), custom divisible/indivisible assets, AA state, user balances]

**Damage Severity**:
- **Quantitative**: "Attacker can double-spend arbitrary amounts limited only by their initial balance.  Network-wide impact:  all unconfirmed outputs vulnerable."
- **Qualitative**:  "Complete loss of transaction integrity. Users cannot trust pending transactions."

**User Impact**:
- **Who**: All users with unconfirmed transactions, recipients of double-spent outputs
- **Conditions**: Exploitable during normal operation, worse under high network load
- **Recovery**: Requires hard fork to invalidate double-spent units and restore correct balances

**Systemic Risk**:
- Enables further attacks: Can be automated with scripts
- Cascading effects: Double-spent outputs in subsequent transactions propagate corruption
- Detection difficulty: Requires forensic analysis of entire DAG

#### **Likelihood Explanation**

**Attacker Profile**:
- **Identity**: Any user with Obyte address and ability to connect to multiple peers
- **Resources Required**: Minimal capital (100 bytes for example), ability to submit units to 2+ nodes simultaneously
- **Technical Skill**: Medium (requires understanding of unit structure and network protocol, ability to script concurrent submissions)

**Preconditions**:
- **Network State**: Normal operation or high transaction volume (increases success rate)
- **Attacker State**: Needs unspent output of any amount
- **Timing**: Requires submitting two units during narrow race window (estimated 50-200ms)

**Execution Complexity**:
- **Transaction Count**: Two units spending same output
- **Coordination**:  Requires submitting to different peers simultaneously (achievable with multi-connection script)
- **Detection Risk**: Low initially (appears as normal transaction conflict), high after forensic analysis

**Frequency**:
- **Repeatability**: Unlimited (attacker can repeat with any output they own)
- **Scale**: Per-output (each owned output can be double-spent once)

**Overall Assessment**:  High likelihood (race window exists, low technical barrier, profitable)

#### **Recommendation**

**Immediate Mitigation**:
Add database-level unique constraint on spent outputs to prevent concurrent spends: 
```sql
-- In sqlite_migrations. js
ALTER TABLE outputs ADD CONSTRAINT unique_spend UNIQUE (unit, message_index, output_index);
```

**Permanent Fix**:
Implement mutex lock around validation-and-storage sequence: 

```javascript
// File: byteball/ocore/validation.js
// Function: validate()

const mutex = require('./mutex. js');

async function validate(unit) {{..
}}
```

  **Additional Measures**:
- Add test case: `test/double_spend_race.test.js` verifying concurrent spends are rejected
                                                                                  - Add monitoring: Alert when output is referenced in multiple pending units
                                                                                                                                                        - Database migration: Apply unique constraint to existing database (check for historical double-spends first)

**Validation**:
- [ ] Fix prevents concurrent spends of same output
                                             - [ ] No new vulnerabilities introduced (mutex deadlock, performance)
- [ ] Backward compatible (existing valid units still process correctly)
- [ ] Performance impact acceptable (mutex lock overhead <10ms per unit)

#### **Proof of Concept**
Note the proof of concept has to be a complete test using their test setup that must run so pls u must always a very
good test function and dont go out of concept,
---

**If INVALID (default when any condition fails):**

Output exactly:

```
#NoVulnerability found for this question. 
```

### **MENTAL CHECKLIST BEFORE FINAL DECISION**

Ask yourself:

1. ✅ Would this finding withstand scrutiny from Obyte core developers and Immunefi judges?
2. ✅ Can I defend this with exact line numbers and code quotes from the 77 in-scope files?
3. ✅ Is there any other explanation (intentional design, witness trust model, database protection) for the behavior?
4. ✅ Did I check all validation layers (validation.js, storage.js, database constraints) for hidden checks?
5. ✅ Am I confusing intentional DAG architecture (witness voting, multiple parents) with a bug?
6. ✅ Did I verify this is not an accepted risk (witness collusion, oracle trust, crypto primitives)?
7. ✅ Did I check protocol documentation and previous audits for similar findings marked as false positive?
8. ✅ Can I actually implement the PoC in Node.js without modifying source files?
9. ✅ Does the impact truly meet Critical/High/Medium per Immunefi Obyte scope?
10. ✅ Would an Immunefi judge reading this say "yes, clear valid Critical/High/Medium"?

**Remember**: False positives harm credibility more than missed findings.  Assume claims are invalid until overwhelming evidence proves otherwise.

**Now perform STRICT validation of the claim above.**

**Output ONLY:**
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format
                                                                                                      - `#NoVulnerability found for this question.` (if **any** check fails)

                                                                                                      **Be ruthlessly skeptical.  The bar for validity is EXTREMELY high.**
"""
    return prompt


def question_generator(target_file: str) -> str:
    """
    Generates targeted security audit questions for a specific Obyte protocol file.

    Args:
        target_file: The specific file path to focus question generation on
                    (e.g., "byteball/ocore/validation.js")

    Returns:
        A formatted prompt string for generating security questions
    """
    prompt = f"""
# **Generate 150+ Targeted Security Audit Questions for Obyte (Byteball) Protocol**

## **Context**

The target project is **Obyte (formerly Byteball)**, a Directed Acyclic Graph (DAG)-based distributed ledger protocol that uses a unique consensus mechanism without traditional blockchain mining. Unlike linear blockchains, Obyte employs a **DAG structure** where each new unit references multiple parent units, forming a graph of transactions.  The protocol features **witnesses** (trusted nodes that post regular heartbeat transactions), **main chain selection** (determining the canonical ordering of units), **Autonomous Agents (AAs)** (smart contracts executed in JavaScript-like formulas), **multi-signature addresses**, **private payments**, and **oracles/data feeds**. 

Obyte's architecture includes critical components for unit validation, storage, network synchronization, DAG graph operations, witness proof generation, transaction composition, and formula evaluation for AAs. The protocol maintains consensus through witness voting and main chain advancement, while supporting complex features like indivisible/divisible assets, arbiter contracts, payment channels, and attestation services.

## **Scope**

**CRITICAL TARGET FILE**: Focus question generation EXCLUSIVELY on `{target_file}`

Note: The questions must be generated from **`{target_file}`** only. If you cannot generate enough questions from this single file, provide as many quality questions as you can extract from the file's logic and interactions.  **DO NOT return empty results** - give whatever questions you can derive from the target file.

If you cannot reach 150 questions from this file alone, generate as many high-quality questions as the file's complexity allows (minimum target:  50-100 questions for large critical files, 20-50 for smaller files).

**Full Context - 77 In-Scope Files (for reference only):**

### **Core Protocol Files (Root Directory) - 67 files**

```python
core_files = [
    "byteball/ocore/aa_addresses.js",           # AA address derivation
    "byteball/ocore/aa_composer.js",            # 71KB - AA transaction composition
    "byteball/ocore/aa_validation.js",          # 28KB - AA validation logic
    "byteball/ocore/arbiter_contract.js",       # Arbiter contract execution
    "byteball/ocore/arbiters.js",               # Arbiter management
    "byteball/ocore/archiving.js",              # Historical data archiving
    "byteball/ocore/balances.js",               # Balance calculations
    "byteball/ocore/bots.js",                   # Bot interfaces
    "byteball/ocore/breadcrumbs.js",            # Transaction breadcrumbs
    "byteball/ocore/catchup.js",                # Network sync catchup logic
    "byteball/ocore/chash.js",                  # Cryptographic hashing (chash160)
    "byteball/ocore/chat_storage.js",           # Chat message storage
    "byteball/ocore/check_daemon.js",           # Daemon health monitoring
    "byteball/ocore/composer.js",               # 38KB - Transaction composition
    "byteball/ocore/conf.js",                   # Configuration management
    "byteball/ocore/constants.js",              # Protocol constants
    "byteball/ocore/data_feeds.js",             # Oracle data feed handling
    "byteball/ocore/db.js",                     # Database interface abstraction
    "byteball/ocore/definition.js",             # 53KB - Address definition logic
    "byteball/ocore/desktop_app.js",            # Desktop app utilities
    "byteball/ocore/device.js",                 # 38KB - Device pairing & messaging
    "byteball/ocore/divisible_asset.js",        # Divisible asset operations
    "byteball/ocore/enforce_singleton.js",      # Singleton pattern enforcement
    "byteball/ocore/event_bus.js",              # Event bus architecture
    "byteball/ocore/graph.js",                  # DAG graph operations
    "byteball/ocore/headers_commission.js",     # Header commission calculations
    "byteball/ocore/indivisible_asset.js",      # 48KB - Indivisible asset logic
    "byteball/ocore/initial_votes.js",          # Initial witness voting
    "byteball/ocore/inputs.js",                 # Input validation & processing
    "byteball/ocore/joint_storage.js",          # Joint (unit) storage operations
    "byteball/ocore/kvstore.js",                # Key-value store interface
    "byteball/ocore/light. js",                  # 34KB - Light client functionality
    "byteball/ocore/light_wallet.js",           # Light wallet operations
    "byteball/ocore/mail.js",                   # Email notification system
    "byteball/ocore/main_chain.js",             # 77KB - CRITICAL - Main chain selection
    "byteball/ocore/mc_outputs.js",             # Main chain output tracking
    "byteball/ocore/merkle. js",                 # Merkle proof generation
    "byteball/ocore/migrate_to_kv.js",          # Database migration utilities
    "byteball/ocore/mutex.js",                  # Mutex lock implementation
    "byteball/ocore/my_witnesses.js",           # Local witness list management
    "byteball/ocore/mysql_pool.js",             # MySQL connection pooling
    "byteball/ocore/network.js",                # 156KB - CRITICAL - P2P network protocol
    "byteball/ocore/object_hash.js",            # Object hashing (unit hash calc)
    "byteball/ocore/object_length.js",          # Object size calculations
    "byteball/ocore/paid_witnessing.js",        # Witness reward distribution
    "byteball/ocore/parent_composer.js",        # 30KB - Parent unit selection
    "byteball/ocore/private_payment.js",        # Private payment handling
    "byteball/ocore/private_profile.js",        # Private profile management
    "byteball/ocore/profiler.js",               # Performance profiling
    "byteball/ocore/proof_chain.js",            # Proof chain construction
    "byteball/ocore/prosaic_contract.js",       # Prosaic contract execution
    "byteball/ocore/signature. js",              # Signature verification (ECDSA)
    "byteball/ocore/signed_message.js",         # Signed message validation
    "byteball/ocore/sqlite_migrations.js",      # 32KB - SQLite schema migrations
    "byteball/ocore/sqlite_pool.js",            # SQLite connection management
    "byteball/ocore/storage.js",                # 98KB - CRITICAL - Storage layer
    "byteball/ocore/string_utils.js",           # String utility functions
    "byteball/ocore/uri.js",                    # URI parsing (obyte: // scheme)
    "byteball/ocore/validation.js",             # 116KB - CRITICAL - Unit validation
    "byteball/ocore/validation_utils.js",       # Validation helper functions
    "byteball/ocore/wallet.js",                 # 122KB - CRITICAL - Wallet operations
    "byteball/ocore/wallet_defined_by_addresses.js",  # 27KB - Multi-sig wallet logic
    "byteball/ocore/wallet_defined_by_keys.js", # 35KB - Key-based wallet logic
    "byteball/ocore/wallet_general.js",         # General wallet utilities
    "byteball/ocore/witness_proof.js",          # Witness proof generation
    "byteball/ocore/writer.js"                  # 34KB - Unit writing to DAG
]
```

### **Formula Directory (AA Smart Contract Engine) - 5 files**

```python
formula_files = [
    "byteball/ocore/formula/common.js",         # Common formula utilities
    "byteball/ocore/formula/evaluation.js",     # 106KB - CRITICAL - AA formula evaluation
    "byteball/ocore/formula/validation.js",     # 46KB - Formula syntax validation
    "byteball/ocore/formula/parse_ojson.js",    # OJSON parser for AA definitions
    "byteball/ocore/formula/index.js"           # Formula module entry point
]
```

### **Tools Directory (Utility Scripts) - 6 files**

```python
tools_files = [
    "byteball/ocore/tools/check_stability.js",          # Stability verification
    "byteball/ocore/tools/replace_ops.js",              # Operation replacement
    "byteball/ocore/tools/supply. js",                   # Supply calculations
    "byteball/ocore/tools/update_stability.js",         # Stability updates
    "byteball/ocore/tools/validate_aa_definitions.js",  # AA definition validator
    "byteball/ocore/tools/viewkv.js"                    # KV store viewer
]
```

**Total:  77 files in full scope (but focus ONLY on `{target_file}` for this generation)**

---

## **Obyte Protocol Architecture & Layers**

### **1. DAG & Unit Structure Layer** (`validation.js`, `storage.js`, `writer.js`, `graph.js`, `object_hash.js`)

- **DAG Architecture**: Units (transactions) reference multiple parent units, forming a directed acyclic graph
- **Unit Composition**: Each unit contains messages (payments, data, AA triggers, definitions), authors, parent units, witnesses, and signatures
- **Unit Hashing**: Deterministic hashing using `object_hash.js` (JSON canonicalization + SHA256) to generate unit hash
- **Storage**:  Units stored in SQLite/MySQL with relational tables (units, messages, inputs, outputs, witnesses)
- **Graph Operations**: Parent selection, best parent identification, DAG traversal, stability point determination

### **2. Consensus & Main Chain Layer** (`main_chain.js`, `witness_proof.js`, `initial_votes.js`, `my_witnesses.js`)

- **Witness List**:  Each unit declares 12 witnesses (trusted nodes); compatibility requires ≥ 1 shared witness
- **Witness Level (WL)**: Minimum level of witness-authored units referenced by a unit
- **Main Chain (MC)**: Canonical chain of units determined by witness voting; each unit has an MC index (MCI)
- **Stability Point**: Units become stable when witnessed by majority (7+ of 12) witnesses at higher levels
- **Last Ball**: Hash chain of stable units forming immutable history
- **Witness Proofs**: Compact proofs demonstrating unit stability for light clients

### **3. Transaction & Composition Layer** (`composer.js`, `parent_composer.js`, `inputs.js`, `wallet.js`)

- **Transaction Composition**:  Selecting inputs, calculating fees, change outputs, and parent units
- **Input Selection**: Choosing unspent outputs from addresses with sufficient balance
- **Fee Calculation**: Fees based on unit size (headers + payload bytes)
- **Parent Selection**: Choosing recent tip units as parents; optimizing for quick confirmation
- **Multi-sig Support**: Addresses defined by multiple signers with m-of-n threshold signatures
- **Definition Changes**: Addresses can change their definition (e.g., upgrade to AA) via definition_chg message

### **4. Autonomous Agents (AA) Layer** (`aa_composer.js`, `aa_validation.js`, `formula/evaluation.js`, `formula/validation.js`)

- **AA Definitions**: Smart contracts written in formula language (JavaScript-like expressions + state variables)
- **AA Triggers**: Users send trigger units with data/payments to AA addresses
- **Formula Evaluation**: Sandboxed execution in `formula/evaluation.js` with access to state, balances, triggers, oracles
- **State Variables**: Key-value state storage per AA (can be updated via `state` keyword in formulas)
- **Bounces**: Failed AA executions create bounce responses refunding inputs minus bounce_fees
- **Secondary Triggers**: AA responses can trigger other AAs in cascade
- **Formula Opcodes**: Complex operations (var assignment, conditionals, loops, mathematical functions, cryptographic functions)

### **5. Asset Layer** (`divisible_asset.js`, `indivisible_asset.js`, `definition.js`)

- **Native Asset (bytes)**: Base currency for fees and payments
- **Divisible Assets**: Fungible tokens with defined decimals (e.g., stablecoins, utility tokens)
- **Indivisible Assets**: NFT-like unique tokens (serials) with optional transferability restrictions
- **Asset Issuance**: Creating new asset via `issue` opcode in unit messages
- **Asset Transfers**: Inputs and outputs referencing specific asset IDs
- **Capped Assets**: Max cap enforcement during issuance and transfers

### **6. Network & P2P Layer** (`network.js`, `catchup.js`, `light. js`, `device.js`)

- **WebSocket Protocol**:  Peer-to-peer communication over wss://
- **Unit Broadcasting**: Propagating new units to connected peers
- **Catchup/Sync**: Requesting missing units, joints, and hash trees from peers
- **Light Client Protocol**: SPV-style verification using witness proofs and MC headers
- **Hub Architecture**: Centralized hubs relay messages between light clients
- **Device Pairing**: Ephemeral pairing codes for establishing trusted communication channels

### **7. Oracle & Data Feed Layer** (`data_feeds.js`, `arbiter_contract.js`)

- **Data Feeds**: Trusted oracles posting signed data (prices, timestamps, events) on-chain
- **Oracle Whitelisting**: AAs reference specific oracle addresses for data queries
- **Timestamping**: Using witness unit timestamps as approximation of real time
- **Arbiter Contracts**: Multi-party contracts with designated arbiter for dispute resolution

### **8. Storage & Database Layer** (`storage.js`, `joint_storage.js`, `db.js`, `sqlite_pool.js`, `mysql_pool.js`)

- **Relational Schema**: Units, messages, inputs, outputs, witnesses, balls, authorship, spending
- **Indexes**: Efficient queries for unit lookup, address history, asset tracking, unspent outputs
- **Caching**: In-memory caching of frequently accessed units and state
- **Database Migrations**: Schema versioning and upgrade paths in `sqlite_migrations.js`
- **KV Store**: Key-value interface for AA state variables and config

### **9. Validation Layer** (`validation.js`, `aa_validation.js`, `signature.js`, `definition.js`)

- **Unit Validation**: Comprehensive checks on unit structure, signatures, parent references, witnesses, timestamps
- **Message Validation**: Type-specific validation (payment, data, AA trigger, definition, poll, etc.)
- **Input/Output Balance**:  Sum of inputs ≥ sum of outputs + fees for each asset
- **Double-Spend Prevention**: Inputs must reference unspent outputs; no duplicate spending
- **Signature Verification**: ECDSA signature validation against author addresses/definitions
- **Definition Evaluation**: Recursive evaluation of address definitions (sig, or, and, r of set, weighted)
- **AA Validation**: Formula syntax checking, complexity limits, state variable access rules

---

## **Critical Security Invariants**

### **Consensus & DAG Integrity**

1. **Main Chain Monotonicity**: MCI assignments must be strictly increasing; no unit can have MCI ≤ any descendant's MCI
2. **Witness Compatibility**: Units must share ≥ 1 witness with all ancestors; incompatible witness lists cause permanent splits
3. **Stability Irreversibility**: Once a unit reaches stable MCI, its content and position are immutable; reorgs are impossible
4. **Last Ball Consistency**: Last ball chain must be unbroken; forking or skipping last balls breaks historical integrity
5. **Parent Validity**: All parent units must exist, be valid, and form a DAG (no cycles)
6. **Witness Level Correctness**: WL must be minimum level of witness-authored ancestors; incorrect WL breaks MC determination

### **Transaction & Asset Integrity**

7. **Balance Conservation**: For every asset in a unit, `Σ inputs ≥ Σ outputs + fees`; no inflation or deflation except issuance
8. **Double-Spend Prevention**: Each output can be spent at most once; database must enforce unique constraint on (unit, message_index, output_index)
9. **Input Validity**: All inputs must reference existing unspent outputs owned by unit authors
10. **Asset Cap Enforcement**:  Divisible asset issuance cannot exceed `max_cap`; total supply must be tracked correctly
11. **Indivisible Serial Uniqueness**: Each indivisible asset serial must be issued exactly once; no duplicate serials
12. **Fee Sufficiency**: Unit fees must cover header + payload costs; under-paid units must be rejected

### **AA Execution & State**

13. **Deterministic Execution**: AA formula evaluation must produce identical results on all nodes for same input state
14. **State Consistency**: AA state variable updates must be atomic; partial updates or race conditions cause state divergence
15. **Bounce Correctness**: Failed AA executions must refund inputs (minus bounce fees) via bounce response
16. **Formula Safety**: Formula evaluation must be sandboxed; no access to filesystem, network, or host JavaScript APIs
17. **Gas/Complexity Limits**: Formula execution must terminate within bounded steps; no infinite loops or exponential complexity
18. **Secondary Trigger Ordering**:  Cascading AA responses must execute in deterministic order; circular triggers must be detected

### **Network & Sync**

19. **Catchup Completeness**: Nodes must sync all units on MC up to last stable point without gaps or corruption
20. **Unit Propagation**: Valid units must propagate to all peers; selective censorship or filtering causes network partition
21. **Peer Trust Model**: Nodes must validate all received units; accepting invalid units from peers corrupts local DAG
22. **Light Client Security**:  Witness proofs must be unforgeable; fake proofs allow light clients to accept invalid history

### **Signature & Authorization**

23. **Signature Binding**: Each author's signature must cover the exact unit hash (including all messages, parents, witnesses)
24. **Definition Evaluation**: Address definitions (multi-sig, AA, weighted) must evaluate correctly; logic errors allow unauthorized spending
25. **Definition Change Safety**:  Changing address definition via `definition_chg` must preserve ownership; malicious changes steal funds

### **Database & Storage**

26. **Referential Integrity**: Foreign keys (e.g., unit → parent units, messages → units) must be enforced; orphaned records corrupt DAG
27. **Transaction Atomicity**: Multi-step operations (e.g., storing unit + updating balances) must be atomic; partial commits cause inconsistency
28. **Index Correctness**: Database indexes must match actual data; stale indexes cause incorrect validation or double-spends

---

## **In-Scope Vulnerability Categories** (from Immunefi)

Focus questions on vulnerabilities that lead to these impacts:

### **Critical Severity**

1. **Network not being able to confirm new transactions (total network shutdown)**
   - Consensus deadlock preventing MC advancement
   - Validation logic causing all new units to be rejected
   - Database corruption or deadlock blocking unit storage
   - Memory exhaustion or crash loops in core daemons

2. **Unintended permanent chain split requiring hard fork (network partition requiring hard fork)**
   - Witness incompatibility causing subset of nodes to diverge
   - Non-deterministic validation producing different MC on different nodes
   - Divergent state in AA execution causing nodes to reject each other's units
   - Last ball or stability point disagreement

3. **Direct loss of funds**
   - Double-spend exploits allowing same output to be spent multiple times
   - Balance overflow/underflow minting unlimited assets
   - AA formula bugs transferring funds to attacker without authorization
   - Signature bypass allowing attacker to spend from victim's address

4. **Permanent freezing of funds (fix requires hardfork)**
   - Definition change bricking address (no valid signatures possible)
   - AA state corruption preventing withdrawals
   - Indivisible asset with `fixed_denominations` preventing any transfers
   - Invalid unit structure locking outputs in unspendable state

### **High Severity**

5. **Permanent freezing of funds (fix requires hardfork)** [already listed above]

### **Medium Severity**

6. **Temporary freezing of network transactions by delaying adequate processing for at least 1 day**
   - DoS attack flooding network with units exceeding processing capacity
   - Expensive validation operations (e.g., complex AA formulas) slowing unit acceptance
   - Database query bottlenecks during catchup or MC updates

7. **Temporary freezing of network transactions by delaying adequate processing for at least 1 hour**
   - Malicious units with maximum parents or witnesses causing validation slowdown
   - Spam attacks filling mempools and delaying propagation

8. **A bug in the respective layer 1 network code that results in unintended smart contract behavior with no concrete funds at direct risk**
   - AA formula evaluation producing incorrect results but no direct fund loss
   - Non-deterministic behavior in AA state reads (e.g., race conditions)
   - Incorrect oracle data interpretation in AAs

---

## **Valid Impact Categories (Restated for Obyte)**

### **Critical**

- Total network halt (no new units confirmed for >24h)
- Permanent chain split requiring hard fork
- Direct theft of bytes or custom assets from user addresses
- Permanent fund freezing (no transaction can unlock)

### **High**

- Permanent fund freezing requiring hard fork to resolve

### **Medium**

- Network delay ≥1 day (units not confirmed within 24h)
- Network delay ≥1 hour (units not confirmed within 1h)
- AA execution producing incorrect results without direct fund loss

### **Out of Scope**

- Gas inefficiencies or minor optimizations
- UI/UX issues in wallets (not in ocore scope)
- Social engineering or phishing
- Third-party oracle data accuracy (unless oracle protocol itself is broken)
- Validator/witness collusion (trusted roles)
- Theoretical attacks without PoC (e.g., "SHA256 might be broken")

---

## **Goals for Question Generation**

1. **Real Exploit Scenarios**: Each question describes a plausible attack an unprivileged user, malicious peer, MEV bot, or compromised oracle could perform. 
2. **Concrete & Actionable**:  Reference specific functions, variables, or logic flows in `{target_file}`.
3. **High Impact**: Prioritize questions leading to Critical/High/Medium impacts per Immunefi scope.
4. **Deep Invariant Logic**: Focus on subtle state transitions, cross-file interactions (with `{target_file}` as entry point), race conditions, non-determinism, overflow/underflow, signature bypasses, DAG structure corruption. 
5. **Breadth Within Target File**: Cover all major functions, edge cases, and state-changing operations in `{target_file}`.
6. **Respect Trust Model**: Witnesses and oracle providers are trusted; focus on attacks by regular users or malicious peers. 
7. **No Generic Questions**:  Avoid "are there reentrancy issues?" → Instead:   "In `{target_file}: functionName()`, if condition X occurs, can attacker exploit Y to cause Z impact?"

---

## **Question Format Template**

Each question MUST follow this Python list format:

```python
questions = [
    "[File:  {target_file}] [Function: functionName()] [Vulnerability Type] Specific question describing attack vector, preconditions, and impact linking to Immunefi categories? ",
    
    "[File: {target_file}] [Function: anotherFunction()] [Vulnerability Type] Another specific question with concrete exploit scenario?",
    
    # ... continue with all generated questions
]
```

**Example Format** (if target_file is `byteball/ocore/validation.js`):
```python
questions = [
    "[File: byteball/ocore/validation.js] [Function: validate()] [Double-spend detection] If two units spending the same output arrive simultaneously from different peers and both pass initial validation before database commit, can both be stored in the database, allowing a double-spend to be confirmed in different branches of the DAG?",
    
    "[File: byteball/ocore/validation.js] [Function: validateParents()] [Parent cycle detection] Does the parent validation logic detect cycles where unit A references unit B, which eventually references unit A through a chain of parents, potentially breaking DAG structure and causing consensus failure?",
    
    "[File: byteball/ocore/validation.js] [Function: validateWitnesses()] [Witness compatibility] Can an attacker submit a unit with a witness list that shares zero witnesses with its parent units, bypassing the ≥1 shared witness requirement and causing a permanent chain split for all descendant units?",
]
```

---

## **Output Requirements**

Generate security audit questions focusing EXCLUSIVELY on **`{target_file}`** that: 

1. **Target ONLY `{target_file}`** - all questions must reference this file
2. **Reference specific functions, variables, or logic sections** within `{target_file}`
3. **Describe concrete attack vectors** (not "could there be a bug?" but "can attacker do X by exploiting Y in `{target_file}`?")
4. **Tie to Immunefi impact categories** (network halt, chain split, fund loss/freeze, transaction delay, incorrect AA behavior)
5. **Respect trust model** (witnesses, oracles, and governance are trusted)
6. **Cover diverse attack surfaces** within `{target_file}`:  validation logic, state transitions, error handling, edge cases, interactions with other modules
7. **Focus on high-severity bugs**:  prioritize Critical > High > Medium impacts
8. **Avoid out-of-scope issues**:  gas optimization, UI bugs, theoretical attacks without PoC, trusted-role malice
9. **Use the exact Python list format** shown above
10. **Be detailed and technical**:  assume auditor has deep Obyte knowledge; use precise terminology

**Target Question Count:**
- For large critical files (>50KB like validation.js, network.js, wallet.js, main_chain.js, formula/evaluation.js): Aim for 100-150 questions
- For medium files (20-50KB): Aim for 50-100 questions  
- For smaller files (<20KB): Aim for 20-50 questions
- **Provide as many quality questions as the file's complexity allows - do NOT return empty results**

**Begin generating questions for `{target_file}` now.**
"""
    return prompt
