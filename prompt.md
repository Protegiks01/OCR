# **Generate 150+ Targeted Security Audit Questions for Obyte (Byteball) Protocol**

## **Context**

The target project is **Obyte (formerly Byteball)**, a Directed Acyclic Graph (DAG)-based distributed ledger protocol that uses a unique consensus mechanism without traditional blockchain mining. Unlike linear blockchains, Obyte employs a **DAG structure** where each new unit references multiple parent units, forming a graph of transactions.  The protocol features **witnesses** (trusted nodes that post regular heartbeat transactions), **main chain selection** (determining the canonical ordering of units), **Autonomous Agents (AAs)** (smart contracts executed in JavaScript-like formulas), **multi-signature addresses**, **private payments**, and **oracles/data feeds**.

Obyte's architecture includes critical components for unit validation, storage, network synchronization, DAG graph operations, witness proof generation, transaction composition, and formula evaluation for AAs. The protocol maintains consensus through witness voting and main chain advancement, while supporting complex features like indivisible/divisible assets, arbiter contracts, payment channels, and attestation services.

## **Scope**

Note the questions must be generated from this file `` only and if u dont have enough questions from this file u must give what u have pls dont give empty questions
if u dont have up to the number give the number of questions u can give. 

**CRITICAL**:  Focus EXCLUSIVELY on the following 77 files from the `byteball/ocore` repository. Generate questions ONLY from these files and their direct interactions:

### **Core Protocol Files (Root Directory) - 67 files**

```python
core_files = [
    "byteball/ocore/aa_addresses.js",           # AA address derivation
    "byteball/ocore/aa_composer.js",            # 71KB - AA transaction composition
    "byteball/ocore/aa_validation.js",          # 28KB - AA validation logic
    "byteball/ocore/arbiter_contract.js",       # Arbiter contract execution
    "byteball/ocore/arbiters.js",               # Arbiter management
    "byteball/ocore/archiving. js",              # Historical data archiving
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
    "byteball/ocore/device. js",                 # 38KB - Device pairing & messaging
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
    "byteball/ocore/network. js",                # 156KB - CRITICAL - P2P network protocol
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

**Total: 77 files to audit**

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

- **Transaction Composition**: Selecting inputs, calculating fees, change outputs, and parent units
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

### **9. Validation Layer** (`validation.js`, `aa_validation.js`, `signature.js`, `definition. js`)

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
10. **Asset Cap Enforcement**: Divisible asset issuance cannot exceed `max_cap`; total supply must be tracked correctly
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
22. **Light Client Security**: Witness proofs must be unforgeable; fake proofs allow light clients to accept invalid history

### **Signature & Authorization**

23. **Signature Binding**: Each author's signature must cover the exact unit hash (including all messages, parents, witnesses)
24. **Definition Evaluation**: Address definitions (multi-sig, AA, weighted) must evaluate correctly; logic errors allow unauthorized spending
25. **Definition Change Safety**: Changing address definition via `definition_chg` must preserve ownership; malicious changes steal funds

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

## **Areas of Concern & Attack Vectors**

### **1. Main Chain & Consensus (`main_chain.js`, `witness_proof.js`)**

- **Non-deterministic MC Selection**: If `main_chain.js` uses non-deterministic logic (e.g., timestamp comparisons with floating-point, hash collisions, random tie-breaking), different nodes may select different MCs → permanent split
- **Witness Level Miscalculation**:  Incorrect WL assignment can cause MCI disagreement; must verify all witness units are correctly identified
- **Stability Point Race Conditions**: Concurrent updates to last stable MCI could cause nodes to stabilize different units
- **Last Ball Forking**: If two units at same MCI both reference previous last ball, which becomes canonical?  Forking breaks historical chain
- **Witness Proof Forgery**: Can attacker craft fake witness proofs convincing light clients to accept invalid units?

### **2. Unit Validation (`validation.js`, `object_hash.js`, `inputs.js`)**

- **Hash Collision or Preimage Attacks**: If attacker finds unit with same hash as valid unit, can substitute malicious content
- **Parent Cycle Detection**: Does validation detect cycles in parent references?  Cycles break DAG assumptions
- **Witness List Incompatibility**: Posting unit with witness list incompatible with all parents causes permanent split for descendants
- **Timestamp Manipulation**:  Can attacker use far-future or far-past timestamps to disrupt MC selection or stability?
- **Double-Spend via Race Conditions**: If two units spending same output arrive simultaneously, can both be accepted in different branches?
- **Input/Output Mismatch**: Does validation correctly sum all assets (bytes + custom assets) and verify `Σ inputs ≥ Σ outputs + fees`?
- **Negative Balances or Overflow**: Integer overflow in balance calculations could mint unlimited assets

### **3. AA Execution (`formula/evaluation.js`, `aa_composer.js`, `aa_validation.js`)**

- **Non-Deterministic Execution**: If formula evaluation uses `Math.random()`, `Date.now()`, or depends on external state not in unit, results diverge
- **Complexity/Gas Exhaustion**: Can attacker deploy AA with infinite loop or exponential complexity causing node DoS?
- **State Variable Race Conditions**: If concurrent AA triggers modify same state variable, can final state diverge across nodes?
- **Reentrancy in Cascading Triggers**: Can AA trigger itself or create circular trigger chain exploiting stale state?
- **Formula Sandbox Escape**: Can attacker use `eval()`, `Function()`, `require()`, or prototype pollution to escape sandbox and execute arbitrary code?
- **Integer Overflow in Formula Math**: Does formula engine handle large numbers safely? Can overflow bypass balance checks?
- **Bounce Response Manipulation**: Can attacker force bounce with incorrect refund amount or recipient?

### **4. Network & Sync (`network.js`, `catchup.js`, `light.js`)**

- **Unit Flooding DoS**: Attacker broadcasts massive number of valid units exceeding node processing capacity
- **Malicious Parent Selection**: Can attacker post units with parents that cause validation bottleneck or MC disagreement?
- **Catchup Poisoning**: During sync, can malicious peer send incorrect units or skip critical units causing node corruption?
- **Light Client Proof Spoofing**: Can attacker forge witness proofs or MC headers to trick light clients?
- **Network Partition via Witness Censorship**: If attacker controls majority of hubs, can they censor witness units causing split?

### **5. Transaction Composition (`composer.js`, `parent_composer.js`, `wallet.js`)**

- **Input Selection Logic Errors**: Can attacker trick wallet into double-spending or selecting already-spent outputs?
- **Fee Underpayment**: Can attacker craft unit with insufficient fees that still gets accepted?
- **Change Output Calculation**: Off-by-one or rounding errors in change could leak funds or cause rejection
- **Parent Selection Bias**: Can malicious parent selection algorithm delay confirmation or cause MC disagreement?

### **6. Asset Operations (`divisible_asset.js`, `indivisible_asset.js`)**

- **Asset Issuance Overflow**: Can attacker issue asset multiple times exceeding `max_cap`?
- **Serial Collision in Indivisibles**: Can same serial be issued twice for indivisible asset?
- **Transfer Restrictions Bypass**: If asset has `cosigned_by_definer`, can attacker bypass co-signature requirement?
- **Decimal Handling Errors**:  Divisible assets with varying decimals; can precision loss or overflow occur in calculations?

### **7. Storage & Database (`storage.js`, `joint_storage.js`, `sqlite_pool.js`, `mysql_pool.js`)**

- **SQL Injection**:  Are all queries using parameterized statements?  Can attacker inject SQL via unit messages or addresses?
- **Race Conditions in Unit Storage**: If two nodes store same unit concurrently, can duplicate entries or constraint violations corrupt DB?
- **Database Deadlocks**: Complex transactions (e.g., storing unit with many inputs/outputs) could deadlock under load
- **Index Corruption**: If indexes become inconsistent with data, can lead to incorrect validation or missed double-spends

### **8. Signature & Definition (`signature.js`, `definition.js`, `wallet_defined_by_addresses.js`)**

- **Signature Malleability**: Can attacker modify signature bytes to create different valid signature for same message (e.g., ECDSA s-value flip)?
- **Definition Evaluation Bypass**: In multi-sig or weighted definitions, can attacker exploit logic errors to authorize without sufficient signatures?
- **Definition Change Attacks**: Can attacker submit `definition_chg` message replacing address definition with one they control?
- **Address Collision**:  Can attacker generate address colliding with existing address to steal funds or impersonate?

### **9. Oracle & Data Feeds (`data_feeds.js`, `arbiter_contract.js`)**

- **Oracle Data Manipulation**: If AA trusts single oracle without verification, can compromised oracle feed incorrect data causing fund loss?
- **Timestamp Spoofing**: Can attacker post data feed with fake timestamp to manipulate time-dependent AAs?
- **Data Feed Censorship**: Can attacker DoS specific oracle preventing AA from executing?

### **10. Time-Dependent Logic (across multiple files)**

- **Timestamp Validation**:  Are unit timestamps validated against MC timestamps? Can far-future timestamps disrupt ordering?
- **Time-Based AA Logic**: Do AAs using `timestamp` trigger keyword handle edge cases (e.g., same timestamp for multiple units)?

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
2. **Concrete & Actionable**: Reference specific functions, variables, or logic flows in the 77 in-scope files.
3. **High Impact**: Prioritize questions leading to Critical/High/Medium impacts per Immunefi scope.
4. **Deep Invariant Logic**: Focus on subtle state transitions, cross-file interactions, race conditions, non-determinism, overflow/underflow, signature bypasses, DAG structure corruption.
5. **Breadth Across Files**: Cover all major areas—validation, consensus, AA execution, network, storage, composition, assets.
6. **Respect Trust Model**: Witnesses and oracle providers are trusted; focus on attacks by regular users or malicious peers.
7. **No Generic Questions**:  Avoid "are there reentrancy issues?" → Instead:  "In `aa_composer.js:handleAAResponse()`, if a secondary trigger's formula calls back into the triggering AA before state is committed, can attacker drain funds via reentrancy?"

---

## **File-Specific Question Strategies**

### **validation.js (116KB - Core Validation)**

- Validate unit structure:  parents, witnesses, authors, messages, signatures
- Check input/output balance for each asset
- Verify hash correctness and signature authenticity
- Inspect double-spend detection logic
- Examine timestamp validation and MC index assignment
- Test edge cases:  units with maximum parents/witnesses, zero outputs, conflicting messages

### **main_chain.js (77KB - Consensus)**

- Analyze MC index determination algorithm
- Verify witness level calculation
- Check last ball and stability point updates
- Inspect for non-deterministic comparisons (timestamps, tie-breaking)
- Test concurrent MC updates from multiple threads

### **network.js (156KB - P2P Protocol)**

- Examine unit broadcasting and request handling
- Check flood protection and rate limiting
- Verify peer trust and validation of received units
- Inspect catchup protocol for missing unit requests
- Test DoS vectors (malformed messages, large payloads, spam)

### **storage.js (98KB - Storage Layer)**

- Validate database transaction atomicity
- Check foreign key constraints and index integrity
- Inspect SQL query construction for injection risks
- Verify locking mechanisms to prevent race conditions
- Test concurrent unit storage and retrieval

### **wallet.js (122KB - Wallet Operations)**

- Analyze input selection algorithm
- Check change output calculation
- Verify fee estimation accuracy
- Inspect multi-sig signing flows
- Test balance tracking for multiple assets

### **formula/evaluation.js (106KB - AA Execution Engine)**

- Verify deterministic execution (no random, time-dependent, or external state)
- Check complexity limits and gas accounting
- Inspect sandbox isolation (no `eval`, `require`, prototype pollution)
- Validate state variable read/write atomicity
- Test formula operations for overflow, division by zero, type coercion bugs
- Examine bounce generation and refund calculation

### **aa_composer.js (71KB - AA Transaction Builder)**

- Verify AA trigger unit composition
- Check data payload encoding and parsing
- Inspect response unit generation (primary and secondary triggers)
- Validate bounced payment construction
- Test cascading trigger ordering

### **aa_validation.js (28KB - AA Validation)**

- Verify formula syntax validation
- Check complexity estimation accuracy
- Inspect state variable access rules
- Validate trigger unit structure

### **composer.js / parent_composer.js (Transaction Composition)**

- Analyze parent unit selection algorithm
- Verify fee calculation against unit size
- Check for missing input validation
- Inspect handling of multi-asset transactions

### **definition.js (53KB - Address Definitions)**

- Verify recursive evaluation of `sig`, `or`, `and`, `r of set`, `weighted`
- Check for logic errors allowing bypass of signature requirements
- Inspect definition change message validation
- Test hash-based address derivation for collisions

### **signature.js (Signature Verification)**

- Validate ECDSA signature verification against unit hash
- Check for signature malleability (s-value flipping)
- Verify public key recovery and address matching

### **divisible_asset.js / indivisible_asset.js (Asset Operations)**

- Verify balance conservation in transfers
- Check `max_cap` enforcement for divisible assets
- Inspect serial uniqueness for indivisible assets
- Validate transfer restrictions (`fixed_denominations`, `cosigned_by_definer`)

### **graph.js (DAG Operations)**

- Verify parent validity (existence, no cycles)
- Check best parent selection algorithm
- Inspect DAG traversal for correctness

### **object_hash.js (Hashing)**

- Verify deterministic JSON canonicalization
- Check SHA256 implementation correctness
- Test for hash collisions or preimage weaknesses

### **witness_proof.js (Light Client Proofs)**

- Verify proof generation correctness
- Check for forgery or manipulation of proofs
- Inspect proof verification in light clients

### **data_feeds.js (Oracle Data)**

- Verify oracle signature validation
- Check data feed timestamp and value parsing
- Inspect AA integration with oracles

### **inputs.js (Input Validation)**

- Verify input references existing unspent outputs
- Check ownership validation against author addresses
- Inspect double-spend detection

### **writer.js (Unit Writing)**

- Verify atomicity of unit commit to database
- Check for partial writes or rollback failures
- Inspect error handling during unit storage

### **catchup.js / light.js (Sync Protocols)**

- Verify completeness of unit sync
- Check validation of received units from peers
- Inspect handling of missing or corrupted units

### **Other Files** (device. js, balances.js, arbiter_contract.js, etc. )**

- Generate targeted questions based on each file's specific logic and interactions

---

## **Question Format Template**

Each question MUST follow this Python list format:

```python
questions = [
    "[File:  byteball/ocore/validation.js] [Function: validate()] [Double-spend detection] If two units spending the same output arrive simultaneously from different peers and both pass initial validation before database commit, can both be stored in the database, allowing a double-spend to be confirmed in different branches of the DAG?",
    
    "[File: byteball/ocore/main_chain.js] [Function: updateMainChainIndex()] [Non-deterministic MC selection] Does the main chain index determination algorithm use floating-point arithmetic or timestamp comparisons that could produce different results on nodes with different system clocks or CPU architectures, causing a permanent chain split?",
    
    "[File: byteball/ocore/formula/evaluation.js] [Function: evaluateFormula()] [Sandbox escape] Can an attacker craft an AA formula using prototype pollution (e.g., `Object.prototype.toString = malicious_func`) or constructor injection to escape the sandbox and execute arbitrary Node.js code on the validating node?",
    
    "[File: byteball/ocore/network.js] [Function: handleJoint()] [Unit flooding DoS] Can an attacker flood the network with a massive number of valid units (e.g., 100,000 units/second) that individually pass validation but collectively exceed the node's processing capacity, causing transaction confirmation delays >1 day?",
    
    "[File: byteball/ocore/aa_composer.js] [Function: composeAAResponse()] [Cascading trigger reentrancy] If AA1 triggers AA2, and AA2's response formula immediately triggers AA1 again before AA1's state changes are committed, can an attacker exploit stale state reads to drain funds or mint unlimited assets?",
]
```

---

## **Output Requirements**

Generate **150+ distinct security audit questions** (aim for 150-200) that:

1. **Target the 77 in-scope files exclusively**
2. **Reference specific functions, variables, or logic sections**
3. **Describe concrete attack vectors** (not "could there be a bug?" but "can attacker do X by exploiting Y?")
4. **Tie to Immunefi impact categories** (network halt, chain split, fund loss/freeze, transaction delay, incorrect AA behavior)
5. **Respect trust model** (witnesses, oracles, and governance are trusted)
6. **Cover diverse attack surfaces**:  consensus, validation, AA execution, network, storage, signatures, assets, composition, sync
7. **Focus on high-severity bugs**:  prioritize Critical > High > Medium impacts
8. **Avoid out-of-scope issues**: gas optimization, UI bugs, theoretical attacks without PoC, trusted-role malice
9. **Use the exact Python list format** shown above
10. **Be detailed and technical**:  assume auditor has deep Obyte knowledge; use precise terminology

**Begin generating the 150+ questions now.**