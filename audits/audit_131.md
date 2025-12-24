# NoVulnerability found for this question.

After rigorous validation, this claim fails critical feasibility checks in the attack creation mechanism.

**Analysis:**

The vulnerability in `receiveTextCoin()` at lines 2542-2547 is technically real - it only claims one asset when the first asset is private. [1](#0-0) 

However, the claimed attack path using `outputs_by_asset` is **not feasible** with the current codebase:

1. **Missing Textcoin Processing**: The `generateNewMnemonicIfNoAddress()` function is only called for `to_address`, `base_outputs`, and `asset_outputs` (lines 2017-2023), but **NOT for `outputs_by_asset`**. [2](#0-1) 

2. **Existing Protection**: When `outputs_by_asset` contains multiple assets and any checked asset is private/indivisible, line 2162-2164 throws an error preventing the multi-asset textcoin creation. [3](#0-2) 

3. **Alternative Path Blocked**: While an attacker could theoretically use `base_outputs` + `asset_outputs` separately to the same textcoin address (which would reuse the mnemonic via line 1999), [4](#0-3)  the NULL sorting in SQL `ORDER BY asset DESC` would place the base currency (NULL) **last**, not mixed with custom assets in a way that triggers the vulnerability consistently.

**Why This Matters:**

The report's exploitation path requires creating a multi-asset textcoin with mixed privacy settings, but:
- `outputs_by_asset` doesn't support textcoin addresses (no mnemonic generation)
- Using separate `base_outputs`/`asset_outputs` requires careful asset ID ordering that may not be attacker-controllable
- The validation at line 2162-2164, while incomplete, still blocks some mixed-privacy scenarios

**Notes:**

While the **logic flaw exists** in `receiveTextCoin()` (unsafe assumption at line 2533), [5](#0-4)  the **attack is not practically exploitable** through documented wallet functions. An attacker would need to manually craft units outside `sendMultiPayment()`, which falls outside the scope of this specific vulnerability claim focused on the wallet API.

The developers should still fix the assumption and add explicit validation, but this does not constitute an immediately exploitable Critical vulnerability under current code constraints.

### Citations

**File:** wallet.js (L1999-2000)
```javascript
					var strMnemonic = assocMnemonics[output.address] || "";
					var mnemonic = new Mnemonic(strMnemonic.replace(/-/g, " "));
```

**File:** wallet.js (L2017-2023)
```javascript
			if (to_address) {
				var to_address_output = {address: to_address, amount: amount};
				var cnt = generateNewMnemonicIfNoAddress(asset, [to_address_output]);
				if (cnt) to_address = to_address_output.address;
			}
			if (base_outputs) generateNewMnemonicIfNoAddress(null, base_outputs);
			if (asset_outputs) generateNewMnemonicIfNoAddress(asset, asset_outputs);
```

**File:** wallet.js (L2162-2164)
```javascript
					if (outputs_by_asset && (objAsset.is_private || objAsset.fixed_denominations)) {
						if (Object.keys(outputs_by_asset).filter(a => a !== 'base' && a !== nonbaseAsset).length > 0)
							throw Error("outputs_by_asset with multiple assets cannot be used for private payments and indivisible assets");
```

**File:** wallet.js (L2533-2533)
```javascript
					const objAsset = asset_infos[0]; // assuming all other assets have the same privacy and divisibility
```

**File:** wallet.js (L2542-2547)
```javascript
					else { // claim only the 1st asset
						opts.asset = asset;
						opts.amount = row.amount;
						opts.to_address = addressTo;
						opts._private = true; // to prevent retries with fees paid by the recipient
					}
```
