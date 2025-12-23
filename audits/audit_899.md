Based on my thorough investigation of the codebase, I can provide a definitive answer to the security question:

## Answer: The Migration Will FAIL (Not Silently Ignore Duplicates)

**Direct Answer to the Question:**

If duplicate entries exist in `headers_commission_outputs` or `witnessing_outputs` tables, the `CREATE UNIQUE INDEX` statements at lines 48-49 of `sqlite_migrations.js` will **FAIL** and **prevent migration**, NOT silently ignore duplicates. [1](#0-0) 

**Technical Explanation:**

SQLite's `CREATE UNIQUE INDEX` behavior:
- The `IF NOT EXISTS` clause only checks if an index with that **name** already exists
- It does NOT check whether the data allows a unique constraint
- If duplicate values exist for the indexed columns, SQLite raises a constraint violation error and the index creation fails
- This halts the migration, leaving the database at version 1

**Related Security Finding:**

However, there IS a conditional vulnerability: **IF duplicates exist in the database (despite the PRIMARY KEY constraint), witnesses can double-claim rewards** because the validation logic accepts the inflated amounts.

The vulnerability chain:

1. **During spending** (transaction composition): [2](#0-1) 

The code queries unspent outputs and accumulates amounts. If duplicates exist for the same (main_chain_index, address), both amounts are counted.

2. **During validation**: [3](#0-2) 

The `calcEarnings` function uses `SUM(amount)` which counts duplicate rows multiple times, accepting the inflated amount as valid. [4](#0-3) 

3. **When spending**: [5](#0-4) 

The UPDATE marks ALL rows in the range as spent, including duplicates.

**Security Properties:**

- **Invariant Broken**: Balance Conservation (Invariant #5) - witnesses claim more than their legitimate earnings
- **Precondition**: Duplicates must exist (should be impossible due to PRIMARY KEY) [6](#0-5) [7](#0-6) 

**Conclusion:**

The migration correctly **FAILS** when duplicates exist (safe behavior), but the underlying issue is that IF duplicates exist before migration is attempted, witnesses can already double-claim rewards on version 1 databases. The migration failure serves as a detection mechanism for this pre-existing corruption rather than being the vulnerability itself.

## Notes

1. **Migration Behavior is Correct**: The use of `CREATE UNIQUE INDEX` without any "OR IGNORE" clause means duplicates will cause an error, which is the safe behavior that alerts operators to database corruption.

2. **Duplicate Creation**: The PRIMARY KEY constraint should prevent duplicates from being created through normal operation. Duplicates could only exist due to database corruption, manual manipulation, or bugs in very early versions before the constraint existed.

3. **No Active Exploit Path**: Without a way to create duplicates given the existing PRIMARY KEY constraints and INSERT logic with GROUP BY clauses, this remains a theoretical vulnerability dependent on database corruption.

The dangerous scenario mentioned in the question (silently ignoring duplicates) **does NOT occur** - the migration properly fails and alerts operators to the problem.

### Citations

**File:** sqlite_migrations.js (L47-50)
```javascript
				if (version < 2){
					connection.addQuery(arrQueries, "CREATE UNIQUE INDEX IF NOT EXISTS hcobyAddressMci ON headers_commission_outputs(address, main_chain_index)");
					connection.addQuery(arrQueries, "CREATE UNIQUE INDEX IF NOT EXISTS byWitnessAddressMci ON witnessing_outputs(address, main_chain_index)");
					connection.addQuery(arrQueries, "CREATE INDEX IF NOT EXISTS inputsIndexByAddressTypeToMci ON inputs(address, type, to_main_chain_index)");
```

**File:** mc_outputs.js (L86-112)
```javascript
		else{
			var MIN_MC_OUTPUT = (type === 'witnessing') ? 10 : 344;
			var max_count_outputs = Math.ceil(target_amount/MIN_MC_OUTPUT) + 1;
			conn.query(
				"SELECT main_chain_index, amount \n\
				FROM "+table+" \n\
				WHERE is_spent=0 AND address=? AND main_chain_index>=? AND main_chain_index<=? \n\
				ORDER BY main_chain_index LIMIT ?",
				[address, from_mci, max_mci, max_count_outputs],
				function(rows){
					if (rows.length === 0)
						return callbacks.ifNothing();
					var accumulated = 0;
					var to_mci;
					var bHasSufficient = false;
					for (var i=0; i<rows.length; i++){
						accumulated += rows[i].amount;
						to_mci = rows[i].main_chain_index;
						if (accumulated > target_amount){
							bHasSufficient = true;
							break;
						}
					}
					callbacks.ifFound(from_mci, to_mci, accumulated, bHasSufficient);
				}
			);
		}
```

**File:** mc_outputs.js (L116-132)
```javascript
function calcEarnings(conn, type, from_main_chain_index, to_main_chain_index, address, callbacks){
	var table = type + '_outputs';
	conn.query(
		"SELECT SUM(amount) AS total \n\
		FROM "+table+" \n\
		WHERE main_chain_index>=? AND main_chain_index<=? AND +address=?",
		[from_main_chain_index, to_main_chain_index, address],
		function(rows){
			var total = rows[0].total;
			if (total === null)
				total = 0;
			if (typeof total !== 'number')
				throw Error("mc outputs total is not a number");
			callbacks.ifOk(total);
		}
	);
}
```

**File:** validation.js (L2349-2360)
```javascript
						var calcFunc = (type === "headers_commission") ? mc_outputs.calcEarnings : paid_witnessing.calcWitnessEarnings;
						calcFunc(conn, type, input.from_main_chain_index, input.to_main_chain_index, address, {
							ifError: function(err){
								throw Error(err);
							},
							ifOk: function(commission){
								if (commission === 0)
									return cb("zero "+type+" commission");
								total_input += commission;
								checkInputDoubleSpend(cb);
							}
						});
```

**File:** writer.js (L378-384)
```javascript
									case "headers_commission":
									case "witnessing":
										var table = type + "_outputs";
										conn.addQuery(arrQueries, "UPDATE "+table+" SET is_spent=1 \n\
											WHERE main_chain_index>=? AND main_chain_index<=? AND +address=?", 
											[from_main_chain_index, to_main_chain_index, address]);
										break;
```

**File:** initial-db/byteball-sqlite.sql (L353-363)
```sql
CREATE TABLE headers_commission_outputs (
	main_chain_index INT NOT NULL, -- mci of the sponsoring (paying) unit
	address CHAR(32) NOT NULL, -- address of the commission receiver
	amount BIGINT NOT NULL,
	is_spent TINYINT NOT NULL DEFAULT 0,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (main_chain_index, address)
);
-- CREATE INDEX hcobyAddressSpent ON headers_commission_outputs(address, is_spent);
CREATE UNIQUE INDEX hcobyAddressMci ON headers_commission_outputs(address, main_chain_index);
CREATE UNIQUE INDEX hcobyAddressSpentMci ON headers_commission_outputs(address, is_spent, main_chain_index);
```

**File:** initial-db/byteball-sqlite.sql (L366-377)
```sql
CREATE TABLE witnessing_outputs (
	main_chain_index INT NOT NULL,
	address CHAR(32) NOT NULL,
	amount BIGINT NOT NULL,
	is_spent TINYINT NOT NULL DEFAULT 0,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (main_chain_index, address),
	FOREIGN KEY (address) REFERENCES addresses(address)
);
-- CREATE INDEX byWitnessAddressSpent ON witnessing_outputs(address, is_spent);
CREATE UNIQUE INDEX byWitnessAddressMci ON witnessing_outputs(address, main_chain_index);
CREATE UNIQUE INDEX byWitnessAddressSpentMci ON witnessing_outputs(address, is_spent, main_chain_index);
```
