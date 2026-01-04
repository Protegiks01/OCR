

### Citations

**File:** validation.js (L972-974)
```javascript
	async.eachSeries(arrAuthors, function(objAuthor, cb){
		validateAuthor(conn, objAuthor, objUnit, objValidationState, cb);
	}, callback);
```

**File:** validation.js (L978-979)
```javascript
	if (!isStringOfLength(objAuthor.address, 32))
		return callback("wrong address length");
```

**File:** validation.js (L1015-1016)
```javascript
		if (!chash.isChashValid(objAuthor.address))
			return callback("address checksum invalid");
```

**File:** validation.js (L1022-1023)
```javascript
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){
```

**File:** validation.js (L1028-1029)
```javascript
						if (!arrDefinition)
							return callback("definition " + definition_chash + " bound to address " + objAuthor.address + " is not defined");
```

**File:** chash.js (L139-141)
```javascript
	var encoded = (chash_length === 160) ? base32.encode(chash).toString() : chash.toString('base64');
	//console.log(encoded);
	return encoded;
```
