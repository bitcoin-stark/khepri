## Previous header hash

```cairo
# Verify previous block header with provided hash
let (prev_hash_eq) = arr_eq(prev_header_hash, 2, curr_header_hash, 2)
# assert prev_hash_eq = 1
```

Why the current header hash is compared to the previous header hash ?


## Timestamp

### Median Past Time (MPT) Rule

### Future Block Time Rule


## Difficulty target

### Hash validation

The block header hash must be lower than the target.

### Retargeting validation
