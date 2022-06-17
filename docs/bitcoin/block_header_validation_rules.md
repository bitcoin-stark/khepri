# Headers validation

See <https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp#L3577>

Note: the genesis block is treated separately: if the current block hash is equal to the genesis block hash, then all checks are bypassed.

This documentation keeps the order of checks as they are done in bitcoin core.

The "🙈" emoji indicates checks or specificities that can be bypassed if we don't handle reorgs.

## Structure

A bitcoin block header is composed of the following elements:

- version
- previous block hash
- merkle root
- timestamp
- difficulty target (encoded in bits)
- nonce

## Look for duplicates

This is not a validation per se, but the algo starts by checking if the block is already known.
If it is known, there is nothing more to do for us.

## Check proof of work

[Issue](https://github.com/bitcoin-stark/khepri-starknet/issues/13)

Check proof of work matches claimed amount. In other words, check that the proof of work is lower than (or equal) the target which is specified in the header `bits` field.

## Check previous block

[PR](https://github.com/bitcoin-stark/khepri-starknet/pull/19)

The hash of the previous block must point to a valid block that is already on the chain.

🙈 In a general case, the previous block doesn't has to be the last block (the block with the highest height), because there might be
a reorg. If we don't want to handle reorgs for now, then it must strictly be the block with the highest height.

## Context-dependent validity checks

> By "context", we mean only the previous block headers, but not the UTXO set; UTXO-related validity checks are done in ConnectBlock().

See <https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp#L3447>

### Check proof of work target (bits)

[Issue](https://github.com/bitcoin-stark/khepri-starknet/issues/11)

Check that the target (ie. the field `bits` of the header) is valid.

See <https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp#L3455>

See the implementation for full details, but basically the equation for retargeting difficulty measures the time it took to find the last 2,016 blocks and compares that to the expected time of 20,160 minutes (two weeks based upon a desired 10-minute block time). The ratio between the actual timespan and desired timespan is calculated and a corresponding adjustment (up or down) is made to the difficulty.

`New Difficulty = Old Difficulty * (Actual Time of Last 2016 Blocks / 20160 minutes)`

### Check against checkpoints 🙈

Don't accept any forks from the main chain prior to last checkpoint. Useless if we don't treat reorgs.

See <https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp#L3459>

### Check timestamp against prev

[Issue](https://github.com/bitcoin-stark/khepri-starknet/issues/7)

The famous "Median Past Time" rule where the clock's timestamp must be higher than the median of the previous 11 timestamps.

See <https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp#L3471>

### Check timestamp

[Issue](https://github.com/bitcoin-stark/khepri-starknet/issues/26)

The block timestamp cannot be more than 2 hours in the future based on the MAX_FUTURE_BLOCK_TIME constant,
relative to the adjusted time (the median time from the node’s peers).

See <https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp#L3475>

### Reject blocks with outdated version

[Issue](https://github.com/bitcoin-stark/khepri-starknet/issues/25)

The block version must be higher than a given value depending on its height.

See <https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp#L3479>

## Check ancestors 🙈

This checks must be done if we want to support reorgs. If we don't support reorgs, and if we checked that the
previous block hash is the one of the last blockchain block, those checks don't seem necessary.

```cpp
/* Determine if this block descends from any block which has been found
* invalid (m_failed_blocks), then mark pindexPrev and any blocks between
* them as failed. For example:
*
*                D3
*              /
*      B2 - C2
*    /         \
*  A             D2 - E2 - F2
*    \
*      B1 - C1 - D1 - E1
*
* In the case that we attempted to reorg from E1 to F2, only to find
* C2 to be invalid, we would mark D2, E2, and F2 as BLOCK_FAILED_CHILD
* but NOT D3 (it was not in any of our candidate sets at the time).
*
* In any case D3 will also be marked as BLOCK_FAILED_CHILD at restart
* in LoadBlockIndex.
*/
```

See <https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp#L3637>
