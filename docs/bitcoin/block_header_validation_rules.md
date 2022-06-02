# Bitcoin block header validation rules

## Structure

A bitcoin block header is composed of the following elements:
- version
- previous block hash
- merkle root
- timestamp
- difficulty target
- nonce

## Fields validation

### Timestamp

#### Median Past Time (MPT) Rule

The timestamp must be further forwards than the median of the last eleven blocks.

#### Future Block Time Rule

The timestamp cannot be more than 2 hours in the future based on the MAX_FUTURE_BLOCK_TIME constant, relative to the median time from the node’s peers. 