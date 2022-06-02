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

### Difficulty target

#### Hash validation

The block header hash must be lower than the target.

#### Retargeting validation

The equation for retargeting difficulty measures the time it took to find the last 2,016 blocks and compares that to the expected time of 20,160 minutes (two weeks based upon a desired 10-minute block time). The ratio between the actual timespan and desired timespan is calculated and a corresponding adjustment (up or down) is made to the difficulty. 

New Difficulty = Old Difficulty * (Actual Time of Last 2016 Blocks / 20160 minutes)