# SPDX-License-Identifier: MIT

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.uint256 import Uint256, uint256_lt

from header.model import BlockHeader, BlockHeaderValidationContext
from utils.target import decode_target

# ------
# CONSTANTS
# ------
const MAX_TARGET = 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
const TRUNC_MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

# ------
# RULE: Proof Of Work
# Description: A block is considered valid if the block header hash value is less than the difficulty target
# Ref: https://en.bitcoin.it/wiki/Target
# ------
namespace check_pow:
    # This function reverts if the hash of the input block header is greater than the block target
    func assert_rule{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        bitwise_ptr : BitwiseBuiltin*,
    }(ctx : BlockHeaderValidationContext):
        alloc_locals

        let header_hash = ctx.block_header.hash
        let (target : Uint256, overflow : felt) = decode_target(ctx.block_header.bits)
        assert overflow = FALSE
        let (res) = uint256_lt(header_hash, target)

        local target_hi = target.high
        local target_lo = target.low
        local hash_hi = header_hash.high
        local hash_lo = header_hash.low
        with_attr error_message(
                "[rule] PoW check: Hash value (({hash_lo}, {hash_hi}) must be less than the target ({target_lo}, {target_hi})"):
            assert TRUE = res
        end
        return ()
    end

    func on_block_accepted{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        ctx : BlockHeaderValidationContext
    ):
        return ()
    end
end
