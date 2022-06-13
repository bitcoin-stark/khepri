# SPDX-License-Identifier: MIT

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.uint256 import Uint256, uint256_lt

from header.model import BlockHeader
from utils.target import decode_target

# ------
# CONSTANTS
# ------
const MAX_TARGET = 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
const TRUNC_MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

# ------
# RULE: Proof Of Work
# Description: A block is considered valid if the block header hash value is less than the difficulty target
# Ref:
# ------

namespace check_pow:
    # This function reverts if
    func assert_rule{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        bitwise_ptr : BitwiseBuiltin*,
    }(header : BlockHeader):
        alloc_locals

        let header_hash = header.hash
        let (target) = decode_target(header.bits)
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
        header : BlockHeader
    ):
        return ()
    end
end
