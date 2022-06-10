# SPDX-License-Identifier: MIT

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_not_zero, assert_le, split_felt, unsigned_div_rem
from starkware.cairo.common.math_cmp import is_le, is_not_zero
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.uint256 import Uint256

from openzeppelin.security.safemath import SafeUint256

from header.library import BlockHeader, BlockHeaderVerifier, assert_block_header
from utils.math import clamp, min_uint256, felt_to_Uint256
from utils.target import decode_target, encode_target
from bitcoin.params import Params

# ------
# RULE: Target
# Description: Check the block's target for proof of work
# Ref:
#   https://en.bitcoin.it/wiki/Target
#   https://en.bitcoin.it/wiki/Protocol_rules#Difficulty_change
#   https://en.bitcoin.it/wiki/Difficulty
#   https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp
# ------
namespace target:
    # This function checks the block's target (bits)
    func assert_rule{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        header : BlockHeader, last_header : BlockHeader, last_height : felt, params : Params
    ):
        alloc_locals
        let (local expected_bits) = internal.getNextWorkRequired(last_header, last_height, params)
        local block_bits = header.bits
        with_attr error_message(
                "[invalid-header]::bad-diffbits: expected block target to be {expected_bits}, got {block_bits}"):
            assert expected_bits = block_bits
        end
        return ()
    end
end

# ------
# INTERNAL
# ------
namespace internal:
    # See https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp#L13
    func getNextWorkRequired{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        last_header : BlockHeader, last_height : felt, params : Params
    ) -> (bits : felt):
        let (_, rest) = unsigned_div_rem(last_height + 1, params.difficulty_adjustment_interval)
        let (no_retarget_needed) = is_not_zero(rest)

        # Only change once per difficulty adjustment interval
        if no_retarget_needed == TRUE:
            return (bits=last_header.bits)
        end

        return calculateNextWorkRequired(last_header, last_height, params)
    end

    # See https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp#L49
    func calculateNextWorkRequired{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr
    }(last_header : BlockHeader, last_height : felt, params : Params) -> (bits : felt):
        alloc_locals

        # Go back by what we want to be 14 days worth of blocks
        let height_first = last_height - (params.difficulty_adjustment_interval - 1)
        assert_not_zero(height_first)
        let (first_block_header : BlockHeader) = BlockHeaderVerifier.block_header_by_height(
            height_first
        )
        assert_block_header(first_block_header)

        # Limit adjustment step
        let actual_timespan = last_header.timestamp - first_block_header.timestamp
        let (actual_timespan) = clamp(
            actual_timespan,
            params.pow_target_timespan_div_by_4,
            params.pow_target_timespan_mul_by_4,
        )

        # Retarget
        let (last_target : Uint256) = decode_target(last_header.bits)
        let (actual_timespan_256 : Uint256) = felt_to_Uint256(actual_timespan)
        let (pow_target_timespan : Uint256) = felt_to_Uint256(params.pow_target_timespan)

        let (new_target : Uint256) = SafeUint256.mul(last_target, actual_timespan_256)  # new_target = last_target * actual_timespan
        let (new_target, _) = SafeUint256.div_rem(new_target, pow_target_timespan)  # new_target /= pow_target_timespan

        # Ensure new target is not two high (ie. difficulty too low)
        let (new_target) = min_uint256(new_target, params.pow_limit)

        let (new_bits) = encode_target(new_target)
        return (bits=new_bits)
    end
end
