# SPDX-License-Identifier: MIT
# Khepri smart contracts written in Cairo v0.1.0 (header/library.cairo)

%lang starknet
# Starkware dependencies
from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256, uint256_lt

from utils.common import swap_endianness_64
from utils.sha256.sha256_contract import compute_sha256
from header.model import BlockHeader, BlockHeaderValidationContext
from header.rules.median_past_time import median_past_time
from header.rules.check_pow import check_pow
from header.rules.previous_block_hash import previous_block_hash

# ------
# STORAGE
# ------
@storage_var
func block_header_hash_(block_height : felt) -> (block_header_hash : Uint256):
end

@storage_var
func block_header_(block_header_hash : Uint256) -> (block_header : BlockHeader):
end

namespace BlockHeaderVerifier:
    # -----
    # VIEWS
    # -----
    func block_header_hash{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        block_height
    ) -> (block_header_hash : Uint256):
        let (block_header_hash) = block_header_hash_.read(block_height)
        return (block_header_hash)
    end

    func block_header_by_hash{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        block_header_hash : Uint256
    ) -> (block_header : BlockHeader):
        let (block_header) = block_header_.read(block_header_hash)
        return (block_header)
    end

    func block_header_by_height{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        block_header_height : felt
    ) -> (block_header : BlockHeader):
        let (block_header_hash) = block_header_hash_.read(block_header_height)
        let (block_header) = block_header_.read(block_header_hash)
        return (block_header)
    end

    # ------
    # CONSTRUCTOR
    # ------

    func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
        return ()
    end

    # ------------------
    # EXTERNAL FUNCTIONS
    # ------------------

    func process_block{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        bitwise_ptr : BitwiseBuiltin*,
        range_check_ptr,
    }(height : felt, data_len : felt, data : felt*):
        alloc_locals

        # Verify provided block header
        let (local header) = prepare_header(data)
        let (previous_block_header) = block_header_by_height(height - 1)
        let ctx = BlockHeaderValidationContext(height, header, previous_block_header)
        process_header(ctx)

        return ()
    end

    # Assuming data is the header packed as an array of 4 bytes
    func prepare_header{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(data : felt*) -> (
        res : BlockHeader
    ):
        alloc_locals
        let (version) = swap_endianness_64(data[0], 4)

        let (prev0) = swap_endianness_64(data[7] * 2 ** 32 + data[8], 8)
        let (prev1) = swap_endianness_64(data[5] * 2 ** 32 + data[6], 8)
        let (prev2) = swap_endianness_64(data[3] * 2 ** 32 + data[4], 8)
        let (prev3) = swap_endianness_64(data[1] * 2 ** 32 + data[2], 8)

        local prev_block : Uint256 = Uint256(
            prev3 + prev2 * 2 ** 64,
            prev1 + prev0 * 2 ** 64,
            )

        let (merkle0) = swap_endianness_64(data[15] * 2 ** 32 + data[16], 8)
        let (merkle1) = swap_endianness_64(data[13] * 2 ** 32 + data[14], 8)
        let (merkle2) = swap_endianness_64(data[11] * 2 ** 32 + data[12], 8)
        let (merkle3) = swap_endianness_64(data[09] * 2 ** 32 + data[10], 8)

        local merkle_root : Uint256 = Uint256(
            merkle3 + merkle2 * 2 ** 64,
            merkle1 + merkle0 * 2 ** 64,
            )
        let (timestamp) = swap_endianness_64(data[17], 4)
        let (bits) = swap_endianness_64(data[18], 4)
        let (nonce) = swap_endianness_64(data[19], 4)

        let (single_sha) = compute_sha256(data, 80)
        let (double_sha) = compute_sha256(single_sha, 32)

        # %{ print('block hash:', ''.join([f'{memory[ids.double_sha + i]:08x}' for i in range(8)])) %}

        let (hash0) = swap_endianness_64(double_sha[6] * 2 ** 32 + double_sha[7], 8)
        let (hash1) = swap_endianness_64(double_sha[4] * 2 ** 32 + double_sha[5], 8)
        let (hash2) = swap_endianness_64(double_sha[2] * 2 ** 32 + double_sha[3], 8)
        let (hash3) = swap_endianness_64(double_sha[0] * 2 ** 32 + double_sha[1], 8)

        local header_hash : Uint256 = Uint256(
            hash3 + hash2 * 2 ** 64,
            hash1 + hash0 * 2 ** 64,
            )

        local header : BlockHeader = BlockHeader(version, prev_block, merkle_root, timestamp, bits, nonce, header_hash)
        return (header)
    end

    func process_header{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        bitwise_ptr : BitwiseBuiltin*,
    }(ctx : BlockHeaderValidationContext):
        alloc_locals
        # Invoke consensus rules checks

        # RULE: Previous Block Hash
        previous_block_hash.assert_rule(ctx)

        # RULE: Proof Of Work
        check_pow.assert_rule(ctx)

        # RULE: Median Past Time
        median_past_time.assert_rule(ctx)

        # RULE: Timestamp is not in the future
        #
        # This rule is a bit specific as it makes sense for accepting new blocks, but not really
        # during Initial Block Download (aka IBD).
        #
        # In Bitcoin Core, the rule is implemented as: `block time <= adjusted-time + 2h`, where
        # adjusted-time is the present time adjusted with the time of peers. The rule remains the same
        # during IBD.
        #
        # In StarkNet, the only source of time we have is the current (StarkNet) block timestamp, which
        # we cannot trust.
        #
        # Therefore, we cannot implement the rule as-is.

        # Accept block
        accept_block(ctx)

        return ()
    end

    func accept_block{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        bitwise_ptr : BitwiseBuiltin*,
    }(ctx : BlockHeaderValidationContext):
        alloc_locals
        # Write current header to storage
        block_header_hash_.write(ctx.height, ctx.block_header.hash)
        block_header_.write(ctx.block_header.hash, ctx.block_header)

        # Consensus rules callback
        previous_block_hash.on_block_accepted(ctx)
        check_pow.on_block_accepted(ctx)
        median_past_time.on_block_accepted(ctx)
        return ()
    end
end
