# SPDX-License-Identifier: MIT
# Khepri smart contracts written in Cairo v0.1.0 (header/library.cairo)

%lang starknet
# Starkware dependencies
from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256, uint256_lt, uint256_eq
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.math import split_felt, assert_not_equal, assert_not_zero
from starkware.cairo.common.math_cmp import is_not_zero

from utils.common import swap_endianness_64
from utils.sha256.sha256_contract import compute_sha256

from header.model import BlockHeader, BlockHeaderValidationContext
from header.storage import storage
from header.rules.median_past_time import median_past_time
from header.rules.check_pow import check_pow
from header.rules.previous_block_hash import previous_block_hash
from header.rules.target import target
from bitcoin.params import Params, get_params

namespace BlockHeaderVerifier:
    # ------
    # CONSTRUCTOR
    # ------

    func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
        let (genesis_block_header : BlockHeader) = internal.genesis_block_header()
        storage.unsafe_write_header(0, genesis_block_header)
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
    }(data_len : felt, data : felt*):
        alloc_locals

        let (last_height) = storage.current_height()

        # Verify provided block header
        let (local header) = internal.prepare_header(data)
        let (previous_block_header) = storage.block_header_by_height(last_height)
        let ctx = BlockHeaderValidationContext(last_height + 1, header, previous_block_header)
        internal.process_header(ctx)

        return ()
    end
end

namespace internal:
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
        let (local params : Params) = get_params()

        let (should_skip) = should_skip_checks(ctx)
        if should_skip == TRUE:
            return ()
        end

        # Invoke consensus rules checks

        # RULE: Previous Block Hash
        previous_block_hash.assert_rule(ctx)

        # RULE: Proof Of Work
        check_pow.assert_rule(ctx)

        # RULE: Check proof of work target (bits)
        target.assert_rule(ctx, params)

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

    func should_skip_checks{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        bitwise_ptr : BitwiseBuiltin*,
    }(ctx : BlockHeaderValidationContext) -> (skip : felt):
        # Should never encounter the genesis block
        let (genesis : BlockHeader) = genesis_block_header()
        let (is_genesis_hash) = uint256_eq(ctx.block_header.hash, genesis.hash)
        assert is_genesis_hash = FALSE

        # Skip if block was already processed
        let (stored_block_header : BlockHeader) = storage.block_header_by_hash(
            ctx.block_header.hash
        )
        let (is_already_stored) = is_not_zero(stored_block_header.version)
        return (skip=is_already_stored)
    end

    func accept_block{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        bitwise_ptr : BitwiseBuiltin*,
    }(ctx : BlockHeaderValidationContext):
        alloc_locals
        # Write current header to storage
        storage.write_header(ctx.height, ctx.block_header)

        # Consensus rules callback
        previous_block_hash.on_block_accepted(ctx)
        check_pow.on_block_accepted(ctx)
        median_past_time.on_block_accepted(ctx)
        return ()
    end

    # Returns the hardcoded genesis block.
    # See https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp
    # and https://www.blockchain.com/btc/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    func genesis_block_header{range_check_ptr}() -> (genesis_block_header : BlockHeader):
        alloc_locals
        let (local genesis_hash : Uint256) = felt_to_uint256(
            0x19d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
        )
        let (genesis_merkle_root : Uint256) = felt_to_uint256(
            0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
        )
        let genesis_block_header = BlockHeader(
            version=1,
            prev_block=Uint256(0, 0),
            merkle_root=genesis_merkle_root,
            timestamp=1231006505,
            bits=0x1d00ffff,
            nonce=2083236893,
            hash=genesis_hash,
        )
        return (genesis_block_header)
    end

    func felt_to_uint256{range_check_ptr}(x) -> (res : Uint256):
        let (hi, lo) = split_felt(x)
        return (Uint256(lo, hi))
    end
end
