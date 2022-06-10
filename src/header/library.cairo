# SPDX-License-Identifier: MIT
# Khepri smart contracts written in Cairo v0.1.0 (header/library.cairo)

%lang starknet
# Starkware dependencies
from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256, uint256_lt
# Open Zeppelin dependencies
from openzeppelin.access.ownable import Ownable

from utils.common import swap_endianness_64, get_target, prepare_hash
from utils.sha256.sha256_contract import compute_sha256
from utils.array import arr_eq

struct BlockHeader:
    member version : felt  # 4 bytes
    member previous : Uint256  # 32 bytes
    member merkle_root : Uint256  # 32 bytes
    member time : felt  # 4 bytes
    member bits : felt  # 4 bytes
    member nonce : felt  # 4 bytes
    member hash : Uint256  # 32 bytes
end

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

    func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        owner : felt
    ):
        Ownable.initializer(owner)
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

        # Retrieve previous block header hash (or zero hash if genesis)
        let (local prev_hash : felt*) = alloc()
        if height == 0:
            assert prev_hash[0] = 0
            assert prev_hash[1] = 0
            tempvar syscall_ptr = syscall_ptr
            tempvar range_check_ptr = range_check_ptr
            tempvar pedersen_ptr = pedersen_ptr
        else:
            let (block_header_hash) = block_header_hash_.read(height - 1)
            assert prev_hash[0] = block_header_hash.low
            assert prev_hash[1] = block_header_hash.high
            tempvar syscall_ptr = syscall_ptr
            tempvar range_check_ptr = range_check_ptr
            tempvar pedersen_ptr = pedersen_ptr
        end
        tempvar syscall_ptr = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
        tempvar pedersen_ptr = pedersen_ptr
        # Verify provided block header
        let (local header) = prepare_header(data)
        process_header(header, prev_hash)

        local syscall_ptr : felt* = syscall_ptr
        # Write current header to storage
        block_header_hash_.write(height, header.hash)
        block_header_.write(header.hash, header)
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

        local previous : Uint256 = Uint256(
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
        let (time) = swap_endianness_64(data[17], 4)
        let (bits) = swap_endianness_64(data[18], 4)
        let (nonce) = swap_endianness_64(data[19], 4)

        # WIP: Compute SHA256 of serialized header (big endian)
        let (tmp1, tmp2) = compute_sha256(data, 80)
        let (spliced_tmp) = prepare_hash(Uint256(tmp1, tmp2))
        let (tmpout1, tmpout2) = compute_sha256(spliced_tmp, 32)  # Second hash
        # TODO Cairo way to do endianness
        local out1
        local out2
        %{
            data = f'{ids.tmpout1:032x}{ids.tmpout2:032x}'
            data = "".join(data[::-1])
            ids.out2 = int(data[:32], 16)
            ids.out1 = int(data[32:], 16)
        %}
        local header_hash : Uint256 = Uint256(
            out1,
            out2
            )

        local header : BlockHeader = BlockHeader(version, previous, merkle_root, time, bits, nonce, header_hash)
        return (header)
    end

    func process_header{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
        header : BlockHeader, prev_header_hash : felt*
    ):
        # TODO: invoke consensus rules checks
        return ()
    end
end
