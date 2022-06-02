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
    member previous : felt*  # 32 bytes
    member merkle_root : felt*  # 32 bytes
    member time : felt  # 4 bytes
    member bits : felt  # 4 bytes
    member nonce : felt  # 4 bytes
    member data : felt*
end

# ------
# STORAGE
# ------
@storage_var
func block_header_lo(number : felt) -> (hash_lo : felt):
end

@storage_var
func block_header_hi(number : felt) -> (hash_hi : felt):
end

namespace BlockHeaderVerifier:
    # -----
    # VIEWS
    # -----

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
            let (lo) = block_header_lo.read(height - 1)
            let (hi) = block_header_hi.read(height - 1)
            assert prev_hash[0] = lo
            assert prev_hash[1] = hi
            tempvar syscall_ptr = syscall_ptr
            tempvar range_check_ptr = range_check_ptr
            tempvar pedersen_ptr = pedersen_ptr
        end
        tempvar syscall_ptr = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
        tempvar pedersen_ptr = pedersen_ptr
        # Verify provided block header
        let (local header) = prepare_header(data)
        let (local block_hash) = process_header(header, prev_hash)

        local syscall_ptr : felt* = syscall_ptr
        # Write current header to storage
        block_header_lo.write(height, block_hash[0])
        block_header_hi.write(height, block_hash[1])

        return ()
    end

    # Assuming data is the header packed as an array of 4 bytes
    func prepare_header{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(data : felt*) -> (
        res : BlockHeader
    ):
        alloc_locals
        let (previous : felt*) = alloc()
        let (merkle_root : felt*) = alloc()
        let (version) = swap_endianness_64(data[0], 4)

        let (prev0) = swap_endianness_64(data[7] * 2 ** 32 + data[8], 8)
        let (prev1) = swap_endianness_64(data[5] * 2 ** 32 + data[6], 8)
        let (prev2) = swap_endianness_64(data[3] * 2 ** 32 + data[4], 8)
        let (prev3) = swap_endianness_64(data[1] * 2 ** 32 + data[2], 8)
        assert previous[0] = prev0
        assert previous[1] = prev1
        assert previous[2] = prev2
        assert previous[3] = prev3

        let (merkle0) = swap_endianness_64(data[15] * 2 ** 32 + data[16], 8)
        let (merkle1) = swap_endianness_64(data[13] * 2 ** 32 + data[14], 8)
        let (merkle2) = swap_endianness_64(data[11] * 2 ** 32 + data[12], 8)
        let (merkle3) = swap_endianness_64(data[09] * 2 ** 32 + data[10], 8)

        assert merkle_root[0] = merkle0
        assert merkle_root[1] = merkle1
        assert merkle_root[2] = merkle2
        assert merkle_root[3] = merkle3
        let (time) = swap_endianness_64(data[17], 4)
        let (bits) = swap_endianness_64(data[18], 4)
        let (nonce) = swap_endianness_64(data[19], 4)

        local header : BlockHeader = BlockHeader(version, previous, merkle_root, time, bits, nonce, data)
        return (header)
    end

    func process_header{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
        header : BlockHeader, prev_header_hash : felt*
    ) -> (current_header_hash : felt*):
        alloc_locals

        # WIP: Compute SHA256 of serialized header (big endian)
        let header_bytes = header.data
        let (tmp1, tmp2) = compute_sha256(header_bytes, 80)
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

        let (local curr_header_hash : felt*) = alloc()
        assert curr_header_hash[0] = out1
        assert curr_header_hash[1] = out2

        # Verify previous block header with provided hash
        let (prev_hash_eq) = arr_eq(prev_header_hash, 2, curr_header_hash, 2)
        # assert prev_hash_eq = 1

        # TODO: Verify difficulty target
        # - Parse bits into target and convert to Uint256

        let (target) = get_target(header.bits)
        %{
            print(hex(ids.out1), hex(ids.out2))
            print(hex(ids.target.low), hex(ids.target.high))
        %}
        let hash = Uint256(out1, out2)
        let (res) = uint256_lt(hash, target)
        assert res = 1

        # TODO: Verify difficulty target interval using timestamps
        # TODO: Return current header hash

        return (curr_header_hash)
    end
end
