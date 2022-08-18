%lang starknet

# Starkware dependencies
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256, uint256_eq

from header.model import BlockHeader, assert_block_header_is_undefined

# ------
# STORAGE
# ------
@storage_var
func block_header_hash_(block_height : felt) -> (block_header_hash : Uint256):
end

@storage_var
func block_header_(block_header_hash : Uint256) -> (block_header : BlockHeader):
end

@storage_var
func current_height_() -> (last_block_height : felt):
end

namespace storage:
    # -----
    # GETTERS
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

    func current_height{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
        height : felt
    ):
        let (height) = current_height_.read()
        return (height)
    end

    # -----
    # SETTERS
    # -----
    func write_header{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        height : felt, block_header : BlockHeader
    ):
        alloc_locals

        let (last_height) = current_height()
        with_attr error_message("invalid height"):
            assert height = last_height + 1
        end

        let (existing_hash : Uint256) = block_header_hash(height)
        let (existing_hash_is_zero) = uint256_eq(existing_hash, Uint256(0, 0))
        with_attr error_message("block header at height {height} is already stored"):
            assert existing_hash_is_zero = 1
        end

        let (existing_block_header : BlockHeader) = block_header_by_hash(block_header.hash)
        with_attr error_message("block header with same hash is already stored"):
            assert_block_header_is_undefined(existing_block_header)
        end

        unsafe_write_header(height, block_header)
        return ()
    end

    # This function should only be used to store the genesis block
    func unsafe_write_header{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        height : felt, block_header : BlockHeader
    ):
        current_height_.write(height)
        block_header_hash_.write(height, block_header.hash)
        block_header_.write(block_header.hash, block_header)
        return ()
    end
end
