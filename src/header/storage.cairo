%lang starknet

# Starkware dependencies
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256

from header.model import BlockHeader

# ------
# STORAGE
# ------
@storage_var
func block_header_hash_(block_height : felt) -> (block_header_hash : Uint256):
end

@storage_var
func block_header_(block_header_hash : Uint256) -> (block_header : BlockHeader):
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

    # -----
    # SETTERS
    # -----
    func write_header{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        height : felt, block_header : BlockHeader
    ):
        block_header_hash_.write(height, block_header.hash)
        block_header_.write(block_header.hash, block_header)
        return ()
    end
end
