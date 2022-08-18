# SPDX-License-Identifier: MIT
# Khepri smart contracts written in Cairo v0.1.0 (block_header_verifier.cairo)

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256

from header.model import BlockHeader
from header.library import BlockHeaderVerifier
from header.storage import storage

# ------
# CONSTRUCTOR
# ------

@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    return BlockHeaderVerifier.constructor()
end

# -----
# VIEWS
# -----

@view
func block_header_hash{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    block_height
) -> (block_header_hash : Uint256):
    return storage.block_header_hash(block_height)
end

@view
func block_header_by_hash{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    block_header_hash : Uint256
) -> (block_header : BlockHeader):
    return storage.block_header_by_hash(block_header_hash)
end

@view
func block_header_by_height{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    block_height
) -> (block_header : BlockHeader):
    return storage.block_header_by_height(block_height)
end

# ------------------
# EXTERNAL FUNCTIONS
# ------------------

@external
func process_block{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, bitwise_ptr : BitwiseBuiltin*, range_check_ptr
}(data_len : felt, data : felt*):
    return BlockHeaderVerifier.process_block(data_len, data)
end
