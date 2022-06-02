# SPDX-License-Identifier: MIT
# Khepri smart contracts written in Cairo v0.1.0 (block_header_verifier.cairo)

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin

from header.library import BlockHeaderVerifier

# ------
# CONSTRUCTOR
# ------

@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(owner : felt):
    return BlockHeaderVerifier.constructor(owner)
end

# -----
# VIEWS
# -----

# ------------------
# EXTERNAL FUNCTIONS
# ------------------

@external
func process_block{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, bitwise_ptr : BitwiseBuiltin*, range_check_ptr
}(height : felt, data_len : felt, data : felt*):
    return BlockHeaderVerifier.process_block(height, data_len, data)
end
