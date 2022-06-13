# SPDX-License-Identifier: MIT
# Khepri smart contracts written in Cairo v0.1.0 (header/rules/previous_block_hash.cairo)

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256, uint256_eq
from starkware.cairo.common.bool import TRUE

from header.model import BlockHeader, BlockHeaderValidationContext

# ------
# RULE: Previous Block Hash
# Description: Previous block hash is a reference to the hash of the previous (parent) block in the chain
# ------
namespace previous_block_hash:
    # This function reverts if the previous block hash is different from the one stored
    func assert_rule{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        ctx : BlockHeaderValidationContext
    ):
        alloc_locals
        let prev_block_header_hash = ctx.previous_block_header.hash
        
        with_attr error_message("[rule] Previous Block Hash: previous block header hash reference is invalid"):
            internal.assert_hash_equal(ctx.block_header.prev_block, prev_block_header_hash)
        end
        return ()
    end

    func on_block_accepted{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        ctx : BlockHeaderValidationContext
    ):
        return ()
    end
end

# ------
# INTERNAL
# ------
namespace internal:
    func assert_hash_equal{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        hash_1: Uint256, hash_2: Uint256
    ):
        let (is_eq) = uint256_eq(hash_1, hash_2)
        assert is_eq = TRUE
        return ()
    end
end
