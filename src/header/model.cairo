# SPDX-License-Identifier: MIT
# Khepri smart contracts written in Cairo v0.1.0 (header/model.cairo)

%lang starknet

# Starkware dependencies
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math import assert_not_zero

struct BlockHeader:
    member version : felt  # 4 bytes
    member prev_block : Uint256  # 32 bytes
    member merkle_root : Uint256  # 32 bytes
    member timestamp : felt  # 4 bytes
    member bits : felt  # 4 bytes
    member nonce : felt  # 4 bytes
    member hash : Uint256  # 32 bytes
end

struct BlockHeaderValidationContext:
    member height : felt
    member block_header : BlockHeader
    member previous_block_header : BlockHeader
end

func assert_block_header{range_check_ptr}(block_header : BlockHeader):
    with_attr error_message("block header is undefined"):
        assert_not_zero(block_header.version)
    end
    return ()
end

func assert_block_header_is_undefined{range_check_ptr}(block_header : BlockHeader):
    with_attr error_message("block header is not undefined"):
        assert 0 = block_header.version
    end
    return ()
end
