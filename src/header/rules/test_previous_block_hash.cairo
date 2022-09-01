%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.bool import TRUE

from header.model import BlockHeader, BlockHeaderValidationContext
from header.rules.previous_block_hash import previous_block_hash
from header.test_utils import test_utils

@view
func test_previous_block_hash_nominal_case{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}():
    tempvar header : BlockHeader = BlockHeader(
        version=2,
        prev_block=Uint256(0x4ff763ae46a2a6c172b3f1b60a8ce26f, 0x000000000019d6689c085ae165831e93),
        merkle_root=Uint256(0, 0),
        timestamp=1231006505,
        bits=0x1d00ffff,
        nonce=0x7c2bac1d,
        hash=Uint256(0x4ff763ae46a2a6c172b3f1b60a8ce26f, 0x000000000019d6689c085ae165831e93)
        )
    tempvar previous_block_header : BlockHeader = BlockHeader(
        version=2,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=1231006505,
        bits=0x1d00ffff,
        nonce=0x7c2bac1d,
        hash=Uint256(0x4ff763ae46a2a6c172b3f1b60a8ce26f, 0x000000000019d6689c085ae165831e93)
        )

    tempvar ctx : BlockHeaderValidationContext = BlockHeaderValidationContext(
        height=1, block_header=header, previous_block_header=previous_block_header)

    previous_block_hash.assert_rule(ctx)

    return ()
end

@view
func test_previous_block_hash_invalid{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}():
    tempvar header : BlockHeader = BlockHeader(
        version=2,
        prev_block=Uint256(41, 42),
        merkle_root=Uint256(0, 0),
        timestamp=1231006505,
        bits=0x1d00ffff,
        nonce=0x7c2bac1d,
        hash=Uint256(0x4ff763ae46a2a6c172b3f1b60a8ce26f, 0x000000000019d6689c085ae165831e93)
        )
    tempvar previous_block_header : BlockHeader = BlockHeader(
        version=2,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=1231006505,
        bits=0x1d00ffff,
        nonce=0x7c2bac1d,
        hash=Uint256(42, 42)
        )

    tempvar ctx : BlockHeaderValidationContext = BlockHeaderValidationContext(
        height=1, block_header=header, previous_block_header=previous_block_header)
    %{ expect_revert(error_message="[rule] Previous Block Hash: previous block header hash reference is invalid") %}
    previous_block_hash.assert_rule(ctx)

    return ()
end
