%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256

from header.model import BlockHeaderValidationContext, BlockHeader
from header.library import BlockHeaderVerifier, internal
from header.test_utils import test_utils

@view
func test_process_block{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}():
    alloc_locals

    let (header0) = test_utils.load_header_from_json('./resources/blocks/block0.json')

    let header1 : BlockHeader = BlockHeader(
        version=1,
        prev_block=Uint256(low=0x4ff763ae46a2a6c172b3f1b60a8ce26f, high=0x000000000019d6689c085ae165831e93),
        merkle_root=Uint256(low=0x6714ee1f0e68bebb44a74b1efd512098, high=0x0e3e2357e806b6cdb1f70b54c3a3a17b),
        timestamp=1231469665,
        bits=0x1d00ffff,
        nonce=2573394689,
        hash=Uint256(low=0x75428afc90947ee320161bbf18eb6048, high=0x00000000839a8e6886ab5951d76f4114),
    )
    let ctx = BlockHeaderValidationContext(
        height=1, block_header=header1, previous_block_header=header0
    )

    internal.process_header(ctx)

    return ()
end
