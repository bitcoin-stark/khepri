%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256

from header.model import BlockHeader, assert_block_header_is_undefined, assert_block_header

@view
func test_assert_block_header{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    alloc_locals

    let header : BlockHeader = BlockHeader(
        version=1,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 0),
    )

    assert_block_header(header)

    let header : BlockHeader = BlockHeader(
        version=0,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 0),
    )

    %{ expect_revert(error_message="block header is undefined") %}
    assert_block_header(header)

    return ()
end

@view
func test_assert_block_header_is_undefined{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr
}():
    alloc_locals

    let header : BlockHeader = BlockHeader(
        version=0,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 0),
    )

    assert_block_header_is_undefined(header)

    let header : BlockHeader = BlockHeader(
        version=1,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 0),
    )

    %{ expect_revert(error_message="block header is not undefined") %}
    assert_block_header_is_undefined(header)

    return ()
end
