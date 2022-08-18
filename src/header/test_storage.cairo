%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256

from header.model import BlockHeader, assert_block_header_is_undefined, assert_block_header
from header.storage import storage, block_header_hash_

@view
func test_storage{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    alloc_locals

    let (height) = storage.current_height()
    assert 0 = height

    let (hash) = storage.block_header_hash(height)
    assert Uint256(0, 0) = hash

    let (header) = storage.block_header_by_height(height)
    assert_block_header_is_undefined(header)

    # The first header must be stored using the unsafe function
    storage.unsafe_write_header(
        0,
        BlockHeader(
        version=1,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 1),
        ),
    )

    let (height) = storage.current_height()
    assert 0 = height

    let (hash) = storage.block_header_hash(height)
    assert Uint256(0, 1) = hash

    let (header) = storage.block_header_by_height(height)
    assert_block_header(header)
    assert Uint256(0, 1) = header.hash

    storage.write_header(
        1,
        BlockHeader(
        version=1,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 2),
        ),
    )

    let (height) = storage.current_height()
    assert 1 = height

    let (hash) = storage.block_header_hash(height)
    assert Uint256(0, 2) = hash

    let (header) = storage.block_header_by_height(height)
    assert_block_header(header)
    assert Uint256(0, 2) = header.hash

    storage.write_header(
        2,
        BlockHeader(
        version=1,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 3),
        ),
    )

    let (height) = storage.current_height()
    assert 2 = height

    let (hash) = storage.block_header_hash(height)
    assert Uint256(0, 3) = hash

    let (header) = storage.block_header_by_height(height)
    assert_block_header(header)
    assert Uint256(0, 3) = header.hash

    return ()
end

@view
func test_storage_wrong_height{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    alloc_locals

    storage.unsafe_write_header(
        0,
        BlockHeader(
        version=1,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 1),
        ),
    )

    # wrong height, we pass 0 but it should be 1
    %{ expect_revert(error_message="invalid height") %}
    storage.write_header(
        0,
        BlockHeader(
        version=1,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 2),
        ),
    )
    return ()
end

@view
func test_storage_block_already_stored{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr
}():
    alloc_locals

    storage.unsafe_write_header(
        0,
        BlockHeader(
        version=1,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 1),
        ),
    )

    # Insert block hash without updating current height
    block_header_hash_.write(1, Uint256(0, 2))

    # block at height 1 is already stored
    %{ expect_revert(error_message="block header at height 1 is already stored") %}
    storage.write_header(
        1,
        BlockHeader(
        version=1,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 3),
        ),
    )
    return ()
end

@view
func test_storage_block_hash_already_exists{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr
}():
    alloc_locals

    storage.unsafe_write_header(
        0,
        BlockHeader(
        version=1,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 1),
        ),
    )

    storage.unsafe_write_header(
        1,
        BlockHeader(
        version=1,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 2),
        ),
    )

    # same hash than first block
    %{ expect_revert(error_message="block header with same hash is already stored") %}
    storage.write_header(
        2,
        BlockHeader(
        version=1,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=0,
        bits=0,
        nonce=0,
        hash=Uint256(0, 1),
        ),
    )
    return ()
end
