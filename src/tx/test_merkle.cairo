%lang starknet

from starkware.cairo.common.uint256 import Uint256, uint256_eq
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import TRUE, FALSE

from tx.test_utils import test_utils
from tx.merkle_root import build_merkle_root

@view
func test_merkle_root_block01{
    range_check_ptr
}():
    alloc_locals
    local root1 : Uint256
    let (tx : Uint256*, tx_len : felt, root1 : Uint256) = test_utils.load_tx_from_json('./resources/blocks/block1.json')
    let (root2 : Uint256) = build_merkle_root(tx, tx_len)
    let (is_true_root) = uint256_eq(root1, root2)
    assert is_true_root = TRUE
    return ()
end

@view
func test_merkle_root_block170{
    range_check_ptr
}():
    alloc_locals
    local root1 : Uint256
    let (tx : Uint256*, tx_len : felt, root1 : Uint256) = test_utils.load_tx_from_json('./resources/blocks/b170.json')
    let (root2 : Uint256) = build_merkle_root(tx, tx_len)
    let (is_true_root) = uint256_eq(root1, root2)
    assert is_true_root = TRUE
    return ()
end

@view
func test_merkle_root_block746298{
    range_check_ptr
}():
    alloc_locals
    local root1 : Uint256
    let (tx : Uint256*, tx_len : felt, root1 : Uint256) = test_utils.load_tx_from_json('./resources/blocks/b746298.json')
    let (root2 : Uint256) = build_merkle_root(tx, tx_len)
    let (is_true_root) = uint256_eq(root1, root2)
    assert is_true_root = TRUE
    return ()
end