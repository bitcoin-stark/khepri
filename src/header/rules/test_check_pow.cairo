%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import split_felt
from starkware.cairo.common.uint256 import Uint256, uint256_eq
from starkware.cairo.common.bool import TRUE

from header.library import BlockHeader
from header.rules.check_pow import internal, check_pow

@view
func test_check_pow_verifies_genesis{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}():
    tempvar header : BlockHeader = BlockHeader(
        version=2,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=1231006505,
        bits=0x1d00ffff,
        nonce=0x7c2bac1d,
        hash=Uint256(0x4ff763ae46a2a6c172b3f1b60a8ce26f, 0x000000000019d6689c085ae165831e93)
        )

    check_pow.assert_rule(header)

    return ()
end

@view
func test_target_genesis{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}():
    alloc_locals
    let bits = 0x1d00ffff
    let (local target) = internal.get_target(bits)
    let (hi, lo) = split_felt(0x00000000ffff0000000000000000000000000000000000000000000000000000)
    let (is_eq) = uint256_eq(target, Uint256(lo, hi))
    assert TRUE = is_eq
    return ()
end

@view
func test_target{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}():
    alloc_locals
    let bits = 0x1729d72d
    let (local target) = internal.get_target(bits)
    let (hi, lo) = split_felt(0x00000000000000000029d72d0000000000000000000000000000000000000000)
    let (is_eq) = uint256_eq(target, Uint256(lo, hi))
    assert TRUE = is_eq
    return ()
end
