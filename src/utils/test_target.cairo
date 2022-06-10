%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import split_felt
from starkware.cairo.common.uint256 import Uint256, uint256_eq
from starkware.cairo.common.bool import TRUE

from utils.target import decode_target, encode_target

@view
func test_target_genesis{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}():
    alloc_locals
    let bits = 0x1d00ffff
    let (local target) = decode_target(bits)
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
    let (local target) = decode_target(bits)
    let (hi, lo) = split_felt(0x00000000000000000029d72d0000000000000000000000000000000000000000)
    let (is_eq) = uint256_eq(target, Uint256(lo, hi))
    assert TRUE = is_eq
    return ()
end
