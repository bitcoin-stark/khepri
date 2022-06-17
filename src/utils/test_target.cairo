%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import split_felt
from starkware.cairo.common.uint256 import Uint256, uint256_eq
from starkware.cairo.common.bool import TRUE

from utils.target import decode_target, encode_target, pad, get_bytes_128, _get_bytes_128
from utils.array import arr_eq

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

@view
func test_pad{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    alloc_locals
    let (local arr) = alloc()
    assert arr[0] = 1
    assert arr[1] = 2
    assert arr[2] = 3
    assert arr[3] = 4
    pad(6, 4, arr)
    local res : felt* = new (1, 2, 3, 4, 0, 0)
    arr_eq(arr, 6, res, 6)
    return ()
end

@view
func test_get_bytes_128{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    alloc_locals
    let value = 0x123456789
    let (size, bytes) = get_bytes_128(value)
    local res : felt* = new (89, 67, 45, 23, 01)
    arr_eq(bytes, size, res, size)

    let value = 0
    let (size, bytes) = get_bytes_128(value)
    local res : felt* = new (0)
    arr_eq(bytes, size, res, size)
    let value = 1
    let (size, bytes) = get_bytes_128(value)
    local res : felt* = new (1)
    arr_eq(bytes, size, res, size)

    let (local size, local bytes) = get_bytes_128(0x0004444000077770000)
    local res : felt* = new (44, 44, 00, 00, 77, 77, 00, 00)
    arr_eq(bytes, size, res, size)

    let (local size, local bytes) = get_bytes_128(2 ** 128 - 1)
    local res : felt* = new (255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255)
    arr_eq(bytes, size, res, size)

    let (size) = _get_bytes_128(0x0004444000077770000, bytes + size, size)
    local res : felt* = new (255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 44, 44, 00, 00, 77, 77, 00, 00)
    arr_eq(bytes, size, res, size)

    return ()
end

func felt_to_uint256{range_check_ptr}(x) -> (res : Uint256):
    let (hi, lo) = split_felt(x)
    return (Uint256(lo, hi))
end

struct Target_test_vector:
    member target : Uint256
    member bits : felt
end

func rec_test_targets{range_check_ptr}(len, test_data_ptr : Target_test_vector*):
    if len == 0:
        return ()
    end

    let (bits_computed) = encode_target(test_data_ptr.target)
    assert test_data_ptr.bits = bits_computed
    return rec_test_targets(len - 1, test_data_ptr + Target_test_vector.SIZE)
end

@view
func test_encode_target{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    alloc_locals
    let (local tests : Target_test_vector*) = alloc()

    let (target) = felt_to_uint256(
        0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    )
    assert tests[0] = Target_test_vector(target, 0x1d00ffff)
    let (target) = felt_to_uint256(
        0x00000000FFFF0000000000000000000000000000000000000000000000000000
    )
    assert tests[1] = Target_test_vector(target, 0x1d00ffff)
    let (target) = felt_to_uint256(
        0x00000000d86a0000000000000000000000000000000000000000000000000000
    )
    assert tests[2] = Target_test_vector(target, 0x1d00d86a)
    let (target) = felt_to_uint256(
        0x00000000be710000000000000000000000000000000000000000000000000000
    )
    assert tests[3] = Target_test_vector(target, 0x1d00be71)
    let (target) = felt_to_uint256(
        0x0000000065465700000000000000000000000000000000000000000000000000
    )
    assert tests[4] = Target_test_vector(target, 0x1c654657)
    let (target) = felt_to_uint256(
        0x00000000000e7256000000000000000000000000000000000000000000000000
    )
    assert tests[5] = Target_test_vector(target, 0x1b0e7256)
    let (target) = felt_to_uint256(
        0x0000000000000abbcf0000000000000000000000000000000000000000000000
    )
    assert tests[6] = Target_test_vector(target, 0x1a0abbcf)
    let (target) = felt_to_uint256(
        0x00000000000004fa620000000000000000000000000000000000000000000000
    )
    assert tests[7] = Target_test_vector(target, 0x1a04fa62)
    let (target) = felt_to_uint256(
        0x000000000000000000ff18000000000000000000000000000000000000000000
    )
    assert tests[8] = Target_test_vector(target, 0x1800ff18)
    let (target) = felt_to_uint256(0xc0de000000)
    assert tests[9] = Target_test_vector(target, 0x0600c0de)
    let (target) = felt_to_uint256(0x1234560000)
    assert tests[10] = Target_test_vector(target, 0x05123456)

    rec_test_targets(11, tests)

    return ()
end
