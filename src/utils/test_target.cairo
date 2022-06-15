%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import split_felt
from starkware.cairo.common.uint256 import Uint256, uint256_eq
from starkware.cairo.common.bool import TRUE, FALSE

from utils.target import decode_target, encode_target, pad, get_bytes_128, _get_bytes_128
from utils.array import arr_eq
from utils.math import felt_to_Uint256

@view
func test_target_genesis{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}():
    alloc_locals
    let bits = 0x1d00ffff
    let (local target, overflow : felt) = decode_target(bits)
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
    let (local target, overflow : felt) = decode_target(bits)
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
end

# Test cases taken from https://github.com/bitcoin/bitcoin/blob/master/src/test/arith_uint256_tests.cpp#L406
# Test cases about negative bits have been removed.
@view
func test_encode_decode_target{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}():
    alloc_locals
    test_internal.test_encode_decode_target(0, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x00123456, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x01003456, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x02000056, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x03000000, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x04000000, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x00923456, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x01803456, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x02800056, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x03800000, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x04800000, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x01003456, 0, FALSE, 0)

    test_internal.test_encode_decode_target(0x01123456, 0x00000012, FALSE, 0x01120000)
    test_internal.test_encode_decode_target(0x02123456, 0x00001234, FALSE, 0x02123400)
    test_internal.test_encode_decode_target(0x03123456, 0x00123456, FALSE, 0x03123456)
    test_internal.test_encode_decode_target(0x04123456, 0x12345600, FALSE, 0x04123456)
    test_internal.test_encode_decode_target(0x05009234, 0x92340000, FALSE, 0x05009234)

    test_internal.test_encode_decode_target(
        0x20123456,
        0x1234560000000000000000000000000000000000000000000000000000000000,
        FALSE,
        0x20123456,
    )

    test_internal.test_encode_decode_target(0xff123456, 0, TRUE, 0)

    # Make sure that we don't generate compacts with the 0x00800000 bit set
    let (local target0x80 : Uint256) = felt_to_Uint256(0x80)
    let (local bits) = encode_target(target0x80)
    with_attr error_message("For target 0x80, expected bits to be 0x02008000U, got {bits}"):
        assert 0x02008000 = bits
    end

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

namespace test_internal:
    func test_encode_decode_target{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        bits : felt,
        expected_decoded_target : felt,
        expected_overflow : felt,
        expected_reencoded_bits : felt,
    ):
        alloc_locals
        let (local uint256_expected_decoded_target : Uint256) = felt_to_Uint256(
            expected_decoded_target
        )
        test_encode_decode_target_Uint256(
            bits, uint256_expected_decoded_target, expected_overflow, expected_reencoded_bits
        )
        return ()
    end

    func test_encode_decode_target_Uint256{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        bits : felt,
        expected_decoded_target : Uint256,
        expected_overflow : felt,
        expected_reencoded_bits : felt,
    ):
        alloc_locals
        let (local decoded_target : Uint256, overflow : felt) = decode_target(bits)

        with_attr error_message(
                "For target {target}, expected overflow to be {expected_overflow}, got {overflow}"):
            assert expected_overflow = overflow
        end
        if overflow == TRUE:
            return ()
        end

        let (decoded_are_equal) = uint256_eq(decoded_target, expected_decoded_target)

        with_attr error_message(
                "For target {target}, expected decoded target to be {expected_decoded_target}, got {decoded_target}"):
            assert decoded_are_equal = TRUE
        end

        let (local reencoded_bits : felt) = encode_target(decoded_target)

        with_attr error_message(
                "For target {target}, expected reencoded bits to be {expected_reencoded_bits}, got {reencoded_bits}"):
            assert expected_reencoded_bits = reencoded_bits
        end

        return ()
    end
end
