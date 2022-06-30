%lang starknet

from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import unsigned_div_rem, split_felt, assert_lt
from starkware.cairo.common.pow import pow
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.bool import TRUE, FALSE

#
# The "compact" format is a representation of a whole
# number N using an unsigned 32bit number similar to a
# floating point format.
# The most significant 8 bits are the unsigned exponent of base 256.
# This exponent can be thought of as "number of bytes of N".
# The lower 23 bits are the mantissa.
# Bit number 24 (0x800000) represents the sign of N.
# N = (-1^sign) * mantissa * 256^(exponent-3)
#
# Satoshi's original implementation used BN_bn2mpi() and BN_mpi2bn().
# MPI uses the most significant bit of the first byte as sign.
# Thus 0x1234560000 is compact (0x05123456)
# and  0xc0de000000 is compact (0x0600c0de)
#
# Bitcoin only uses this "compact" format for encoding difficulty
# targets, which are unsigned 256bit quantities.  Thus, all the
# complexities of the sign bit and using base 256 are probably an
# implementation accident.
#
func decode_target{range_check_ptr}(bits : felt) -> (res : Uint256):
    let (res : Uint256, negative : felt, overflow : felt) = internal.decode_target(bits)
    assert FALSE = negative
    assert FALSE = overflow
    return (res)
end

func encode_target{range_check_ptr}(target : Uint256) -> (bits):
    return internal.encode_target(target, FALSE)
end

namespace internal:
    func decode_target{range_check_ptr}(bits : felt) -> (
        res : Uint256, negative : felt, overflow : felt
    ):
        alloc_locals
        let (exponent, rest) = unsigned_div_rem(bits, 2 ** 24)
        let (is_neg, local mantissa) = unsigned_div_rem(rest, 2 ** 23)

        # Check overflow
        let (exponent_is_gt_34) = is_le(35, exponent)
        if exponent_is_gt_34 == TRUE:
            return (Uint256(0, 0), is_neg, TRUE)
        end
        let (exponent_is_gt_33) = is_le(34, exponent)
        let (mantissa_is_gt_0xff) = is_le(0xff + 1, mantissa)
        if exponent_is_gt_33 * mantissa_is_gt_0xff == TRUE:
            return (Uint256(0, 0), is_neg, TRUE)
        end
        let (exponent_is_gt_32) = is_le(33, exponent)
        let (mantissa_is_gt_0xffff) = is_le(0xffff + 1, mantissa)
        if exponent_is_gt_32 * mantissa_is_gt_0xffff == TRUE:
            return (Uint256(0, 0), is_neg, TRUE)
        end

        let (exponent_is_le_3) = is_le(exponent, 3)
        if exponent_is_le_3 == TRUE:
            let (exp) = pow(256, 3 - exponent)
            let (tmp, _) = unsigned_div_rem(mantissa, exp)
            let res_target = split_felt(tmp)
            return (Uint256(res_target.low, res_target.high), is_neg, FALSE)
        end

        let (exp) = pow(256, exponent - 3)
        let tmp = mantissa * exp
        let res_target = split_felt(tmp)
        return (Uint256(res_target.low, res_target.high), is_neg, FALSE)
    end

    func encode_target{range_check_ptr}(target : Uint256, negative : felt) -> (bits):
        alloc_locals
        local bytes : felt*
        local size

        let (size_lo, bytes_lo) = get_bytes_128(target.low)
        assert bytes = bytes_lo

        if target.high == 0:
            assert size = size_lo
            tempvar range_check_ptr = range_check_ptr
        else:
            pad(16, size_lo, bytes_lo)
            let (size_hi) = _get_bytes_128(target.high, bytes_lo + 16, 16)
            assert size = size_hi
            tempvar range_check_ptr = range_check_ptr
        end
        tempvar range_check_ptr = range_check_ptr

        let (local compact) = get_truncated_target(3, size, bytes, 0)

        let (is_neg) = is_le(0x00800000, compact)

        # Assert the size doesn't overflow
        assert_lt(size + is_neg, 256)

        local bits
        if is_neg == 1:
            let (adj_compact, _) = unsigned_div_rem(compact, 256)
            assert bits = adj_compact + (size + 1) * 2 ** 24
            tempvar range_check_ptr = range_check_ptr
        else:
            assert bits = compact + size * 2 ** 24
            tempvar range_check_ptr = range_check_ptr
        end
        let bits = bits + negative * 2 ** 24
        return (bits=bits)
    end

    func pad(pad_to : felt, len : felt, bytes : felt*):
        if pad_to == 0:
            return ()
        end

        if len == 0:
            assert [bytes] = 0
            return pad(pad_to - 1, 0, bytes + 1)
        end
        return pad(pad_to - 1, len - 1, bytes + 1)
    end

    func _get_bytes_128{range_check_ptr : felt}(x, bytes : felt*, bytes_len : felt) -> (
        bytes_len : felt
    ):
        if x == 0:
            return (0)
        end
        let (q, r) = unsigned_div_rem(x, 256)
        [bytes] = r
        if q == 0:
            return (bytes_len + 1)
        else:
            return _get_bytes_128(q, bytes + 1, bytes_len + 1)
        end
    end

    func get_bytes_128{range_check_ptr}(x) -> (bytes_len, bytes : felt*):
        alloc_locals
        let (local bytes : felt*) = alloc()
        let (size) = _get_bytes_128(x, bytes, 0)
        return (size, bytes)
    end

    func get_truncated_target(size, bytes_len, bytes : felt*, acc : felt) -> (res):
        if size == 0:
            return (acc)
        end
        if bytes_len == 0:
            return get_truncated_target(size - 1, bytes_len, bytes, acc * 256)
        end

        return get_truncated_target(
            size - 1, bytes_len - 1, bytes, acc * 256 + bytes[bytes_len - 1]
        )
    end
end
