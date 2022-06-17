from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import unsigned_div_rem, split_felt
from starkware.cairo.common.pow import pow
from starkware.cairo.common.math_cmp import is_le

func decode_target{range_check_ptr}(bits : felt) -> (res : Uint256):
    alloc_locals
    let (exponent, local mantissa) = unsigned_div_rem(bits, 2 ** 24)
    let (exp) = pow(256, exponent - 3)
    let tmp = mantissa * exp
    let res_target = split_felt(tmp)
    return (Uint256(res_target.low, res_target.high))
end

func encode_target{range_check_ptr}(target : Uint256) -> (bits):
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
    if is_neg == 1:
        let (adj_compact, _) = unsigned_div_rem(compact, 256)
        return (adj_compact + (size + 1) * 2 ** 24)
    else:
        return (compact + size * 2 ** 24)
    end
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
    if bytes_len * size == 0:
        return (acc)
    end

    return get_truncated_target(size - 1, bytes_len - 1, bytes, acc * 256 + bytes[bytes_len - 1])
end
