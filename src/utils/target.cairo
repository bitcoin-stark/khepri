from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import unsigned_div_rem, split_felt
from starkware.cairo.common.pow import pow

func decode_target{range_check_ptr}(bits : felt) -> (res : Uint256):
    alloc_locals
    let (exponent, local mantissa) = unsigned_div_rem(bits, 2 ** 24)
    let (exp) = pow(256, exponent - 3)
    let tmp = mantissa * exp
    let res_target = split_felt(tmp)
    return (Uint256(res_target.low, res_target.high))
end

func encode_target{range_check_ptr}(val : Uint256) -> (bits : felt):
    return (0)
end
