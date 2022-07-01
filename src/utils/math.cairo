%lang starknet

from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.math import split_felt
from starkware.cairo.common.uint256 import Uint256, uint256_le
from starkware.cairo.common.bool import TRUE, FALSE
from openzeppelin.security.safemath import SafeUint256

func min{range_check_ptr}(a : felt, b : felt) -> (min : felt):
    let (a_is_le_b) = is_le(a, b)
    return (min=a * a_is_le_b + b * (1 - a_is_le_b))
end

func max{range_check_ptr}(a : felt, b : felt) -> (max : felt):
    let (a_is_le_b) = is_le(a, b)
    return (max=a * (1 - a_is_le_b) + b * a_is_le_b)
end

func clamp{range_check_ptr}(value : felt, min_value : felt, max_value : felt) -> (
    clamped_value : felt
):
    let (clamped_value) = max(value, min_value)
    let (clamped_value) = min(clamped_value, max_value)
    return (clamped_value)
end

func felt_to_Uint256{range_check_ptr}(value : felt) -> (value : Uint256):
    let (high, low) = split_felt(value)
    return (value=Uint256(low=low, high=high))
end

func min_uint256{range_check_ptr}(a : Uint256, b : Uint256) -> (min : Uint256):
    let (a_is_le_b) = uint256_le(a, b)
    if a_is_le_b == TRUE:
        return (min=a)
    end
    return (min=b)
end
