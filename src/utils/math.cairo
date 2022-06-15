%lang starknet

from starkware.cairo.common.math import split_felt
from starkware.cairo.common.uint256 import Uint256

func felt_to_Uint256{range_check_ptr}(value : felt) -> (value : Uint256):
    let (high, low) = split_felt(value)
    return (value=Uint256(low=low, high=high))
end
