from utils.sha256.sha256 import finalize_sha256, sha256
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

# Computes the SHA256 hash of the given input (up to 55 bytes).
# input should consist of a list of 32-bit integers (each representing 4 bytes, in big endian).
# n_bytes should be the number of input bytes (for example, it should be between 4*input_len - 3 and
# 4*input_len).
# Returns the 256 output bits as 2 128-bit big-endian integers.
func compute_sha256{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
    input : felt*, n_bytes : felt
) -> (output : felt*):
    alloc_locals

    let (local sha256_ptr_start : felt*) = alloc()
    let sha256_ptr = sha256_ptr_start

    let (local output : felt*) = sha256{sha256_ptr=sha256_ptr}(input, n_bytes)
    # TODO: make finalize work
    # finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr)

    return (output)
end
