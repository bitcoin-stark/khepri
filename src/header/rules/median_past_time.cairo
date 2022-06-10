# SPDX-License-Identifier: MIT

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_lt
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.bool import TRUE, FALSE

from header.library import BlockHeader

# ------
# CONSTANTS
# ------
const TIMESTAMP_COUNT = 11
const TIMESTAMP_MEDIAN_INDEX = 6

# ------
# STRUCTS
# ------
struct Timestamps:
    member t1 : felt
    member t2 : felt
    member t3 : felt
    member t4 : felt
    member t5 : felt
    member t6 : felt
    member t7 : felt
    member t8 : felt
    member t9 : felt
    member t10 : felt
    member t11 : felt
end

# ------
# STORAGE
# ------
@storage_var
func last_11_timestamps() -> (timestamps : Timestamps):
end

# ------
# RULE: Median Past Time
# Description: A timestamp is accepted as valid if it is greater than the median timestamp of previous 11 blocks
# Ref: https://en.bitcoin.it/wiki/Block_timestamp, https://en.bitcoin.it/wiki/BIP_0113
# ------
namespace median_past_time:
    # This function reverts if the timestamp of the given header if lower than or equal to the median timestamp of previous 11 blocks
    func assert_rule{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        header : BlockHeader
    ):
        alloc_locals
        let (timestamps : Timestamps) = last_11_timestamps.read()
        let (local timestamp_median) = internal.compute_timestamps_median(timestamps)
        local block_timestamp = header.time

        with_attr error_message(
                "[rule] Median Past Time: block timestamp ({block_timestamp}) must be higher than the median ({timestamp_median}) of the previous 11 block timestamps"):
            assert_lt(timestamp_median, block_timestamp)
        end
        return ()
    end

    # This function must be called when a block is accepted so that the list of the last 11 timestamps is updated
    func on_block_accepted{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        header : BlockHeader
    ):
        let (timestamps : Timestamps) = last_11_timestamps.read()
        let new_timestamps : Timestamps = Timestamps(
            timestamps.t2,
            timestamps.t3,
            timestamps.t4,
            timestamps.t5,
            timestamps.t6,
            timestamps.t7,
            timestamps.t8,
            timestamps.t9,
            timestamps.t10,
            timestamps.t11,
            header.time,
        )
        last_11_timestamps.write(new_timestamps)
        return ()
    end
end

# ------
# INTERNAL
# ------
namespace internal:
    func compute_timestamps_median{range_check_ptr}(timestamps : Timestamps) -> (
        median_value : felt
    ):
        tempvar timestamp_array : felt* = new (
            timestamps.t1,
            timestamps.t2,
            timestamps.t3,
            timestamps.t4,
            timestamps.t5,
            timestamps.t6,
            timestamps.t7,
            timestamps.t8,
            timestamps.t9,
            timestamps.t10,
            timestamps.t11)

        let (sorted_timestamp_array : felt*) = sort_unsigned(TIMESTAMP_COUNT, timestamp_array)
        return (median_value=sorted_timestamp_array[TIMESTAMP_MEDIAN_INDEX])
    end

    # Implement a naive sort algorithm for an array of felts without using any hint.
    # Complexity is O(n^2) but this is not a problem as it is used to sort an array of only 11 elements.
    func sort_unsigned{range_check_ptr}(arr_len : felt, arr : felt*) -> (sorted_array : felt*):
        alloc_locals

        let (local sorted_array : felt*) = alloc()
        sort_unsigned_loop(arr_len, arr, sorted_array)
        return (sorted_array)
    end

    func sort_unsigned_loop{range_check_ptr}(arr_len : felt, arr : felt*, sorted_array : felt*):
        if arr_len == 0:
            return ()
        end

        # find the lowest element out of remaining elements
        let (lowest_element_index, lowest_element) = internal.find_lowest_element(arr_len, arr)

        # push the lowest element to the sorted array
        assert sorted_array[0] = lowest_element

        # remove the lowest element from the remaining elements
        let (arr : felt*) = copy_array_without_index(arr_len, arr, lowest_element_index)

        sort_unsigned_loop(arr_len - 1, arr, sorted_array + 1)
        return ()
    end

    func find_lowest_element{range_check_ptr}(arr_len : felt, arr : felt*) -> (
        lowest_element_index : felt, lowest_element : felt
    ):
        return find_lowest_element_loop(0, arr_len, arr, 0)
    end

    func find_lowest_element_loop{range_check_ptr}(
        index : felt, arr_len : felt, arr : felt*, lowest_element_index : felt
    ) -> (lowest_element_index : felt, lowest_element : felt):
        if index == arr_len:
            return (
                lowest_element_index=lowest_element_index, lowest_element=arr[lowest_element_index]
            )
        end

        let (is_lower) = is_le(arr[index], arr[lowest_element_index])
        let new_lowest_element_index = index * is_lower + lowest_element_index * (1 - is_lower)

        return find_lowest_element_loop(index + 1, arr_len, arr, new_lowest_element_index)
    end

    func copy_array_without_index{range_check_ptr}(
        arr_len : felt, arr : felt*, removed_index : felt
    ) -> (new_arr : felt*):
        alloc_locals

        let (local new_arr : felt*) = alloc()
        copy_array_without_index_loop(0, arr_len, arr, removed_index, 0, new_arr)
        return (new_arr)
    end

    func copy_array_without_index_loop{range_check_ptr}(
        index : felt,
        arr_len : felt,
        arr : felt*,
        removed_index : felt,
        new_index : felt,
        new_arr : felt*,
    ):
        if index == arr_len:
            return ()
        end

        if index == removed_index:
            copy_array_without_index_loop(
                index + 1, arr_len, arr, removed_index, new_index, new_arr
            )
            return ()
        end

        assert new_arr[new_index] = arr[index]

        copy_array_without_index_loop(
            index + 1, arr_len, arr, removed_index, new_index + 1, new_arr
        )
        return ()
    end
end
