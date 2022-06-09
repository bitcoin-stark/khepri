%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc

from header.library import BlockHeader
from header.rules.median_past_time import (
    internal,
    Timestamps,
    last_11_timestamps,
    assert_median_past_time,
    on_block_accepted,
)

@view
func test_assert_median_past_time_doesnt_revert_when_timestamp_is_higher_than_median{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr
}():
    # median of timestamps is 8
    let timestamps : Timestamps = Timestamps(10, 16, 8, 0, 3, 3, 7, 20, 0, 4, 10)
    last_11_timestamps.write(timestamps)

    tempvar header : BlockHeader = BlockHeader(
        version=2, previous=new (), merkle_root=new (), time=9, bits=10, nonce=10, data=new ()
        )

    assert_median_past_time(header)

    return ()
end

@view
func test_assert_median_past_time_reverts_when_timestamp_is_lower_than_median{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr
}():
    # median of timestamps is 8
    let timestamps : Timestamps = Timestamps(10, 16, 8, 0, 3, 3, 7, 20, 0, 4, 10)
    last_11_timestamps.write(timestamps)

    tempvar header : BlockHeader = BlockHeader(
        version=2, previous=new (), merkle_root=new (), time=7, bits=10, nonce=10, data=new ()
        )

    %{ expect_revert(error_message="[rule] Median Past Time: block timestamp (7) must be higher than the median (8) of the previous 11 block timestamps") %}
    assert_median_past_time(header)

    return ()
end

@view
func test_assert_median_past_time_reverts_when_timestamp_equals_median{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr
}():
    # median of timestamps is 8
    let timestamps : Timestamps = Timestamps(10, 16, 8, 0, 3, 3, 7, 20, 0, 4, 10)
    last_11_timestamps.write(timestamps)

    tempvar header : BlockHeader = BlockHeader(
        version=2, previous=new (), merkle_root=new (), time=8, bits=10, nonce=10, data=new ()
        )

    %{ expect_revert(error_message="[rule] Median Past Time: block timestamp (8) must be higher than the median (8) of the previous 11 block timestamps") %}
    assert_median_past_time(header)

    return ()
end

@view
func test_on_block_accepted{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    # median of timestamps is 8
    let timestamps : Timestamps = Timestamps(10, 16, 8, 0, 3, 3, 7, 20, 0, 4, 10)
    last_11_timestamps.write(timestamps)

    tempvar header : BlockHeader = BlockHeader(
        version=2, previous=new (), merkle_root=new (), time=9, bits=10, nonce=10, data=new ()
        )

    on_block_accepted(header)

    let (timestamps : Timestamps) = last_11_timestamps.read()
    assert timestamps = Timestamps(16, 8, 0, 3, 3, 7, 20, 0, 4, 10, 9)
    return ()
end

@view
func test_compute_timestamps_median{range_check_ptr}():
    let timestamps : Timestamps = Timestamps(10, 16, 8, 0, 3, 3, 7, 20, 0, 4, 10)

    let (median) = internal.compute_timestamps_median(timestamps)

    assert median = 8

    return ()
end

@view
func test_find_lowest_element{range_check_ptr}():
    let (lowest_element_index, lowest_element) = internal.find_lowest_element(4, new (10, 4, 3, 7))

    assert lowest_element_index = 2
    assert lowest_element = 3

    return ()
end

@view
func test_sort_unsigned{range_check_ptr}():
    let (sorted_array : felt*) = internal.sort_unsigned(4, new (10, 4, 3, 7))

    assert 3 = sorted_array[0]
    assert 4 = sorted_array[1]
    assert 7 = sorted_array[2]
    assert 10 = sorted_array[3]

    return ()
end

@view
func test_sort_unsigned_with_equal_values{range_check_ptr}():
    let (sorted_array : felt*) = internal.sort_unsigned(
        11, new (10, 16, 8, 0, 3, 3, 7, 20, 0, 4, 10)
    )

    assert 0 = sorted_array[0]
    assert 0 = sorted_array[1]
    assert 3 = sorted_array[2]
    assert 3 = sorted_array[3]
    assert 4 = sorted_array[4]
    assert 7 = sorted_array[5]
    assert 8 = sorted_array[6]
    assert 10 = sorted_array[7]
    assert 10 = sorted_array[8]
    assert 16 = sorted_array[9]
    assert 20 = sorted_array[10]

    return ()
end
