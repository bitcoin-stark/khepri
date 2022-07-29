from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc

func hash_chain(a : Uint256*, a_len : felt, c : Uint256*) -> (c_end : Uint256*):
    alloc_locals

    if (a_len+1)*a_len == 0:
        return (c_end=c)
    end

    let x = [a]
    local y : Uint256
    if a_len == 1:
        assert y = [a]
    else:
        assert y = a[1]
    end
    
    local z : Uint256

    %{
        from hashlib import  sha256

        sha = sha256()
        sha.update(ids.x.low.to_bytes(16, 'little'))
        sha.update(ids.x.high.to_bytes(16, 'little'))
        sha.update(ids.y.low.to_bytes(16, 'little'))
        sha.update(ids.y.high.to_bytes(16, 'little'))
        h = sha256(sha.digest()).digest()[::-1]
        ids.z.low = int.from_bytes(h[16:], "big")
        ids.z.high = int.from_bytes(h[:16], "big")
    %}

    assert [c] = z

    return hash_chain(a+Uint256.SIZE*2, a_len-2, c+Uint256.SIZE)
end

func build_merkle_root(a : Uint256*, a_len : felt) -> (res : Uint256):
    alloc_locals
    
    if a_len == 1:
        return (res=[a])
    end
    
    let (local c_start : Uint256*) = alloc()
    let (c_end : Uint256*) = hash_chain(a, a_len, c_start)
    tempvar c_len = (c_end - c_start) / Uint256.SIZE

    return build_merkle_root(a=c_start, a_len=c_len)
end