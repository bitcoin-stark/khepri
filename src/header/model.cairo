# SPDX-License-Identifier: MIT
# Khepri smart contracts written in Cairo v0.1.0 (header/model.cairo)

%lang starknet

# Starkware dependencies
from starkware.cairo.common.uint256 import Uint256

struct BlockHeader:
    member version : felt  # 4 bytes
    member prev_block : Uint256  # 32 bytes
    member merkle_root : Uint256  # 32 bytes
    member timestamp : felt  # 4 bytes
    member bits : felt  # 4 bytes
    member nonce : felt  # 4 bytes
    member hash : Uint256  # 32 bytes
end
