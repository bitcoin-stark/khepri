# SPDX-License-Identifier: MIT
# Khepri smart contracts written in Cairo v0.1.0 (btc_header_verifier.cairo)

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin

from src.header.library import BtcHeaderVerifier

# ------
# CONSTRUCTOR
# ------

@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(owner : felt):
    return BtcHeaderVerifier.constructor(owner)
end

# -----
# VIEWS
# -----

# ------------------
# EXTERNAL FUNCTIONS
# ------------------
