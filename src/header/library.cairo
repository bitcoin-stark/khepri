# SPDX-License-Identifier: MIT
# Khepri smart contracts written in Cairo v0.1.0 (header/library.cairo)

%lang starknet
# Starkware dependencies
from starkware.cairo.common.cairo_builtins import HashBuiltin

# Open Zeppelin dependencies
from openzeppelin.access.ownable import Ownable

# ------
# STORAGE
# ------

namespace BtcHeaderVerifier:
    # -----
    # VIEWS
    # -----

    # ------
    # CONSTRUCTOR
    # ------

    func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        owner : felt
    ):
        Ownable.initializer(owner)
        return ()
    end

    # ------------------
    # EXTERNAL FUNCTIONS
    # ------------------
end
