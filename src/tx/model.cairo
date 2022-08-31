from starkware.cairo.common.uint256 import Uint256

struct Point:
    member x : Uint256
    member y : Uint256
end	

struct Signature:
    member r : Uint256
    member s : Uint256
end	

struct SignatureVerification:
    member pub_key : Point
    member signature : Signature
    member digest : Uint256
end