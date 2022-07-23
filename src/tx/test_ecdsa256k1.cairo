%lang starknet
%builtins range_check

from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.cairo_secp.bigint import (
    BigInt3,
    bigint_to_uint256,
    uint256_to_bigint,
)

from tx.ecdsa256k1 import _verify_ecdsa_secp256k1, verify_ecdsa_secp256k1
from tx.model import Signature, Point, SignatureVerification

# Verifies a secp256k1 ECDSA signature.
@view
func test_ecsda_secp256k1_TV0{
    range_check_ptr
}():
    let public_key_pt = EcPoint(
        BigInt3(0x35dec240d9f76e20b48b41, 0x27fcb378b533f57a6b585, 0xbff381888b165f92dd33d),
        BigInt3(0x1711d8fb6fbbf53986b57f, 0x2e56f964d38cb8dbdeb30b, 0xe4be2a8547d802dc42041))
    let r = BigInt3(0x2e6c77fee73f3ac9be1217, 0x3f0c0b121ac1dc3e5c03c6, 0xeee3e6f50c576c07d7e4a)
    let s = BigInt3(0x20a4b46d3c5e24cda81f22, 0x967bf895824330d4273d0, 0x541e10c21560da25ada4c)
    let msg_hash = BigInt3(
        0x38a23ca66202c8c2a72277, 0x6730e765376ff17ea8385, 0xca1ad489ab60ea581e6c1)

    _verify_ecdsa_secp256k1(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s)
    
    return ()
end

@view
func test_ecsda_secp256k1_TV1{
    range_check_ptr
}():
    let x = Uint256(0x28b790dc6b3b7d4437a427bd5847dfcd, 0x779dd197a5df977ed2cf6cb31d82d433)
    let y = Uint256(0xf5b1699d6ef4124975c9237b917d426f, 0xe94b724a555b6d017bb7607c3e3281da)
    let r = Uint256(0x10efbb3b2676bbc0f8b08505c9e2f795, 0x241097efbf8b63bf145c8961dbdf10c3)
    let s = Uint256(0x661828131aef1ecbc7955dfb01f3ca0e, 0x021006b7838609339e8b415a7f9acb1b)
    let z = Uint256(0x9c67ea1c3bf63f3e0471baa664531d1a, 0x4b688df40bcedbe641ddb16ff0a1842d)
    
    verify_ecdsa_secp256k1(x, y, z, r, s)

    return ()
end

@view
func test_ecsda_secp256k1_TV2{
    range_check_ptr
}():
    let x = Uint256(0x6140347dcee1b2943f4a2897351e5d90, 0xb726d7eae11a6d5cf3b2362e773e116a)
    let y = Uint256(0xeac7de14867da251edb4e8451d6b8264, 0x3533a9823cfc90d0314e490e9989d7a4)
    let r = Uint256(0x49c029e6b7b15371342d0d2ce286c8f2, 0xd8629403cd3b49950da9293653c62791)
    let s = Uint256(0xc94af5f00d9d34a07dc2f9e0987ef990, 0x78787985a644e94fd9246f6c25733336)
    let z = Uint256(0xb833a05041db90a2b9dde498922de36b, 0x698948d02abe641646313266416e05ce)
    
    verify_ecdsa_secp256k1(x, y, z, r, s)
    
    return ()
end

# the 'pizza transaction' 
#   https://www.blockchain.com/btc/tx/cca7507897abc89628f450e8b1e0c6fca4ec3f7b34cccf55f3f531c659ff4d79
@view
func test_ecsda_secp256k1_TV3{
    range_check_ptr
}():
    alloc_locals
   
    let point = Point(
        x=Uint256(0xd34aa9e057cda01cfd422c6bab3667b7, 0x2e930f39ba62c6534ee98ed20ca98959),
        y=Uint256(0xd6b437a8526e59667ce9c4e9dcebcabb, 0x6426529382c23f42b9b08d7832d4fee1)
    )
    let signature = Signature(
        r=Uint256(0xd478fbb96f8addbc3d075544dc413287, 0x9908144ca6539e09512b9295c8a27050),
        s=Uint256(0x3243d97e444d59290d2fddf25269ee0e, 0x1aa528be2b907d316d2da068dd9eb1e2)
    )
    let digest = Uint256(0x275f0943444d7df8cc851b3d55782669, 0xc2d48f45d7fbeff644ddb72b0f60df6c)
    
    local sv : SignatureVerification
    assert sv.pub_key = point 
    assert sv.signature = signature
    assert sv.digest = digest

    verify_ecdsa_secp256k1(sv.pub_key.x, sv.pub_key.y, sv.digest, sv.signature.r, sv.signature.s)

    return ()
end