%lang starknet

from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.cairo_secp.bigint import BigInt3

from tx.ecdsa256k1 import _verify_ecdsa_secp256k1, verify_ecdsa_secp256k1
from tx.model import Signature, Point, SignatureVerification
from tx.test_utils import test_utils

# stark template
@view
func test_ecsda_secp256k1{
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

func validate_ecdsa_secp256k1{
    range_check_ptr
}(sv : SignatureVerification):
    # test_utils.print_ecdsa_params(sv)
    verify_ecdsa_secp256k1(sv.pub_key.x, sv.pub_key.y, sv.digest, sv.signature.r, sv.signature.s)
    return ()
end

@view
func test_p2pkh_with_compressed_pubkey02{
    range_check_ptr
}():
    let (sv : SignatureVerification) = test_utils.load_p2pkh_tx_from_json('./resources/tx/p2pkh02.json')
    validate_ecdsa_secp256k1(sv)
    return ()
end

@view
func test_p2pkh_with_compressed_pubkey03{
    range_check_ptr
}():
    let (sv : SignatureVerification) = test_utils.load_p2pkh_tx_from_json('./resources/tx/p2pkh03.json')
    validate_ecdsa_secp256k1(sv)
    return ()
end

# uncompressed pubkey
@view
func test_p2pkh_with_uncompressed_pubkey04{
    range_check_ptr
}():
    let (sv : SignatureVerification) = test_utils.load_p2pkh_tx_from_json('./resources/tx/p2pkh04.json')
    validate_ecdsa_secp256k1(sv)
    return ()
end