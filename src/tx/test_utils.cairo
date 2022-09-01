from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc

from tx.model import SignatureVerification

namespace test_utils:
    func p2pkh_helper():
        %{
            import hashlib
            from binascii import unhexlify

            def generate_pubkey_script(key_hex):
                sha = hashlib.sha256()
                rip = hashlib.new('ripemd160')
                sha.update(unhexlify(key_hex))
                rip.update(sha.digest())
                return f'1976a914{rip.hexdigest()}88ac'

            def decode_signature_script(sig):
                s1 = sig
                sig = s1[2:]
                s_len = int(sig[6:8],16)*2
                r_hex = sig[8:8+s_len]
                if int(r_hex[0:2],16) == 0: r_hex = r_hex[2:] 
                r_len = int(sig[10+s_len:12+s_len],16)*2
                s_hex = sig[12+s_len:12+s_len+r_len]
                key_offset = int(s1[:2], 16)*2 + 2
                k_len = int(s1[key_offset:key_offset+2], 16)*2
                key_hex = s1[-k_len:]
                return (r_hex, s_hex, key_hex)

            def digest_raw_transaction(tx_hex):
                tx_bin = unhexlify(rawtx_hex)
                tx_hex = hashlib.sha256(hashlib.sha256(tx_bin).digest()).hexdigest()
                return tx_hex

            def generate_hex_vout(vout):
                vout = [(v["scriptPubKey"]["hex"], int(v["value"]*10**8).to_bytes(8, 'little').hex()) for v in vout]
                voutHex = ''.join(f'{v}{int(len(s)/2).to_bytes(1, "little").hex()}{s}' for (s, v) in vout)
                coutHex = len(vout).to_bytes(1, 'little').hex()
                return (coutHex, voutHex)
        %}
        return ()
    end

    func load_p2pkh_tx_from_json(file_name : felt) -> (sv : SignatureVerification):
        alloc_locals
        local sv : SignatureVerification
        p2pkh_helper()
        %{
            import json

            f_name_int = int(ids.file_name)
            file_name = f_name_int.to_bytes((f_name_int.bit_length() + 7 ) // 8, 'big').decode()
            with open(file_name, 'r') as f: tx = json.load(f)

            # tx raw
            vin = tx["vin"][0]
            vinCountHex = "01"
            versionHex = tx["version"].to_bytes(4, 'little').hex()
            previousTxHex = (bytes.fromhex(vin["txid"])[::-1].hex() if "txid" in vin else (0).to_bytes(32, 'little').hex())

            # extract signature and pub key
            (r_hex, s_hex, key_hex) = decode_signature_script(vin["scriptSig"]["hex"])

            # extract out elements
            (coutHex, voutHex) = generate_hex_vout(tx["vout"])

            # generate pubkey script
            voutIndexHex = vin["vout"].to_bytes(4, 'little').hex()
            vinHex = generate_pubkey_script(key_hex)

            seqHex = "ffffffff"
            suffixHex = "0000000001000000"

            rawtx_hex = (
                versionHex + vinCountHex + previousTxHex + voutIndexHex + vinHex + seqHex + coutHex + voutHex + suffixHex
            )

            tx_hex = digest_raw_transaction(rawtx_hex)
                    
            # if uncompressed pubkey
            if len(key_hex) > 128:
                x = key_hex[2:66]
                y = key_hex[-64:]
                ids.sv.pub_key.x.low = int(x[32:], 16)
                ids.sv.pub_key.x.high = int(x[:32], 16)
                ids.sv.pub_key.y.low = int(y[32:], 16)
                ids.sv.pub_key.y.high = int(y[:32], 16)
            else:
                x = key_hex[2:66]
                ids.sv.pub_key.x.low = int(x[32:], 16)
                ids.sv.pub_key.x.high = int(x[:32], 16)
                ids.sv.pub_key.y.low = int(key_hex[:2], 16)
                ids.sv.pub_key.y.high = 0

            ids.sv.signature.r.low = int(r_hex[32:], 16)
            ids.sv.signature.r.high = int(r_hex[:32], 16)
            ids.sv.signature.s.low = int(s_hex[32:], 16)
            ids.sv.signature.s.high = int(s_hex[:32], 16)
            ids.sv.digest.low = int(tx_hex[32:], 16)
            ids.sv.digest.high = int(tx_hex[:32], 16)
        %}
        return (sv)
    end

    func load_merkle_tx_from_json(file_name : felt) -> (
        tx : Uint256*, tx_len : felt, root : Uint256
    ):
        alloc_locals
        local tx_root : Uint256
        local tx : Uint256*
        local tx_len
        %{
            import json

            f_name_int = int(ids.file_name)
            file_name = f_name_int.to_bytes((f_name_int.bit_length() + 7 ) // 8, 'big').decode()
            with open(file_name, 'r') as f: j = json.load(f)

            ids.tx = tx = segments.add()
            for i, x in enumerate(j["tx"]):
                memory[tx + i*2] = int(x[32:], 16)
                memory[tx + i*2 + 1] = int(x[:32], 16)
            ids.tx_len = len(j["tx"])

            x = j["merkleroot"]
            ids.tx_root.low = int(x[32:], 16)
            ids.tx_root.high = int(x[:32], 16)
        %}
        return (tx=tx, tx_len=tx_len, root=tx_root)
    end

    func print_ecdsa_params(sv : SignatureVerification):
        %{
            x = ids.sv
            print(f'pub_x: {x.pub_key.x.high:032x}{x.pub_key.x.low:032x}')
            print(f'pub_y: {x.pub_key.y.high:032x}{x.pub_key.y.low:032x}')
            print(f'sig_r: {x.signature.r.high:032x}{x.signature.r.low:032x}')
            print(f'sig_s: {x.signature.s.high:032x}{x.signature.s.low:032x}')
            print(f'hash_: {x.digest.high:032x}{x.digest.low:032x}')
        %}
        return ()
    end
end
