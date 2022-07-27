from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc

from tx.model import SignatureVerification

namespace test_utils:

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

    func load_ecdsa_params_from_json(file_name : felt) -> (sv : SignatureVerification):
        alloc_locals
        local sv : SignatureVerification
        %{
            ENDIANNESS = "little"
            BIG = "big"
            
            import json
            import hashlib
            from binascii import unhexlify

            f_name_int = int(ids.file_name)
            file_name = f_name_int.to_bytes((f_name_int.bit_length() + 7 ) // 8, BIG).decode()
            with open(file_name, 'r') as f: tx = json.load(f)

            # signature and pub key
            vin = tx["vin"][0]
            x = vin["scriptSig"]["hex"]
            sig = x[2:]
            s_len = int(sig[6:8],16)*2
            r_hex = sig[8:8+s_len]
            if int(r_hex[0:2],16) == 0: r_hex = r_hex[2:] 
            r_len = int(sig[10+s_len:12+s_len],16)*2
            s_hex = sig[12+s_len:12+s_len+r_len]
            key_offset = int(x[:2], 16)*2 + 2
            k_len = int(x[key_offset:key_offset+2], 16)*2
            key_hex = x[-k_len:]

            # tx raw
            versionHex = tx["version"].to_bytes(4, ENDIANNESS).hex()
            vinCountHex = "01"
            previousTxHex = (bytes.fromhex(vin["txid"])[::-1].hex() if "txid" in vin else (0).to_bytes(32, ENDIANNESS).hex())
            
            voutIndex = vin["vout"]
            voutIndexHex = voutIndex.to_bytes(4, ENDIANNESS).hex()
            vout = [(v["scriptPubKey"]["hex"], int(v["value"]*10**8).to_bytes(8, ENDIANNESS).hex()) for v in tx["vout"]]

            # generate new script
            sha = hashlib.sha256()
            rip = hashlib.new('ripemd160')
            sha.update(unhexlify(key_hex))
            rip.update(sha.digest())
            vinHex = f'1976a914{rip.hexdigest()}88ac'
            
            coutHex = len(vout).to_bytes(1, ENDIANNESS).hex()
            voutHex = ''.join(f'{v}{int(len(s)/2).to_bytes(1, ENDIANNESS).hex()}{s}' for (s, v) in vout)

            magicHex = "ffffffff"
            suffixHex = "0000000001000000"

            rawtx_hex = (
                versionHex + vinCountHex + previousTxHex + voutIndexHex + vinHex + magicHex + coutHex + voutHex + suffixHex
            )

            tx_bin = unhexlify(rawtx_hex)
            h_hex = hashlib.sha256(hashlib.sha256(tx_bin).digest()).hexdigest()
                    
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
            ids.sv.digest.low = int(h_hex[32:], 16)
            ids.sv.digest.high = int(h_hex[:32], 16)
        %}
        return (sv)
    end
end