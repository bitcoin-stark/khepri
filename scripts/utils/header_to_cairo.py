import json

def hash_to_Uint256_cairo(hash_hex_str):
    low = hash_hex_str[32:]
    high = hash_hex_str[:32]
    return f"Uint256(low=0x{low}, high=0x{high})"
    
def header_to_cairo(block_json):
    prev_block = block_json["previousblockhash"] if "previousblockhash" in block_json else "0"*64
    hash = block_json["hash"] if "hash" in block_json else "0"*64
    merkle_root = block_json["merkleroot"] if "merkleroot" in block_json else "0"*64
    res = f"""\
BlockHeader(
    version= {block_json['version']}, 
    prev_block={hash_to_Uint256_cairo(prev_block)},
    merkle_root={hash_to_Uint256_cairo(merkle_root)},
    timestamp={block_json['time']},
    bits=0x{block_json['bits']},
    nonce={block_json['nonce']},
    hash={hash_to_Uint256_cairo(hash)},
    )\
"""
    return res


def main():
    import sys
    input_name = sys.argv[1] 

    if input_name is None: return

    with open(input_name) as block_file:
        block = json.load(block_file)
    
    res = header_to_cairo(block)
    print(f"let header: BlockHeader = {res}")

if __name__ == "__main__":
    main()