%lang starknet

from starkware.cairo.common.uint256 import Uint256
from header.model import BlockHeader, BlockHeaderValidationContext

namespace test_utils:
    func mock_ctx(header : BlockHeader) -> (ctx : BlockHeaderValidationContext):
        tempvar ctx : BlockHeaderValidationContext = BlockHeaderValidationContext(
            height=0, block_header=header, previous_block_header=header)
        return (ctx)
    end

    func print_block_header(x : BlockHeader):
        %{
            x = ids.x
            print(f'version: {x.version:08x}')
            print(f'prev_block: {x.prev_block.high:032x}{x.prev_block.low:032x}')
            print(f'merkle_root: {x.merkle_root.high:032x}{x.merkle_root.low:032x}')
            print(f'timestamp: {x.timestamp}')
            print(f'bits: {x.bits:08x}')
            print(f'nonce: {x.nonce:08x}')
            print(f'hash: {x.hash.high:032x}{x.hash.low:032x}')
        %}
        return ()
    end

    func genesis_block_header() -> (header : BlockHeader):
        let (header : BlockHeader) = BlockHeader(
            version=1,
            prev_block=Uint256(0, 0),
            merkle_root=Uint256(0x618f76673e2cc77ab2127b7afdeda33b, 0x4a5e1e4baab89f3a32518a88c31bc87f),
            timestamp=1231006505,
            bits=0x1d00ffff,
            nonce=0x7c2bac1d,
            hash=Uint256(0x4ff763ae46a2a6c172b3f1b60a8ce26f, 0x000000000019d6689c085ae165831e93),
        )
        return (header=header)
    end

    func load_header_from_json(file_name : felt) -> (header : BlockHeader):
        alloc_locals
        local header : BlockHeader
        %{
            import json
            f_name_int = int(ids.file_name)
            file_name = f_name_int.to_bytes((f_name_int.bit_length() + 7 ) // 8, 'big').decode()
            with open(file_name, 'r') as f:
                data = json.load(f)

            prev_block = data['previousblockhash'] if 'previousblockhash' in data else "0"*64
            merkle_root = data['merkleroot']
            hash = data['hash']

            ids.header.version = data['version']
            ids.header.prev_block.low = int(prev_block[32:], 16)
            ids.header.prev_block.high = int(prev_block[:32], 16)
            ids.header.merkle_root.low = int(merkle_root[32:], 16)
            ids.header.merkle_root.high = int(merkle_root[:32], 16)

            ids.header.timestamp = data['version']
            ids.header.bits = int(data['bits'], 16)
            ids.header.nonce = data['nonce']
            ids.header.hash.low = int(hash[32:], 16)
            ids.header.hash.high = int(hash[:32], 16)
        %}
        return (header)
    end
end
