%lang starknet

from header.model import BlockHeader, BlockHeaderValidationContext

namespace test_utils:
    func mock_ctx(header : BlockHeader) -> (ctx : BlockHeaderValidationContext):
        tempvar ctx : BlockHeaderValidationContext = BlockHeaderValidationContext(
            height=0, block_header=header, previous_block_header=header)
        return (ctx)
    end
end
