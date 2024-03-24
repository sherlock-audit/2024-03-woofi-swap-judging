Icy Denim Cougar

high

# Bridging is not possible because StargateComposer is not used when interacting with StargateRouter

## Summary
If there are payload to sent to the destination chain, StargateComposer must be used instead of interacting with StargateRouter directly. 
## Vulnerability Detail
As we can see in the official Stargate docs if the external contracts will integrate with Stargate, it has to integrate with StargateComposer:
https://stargateprotocol.gitbook.io/stargate/stargate-composability#stargatecomposer.sol

The revert is onchain and its inside the RelayerV2 contract implementation. Since the RelayerV2 contract is not published open source we can't see the exact revert reason. However, we can observe the reverts onchain:
https://optimistic.etherscan.io/tx/0x293a3cfd59bd7cb92803bf0895ab962605c34ff1b38503e478da7cfcf187b0d7
https://snowtrace.io/tx/0xa3115efe5ba4c955844aa5aa6d97d2ceec742c1e0ca03bcab03e5cc69870a063

This is the RelayerV2 implementation that is not published:
https://etherscan.io/address/0xb830a5afcbebb936c30c607a18bbba9f5b0a592f#code

I talked with the Stargate team and they confirmed that any contracts that will use Stargate MUST need to interact with the Composer or the transactions will revert with on-chain error:
`require(stargateComposer.isSending(), "Relayer: stargate composer is not sending");`


## Impact
High since the bridging is impossible because WooFi doesn't interact with Composer contract and instead interacts with the Router directly.

Stargate/LayerZero teams response:
"its upgradeable , the impl changes occasionally and we dont alwyas update the public repo because we dont want people to build on some of the conventions in it"

"most important thing is if youre sending a payload with stargate, you need to send it thru StargateComposer.sol
or youll get the revert on source"

since WooFi sends [payload](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L237) the bridging will be impossible with the current implementation.
## Code Snippet
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L219-L267
## Tool used

Manual Review

## Recommendation
Use StargateComposer instead of interacting with StargateRouter directly.