Sunny Lava Orca

medium

# The protocol can get less fees due to slippage

## Summary

## Vulnerability Detail
Inside the crossSwap function, the protocol takes external fees if the swap router is 1inch. But the problem is that it takes fees after the swap. The bridgeAmount can be less than the fromAmount due to slippage, and this causes the protocol to take less fees.

```solidity
if (srcInfos.fromToken != srcInfos.bridgeToken) {
                TransferHelper.safeApprove(srcInfos.fromToken, address(wooRouter), srcInfos.fromAmount);
                if (src1inch.swapRouter != address(0)) {
                    // external swap via 1inch
                    bridgeAmount = wooRouter.externalSwap(
                        src1inch.swapRouter,
                        src1inch.swapRouter,
                        srcInfos.fromToken,
                        srcInfos.bridgeToken,
                        srcInfos.fromAmount,
                        srcInfos.minBridgeAmount,
                        payable(address(this)),
                        src1inch.data
                    );
                    fee = (bridgeAmount * srcExternalFeeRate) / FEE_BASE; //@audit !!
```

For example, the other functions like _handleERC20Received and _handleNativeReceived take fees before swaps.

```solidity
if (dst1inch.swapRouter != address(0)) {
            uint256 fee = (bridgedAmount * dstExternalFeeRate) / FEE_BASE; 
            uint256 swapAmount = bridgedAmount - fee;
            TransferHelper.safeApprove(weth, address(wooRouter), swapAmount);
            try
                wooRouter.externalSwap(
```
If the protocol doesn't want to be affected by slippage, fees need to be taken before the swap.



## Impact
The protocol can get less fees due to slippage.
## Code Snippet
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L97-L111
## Tool used

Manual Review

## Recommendation
```solidity
// Step 2: local swap by 1inch router
            if (srcInfos.fromToken != srcInfos.bridgeToken) {
                TransferHelper.safeApprove(srcInfos.fromToken, address(wooRouter), srcInfos.fromAmount);
                if (src1inch.swapRouter != address(0)) {
                    fee = (srcInfos.fromAmount * srcExternalFeeRate) / FEE_BASE;
                    srcInfos.fromAmount = srcInfos.fromAmount - fee;
                    // external swap via 1inch
                    bridgeAmount = wooRouter.externalSwap(
                        src1inch.swapRouter,
                        src1inch.swapRouter,
                        srcInfos.fromToken,
                        srcInfos.bridgeToken,
                        srcInfos.fromAmount,
                        srcInfos.minBridgeAmount,
                        payable(address(this)),
                        src1inch.data
                    );
                }
```