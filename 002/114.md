Furry Fiery Ostrich

medium

# In the function _handleERC20Received, the fee was incorrectly charged

## Summary

In the function _handleERC20Received, the fee was incorrectly charged.

## Vulnerability Detail

In the contract, when external swap occurs, a portion of the fee will be charged. However, in function _handleERC20Received, the fee is also charged in internal swap.

```solidity
} else {
    // Deduct the external swap fee
    uint256 fee = (bridgedAmount * dstExternalFeeRate) / FEE_BASE;
    bridgedAmount -= fee;  // @@audit: fee should not be applied to internal swap 

    TransferHelper.safeApprove(bridgedToken, address(wooRouter), bridgedAmount);
    if (dst1inch.swapRouter != address(0)) {
        try
            wooRouter.externalSwap(
```

At the same time, when the internal swap fails, this part of the fee will not be returned to the user.

## Impact

Internal swaps are incorrectly charged, and fees are not refunded when internal swap fail.

## Code Snippet

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L412-L414

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L478

## Tool used

Manual Review

## Recommendation

Apply fee calculation only to external swaps.

```dart
function _handleERC20Received(
    uint256 refId,
    address to,
    address toToken,
    address bridgedToken,
    uint256 bridgedAmount,
    uint256 minToAmount,
    Dst1inch memory dst1inch
) internal {
    address msgSender = _msgSender();

    // ...

    } else {
        if (dst1inch.swapRouter != address(0)) {
            // Deduct the external swap fee
            uint256 fee = (bridgedAmount * dstExternalFeeRate) / FEE_BASE;
            bridgedAmount -= fee;  

            TransferHelper.safeApprove(bridgedToken, address(wooRouter), bridgedAmount);
            try
                wooRouter.externalSwap(
                    // ...
                )
            returns (uint256 realToAmount) {
                emit WooCrossSwapOnDstChain(
                    // ...
                );
            } catch {
                bridgedAmount += fee;
                TransferHelper.safeTransfer(bridgedToken, to, bridgedAmount);
                emit WooCrossSwapOnDstChain(
                    // ...
                );
            }
        } else {
            TransferHelper.safeApprove(bridgedToken, address(wooRouter), bridgedAmount);
            try wooRouter.swap(bridgedToken, toToken, bridgedAmount, minToAmount, payable(to), to) returns (
                uint256 realToAmount
            ) {
               // ...
            } catch {
                // ...
            }
        }
    }
}
```