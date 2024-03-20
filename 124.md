Furry Fiery Ostrich

high

# When bridgeToken is ETH_PLACEHOLDER_ADDR, `crossSwap` will fail.

## Summary

When bridgeToken is ETH_PLACEHOLDER_ADDR, `crossSwap` will fail.

## Vulnerability Detail

In the function `crossSwap`, srcInfos.bridgeToken represents the token that the user wants to obtain. At the same time, in the contract, ETH_PLACEHOLDER_ADDR is used to represent the native token (ETH). Thus, user may set srcInfos.bridgeToken to ETH_PLACEHOLDER_ADDR to get ETH. However, in the function `crossSwap`, when checking whether the balance of the contract is greater than bridgeAmount, the IERC20 interface is directly used, which will cause the function crossSwap to fail.

```solidity
// @@audit: if bridgeToken == ETH_PLACEHOLDER_ADDR, failed!
require(
    bridgeAmount <= IERC20(srcInfos.bridgeToken).balanceOf(address(this)),
    "WooCrossChainRouterV3: !bridgeAmount"
);
```

## Impact

Function crossSwap will fail. 

## Code Snippet

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L131-L134

## Tool used

Manual Review

## Recommendation

Use the function `_generalBalanceOf` to get the balance.