Fantastic Boysenberry Elephant

medium

# Cross chain swap could revert for strictly equal require statement

## Summary

`crossSwap` mechanism requires the srcInfos `fromAmount` to be strictly equal to `minBridgeAmount` that could revert the entire transaction if the `fromToken` is the `bridgeToken`.

## Vulnerability Detail

The cross swap mechanism in `WooCrossChainRouterV4` requires the `srcInfos.fromAmount` to be strictly equal to `srcInfos.minBridgeAmount` in the case of `srcInfos.fromToken` is the `bridgeToken`.

```solidity
require(
	srcInfos.fromAmount == srcInfos.minBridgeAmount, "WooCrossChainRouterV3: !srcInfos.minBridgeAmount"
);
```

In any case where `srcInfos.fromToken` is not equal to `srcInfos.minBridgeAmount` the entire cross chain swap transaction will revert.

## Impact

If the `fromToken` and `bridgeToken` is same, user is forced to use the same amount for `fromAmount` and `minBridgeAmount`.

## Code Snippet

[WooCrossChainRouterV4.sol::crossSwap#L125](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L125)

```solidity
function crossSwap(
.
.
.
	// Step 2: local swap by 1inch router
	.
	.
	.
	} else {
		require(
@>			srcInfos.fromAmount == srcInfos.minBridgeAmount, "WooCrossChainRouterV3: !srcInfos.minBridgeAmount");
			bridgeAmount = srcInfos.fromAmount;
		}
```

## Tool used

Manual Review

## Recommendation

Instead of requiring the `fromAmount` to be strictly equal to `minBridgeAmount`, consider using greater than equal -

```diff
require(
-		srcInfos.fromAmount == srcInfos.minBridgeAmount, "WooCrossChainRouterV3: !srcInfos.minBridgeAmount"
+		srcInfos.fromAmount >= srcInfos.minBridgeAmount, "WooCrossChainRouterV3: !srcInfos.minBridgeAmount"
);
```

