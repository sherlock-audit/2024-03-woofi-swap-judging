Odd Heather Whale

medium

# Missing check for stale results from Chainlink oracle may result in wrong calculations during swaps

## Summary

The protocol's oracle contract `WooracleV2_2` is not implementing checks for whether a returned price from a Chainlink oracle is stale.


## Vulnerability Detail

When the oracle price is fetched via `WooracleV2_2.price()`, the Chainlink price is fetched with `WooracleV2_2._cloPriceInQuote()` on line 247 in WooracleV2_2.sol.

The function `WooracleV2_2._cloPriceInQuote()` returns `refPrice` and `refTimestamp`, where `refTimestamp` is the `updatedAt` value of either the base or the quote token answer from Chainlink's `latestRoundData()` function, depending on which of them is older (see line 368 WooracleV2_2.sol).

However when `WooracleV2_2.price()` is calling `WooracleV2_2._cloPriceInQuote()` on line 247 in WooracleV2_2.sol, the `refTimestamp` return value is ignored. This means that there are no checks for stale Chainlink oracle prices.

There is only a check for staleness for the wooracle price at line 249 in WooracleV2_2.sol, but no check for stale price for the Chainlink price.

The issue is that it is not enough to only check the wooracle price for staleness, because `WooracleV2_2.price()` may return the Chainlink oracle price (line 257 WooracleV2_2.sol), which may be stale.

In the case that the wooracle price `woPrice_` is returned (line 254 WooracleV2_2.sol) it may also be an issue, since `woPrice_` may be checked to be in bound of a potentially outdated/stale Chainlink oracle price `cloPrice_` on line 250-251 in WooracleV2_2.sol. So the `woPriceInBound` flag may be set wrong due to this issue, and `feasible` may be returned to be true despite that the check was done against an outdated/stale Chainlink price (line 255 WooracleV2_2.sol).

The `feasible` return value is used by the protocol to revert in case the value is false. See line 326-327 in WooracleV2_2.sol where `feasiable` is assigned to `state.woFeasible`, and the revert is then done line 596 and line 626 in WooPPV2.sol based on the value of `state.woFeasible`, in order to avoid further processing a wrong price.

## Impact

If the protocol is using a price fetched from a Chainlink oracle that is an outdated/stale/incorrect price, calculations that are based on this price may be wrong, potentially leading to a loss for the protocol.

This can happen during a swap:

The protocol is fetching oracle prices when a swap is done in `WooPPV2.swap()` where subsequently a potentially stale Chainlink oracle price is fetched and may be used to do the necessary calculations for a swap:

* In the case of a base-to-quote swap, the trace may be `WooPPV2.swap() -> WooPPV2._sellBase() -> WooracleV2_2.state() -> WooracleV2_2.price()` -> `WooPPV2._calcQuoteAmountSellBase()`, where on line 436 in WooPPV2.sol the `quoteAmount`, that is the amount of quote tokens transferred to the recipient, and the new price `newPrice` for the base token are then determined based on an potentially stale oracle price.

* In the case of a quote-to-base swap, the trace may be `WooPPV2.swap() -> WooPPV2._sellQuote() -> WooracleV2_2.state() -> WooracleV2_2.price()` -> `WooPPV2._calcBaseAmountSellQuote()` where on line 487 in WooPPV2.sol the amount of base tokens that are transferred to the recipient and the new price are determined based on an potentially stale oracle price.

## Code Snippet

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L243-L260

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L348-L369

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L626

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L324-L327

## Tool used

Manual Review

## Recommendation

Consider checking the Chainlink prices for staleness.

```solidity
// WooracleV2_2.sol

360        (, int256 rawBaseRefPrice, , uint256 baseUpdatedAt, ) = AggregatorV3Interface(baseOracle).latestRoundData();
361        (, int256 rawQuoteRefPrice, , uint256 quoteUpdatedAt, ) = AggregatorV3Interface(quoteOracle).latestRoundData();
+362       if (block.timestamp > baseUpdatedAt + clOracles[_fromToken].staleDuration) { revert(); }
+363       if (block.timestamp > quoteUpdatedAt + clOracles[_toToken].staleDuration) { revert(); }
```

Consider comparing the `block.timestamp` against a different `staleDuration` for each different token, since Chainlink heartbeats may vary between tokens from 24 hours (USDC) to 1 hour (ETH). Reference: https://data.chain.link/feeds/ethereum/mainnet/eth-usd and https://data.chain.link/feeds/ethereum/mainnet/usdc-usd

