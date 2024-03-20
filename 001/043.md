Fantastic Boysenberry Elephant

high

# Repeated swap fee deduction in `_sellBase()` causes loss of fund from the protocol

## Summary

Repeated deduction of `swapFee` in the `quoteToken` reserve update during `quoteToken` to `baseToken` swap results in fund loss for protocol every time user swaps from the `WooPPV2` private pool.

## Vulnerability Detail

`swap()` is a crucial function for the Woo private pool that swaps `fromToken` to `toToken`. Within this external function, based on the `fromToken` and `toToken` it calls three different private functions that would perform the actual swap and return the `realToAmount`.

One of the case is `toToken` being the `quoteToken`, for which the swap would be done via `_sellBase()` function.

```solidity
else if (toToken == quoteToken) {
		// case 2: fromToken --> quoteToken
		realToAmount = _sellBase(fromToken, fromAmount, minToAmount, to, rebateTo);
}
```

In the `_sellBase()`, `swapFee` is being deducted from the `quoteAmount`, which updates the final value of `quoteAmount`.

```solidity
quoteAmount = quoteAmount - swapFee;
```

Naturally, the updated `quoteAmount` should be deducted from the `quoteToken` overall reserve to update the pool balance, as what is being done in other cases of swapping, e.g., [[1]](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L493-494), [[2]](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L550).

However in the code of this pool reserve update, alongside the `quoteAmount`, additionally `swapFee` is being deducted again.

```solidity
// @audit `quoteAmount` is already updated with the `swapFee` deduction.
tokenInfos[quoteToken].reserve = uint192(tokenInfos[quoteToken].reserve - quoteAmount - swapFee);
```

Since `swapFee` is already deducted from the `quoteAmount`, doing it again during the reserve update results in unnecessary fund loss from the protocol every time user uses `WooPPV2` pool for swapping.

<Details>
<Summary>Proof of Concept</Summary>

In the `WooPPv2.test.ts` test file, within the [`wooPP swap::sellBase accuracy2`](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/test/typescript/WooPPv2.test.ts#L273-319) test case add the following lines at the end of the case -

```typescript
const quoteReserve = preWooppUsdtSize.sub(quoteAmount);
expect(quoteReserve).to.gt(wppUsdtSize);
console.log(
	'wooPP usdt reserve without extra swapFee: ',
	utils.formatEther(quoteReserve)
);
console.log(
	'wooPP usdt reserve difference: ',
	utils.formatEther(wppUsdtSize),
	utils.formatEther(quoteReserve),
	utils.formatEther(quoteReserve.sub(wppUsdtSize))
);
```

Running this test case in the Hardhat environment with `hh test --grep 'sellBase accuracy2'` will console log the difference every time the protocol loses fund -

```log
  WooPPV2 Integration tests
    wooPP swap
swap query quote: 59876
unclaimed fee: 59.9364
balance usdt:  240123
pool usdt:  240063
balance delta:  59936
fee:  0 59
user1 usdt:  0.0 59876.4636
user1 btc:  3.0 0.0
wooPP btc:  10.0 13.0
wooPP usdt:  300000.0 240063.6
wooPP usdt reserve without extra swapFee:  240123.5364
wooPP usdt reserve difference:  240063.6 240123.5364 59.9364
      ✔ sellBase extra swapFee (721ms)

  1 passing (4s)
```

</Details>

## Impact

Protocol losses unnecessary funds every time user swaps using `WooPPV2` pool.

## Code Snippet

[WooPPV2.sol::\_sellBase#L448](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L448)

```solidity
function _sellBase(address baseToken, uint256 baseAmount, uint256 minQuoteAmount, address to, address rebateTo)
.
.
.
		tokenInfos[baseToken].reserve = uint192(tokenInfos[baseToken].reserve + baseAmount);
@>		tokenInfos[quoteToken].reserve = uint192(tokenInfos[quoteToken].reserve - quoteAmount - swapFee);
```

## Tool used

Manual Review

## Recommendation

Consider removing the `swapFee` from the code where it's updating the `quoteToken`'s reserve.

```diff
function _sellBase(address baseToken, uint256 baseAmount, uint256 minQuoteAmount, address to, address rebateTo)
.
.
.
		tokenInfos[baseToken].reserve = uint192(tokenInfos[baseToken].reserve + baseAmount);
-		tokenInfos[quoteToken].reserve = uint192(tokenInfos[quoteToken].reserve - quoteAmount - swapFee);
+		tokenInfos[quoteToken].reserve = uint192(tokenInfos[quoteToken].reserve - quoteAmount);

}
```

