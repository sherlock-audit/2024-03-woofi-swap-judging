Acrobatic Sable Falcon

medium

# The swap function does not properly handle the case where the `to` address is the pool address itself, allowing an attacker to steal tokens from the swap.

## Summary
_sellBase, _sellQuote, _swapBaseToBase function does not handle the case properly where the `to` address is the pool.
It allows attacker exploit the difference between balance and reserve of token. 

## Vulnerability Detail
`_sellBase`, `_sellQuote`, `_swapBaseToBase` function decrease reserve amount of base/quote token after calculation amount related to swap and posting price.
And then if to address is not Pool address itself, transfer tokens to `to` address.
```solidity
function _sellQuote(
        address baseToken,
        uint256 quoteAmount,
        uint256 minBaseAmount,
        address to,
        address rebateTo
    ) private nonReentrant whenNotPaused returns (uint256 baseAmount) {
    __SNIP__
@>      tokenInfos[baseToken].reserve = uint192(tokenInfos[baseToken].reserve - baseAmount); 
        tokenInfos[quoteToken].reserve = uint192(tokenInfos[quoteToken].reserve + quoteAmount);

        if (to != address(this)) {
@>          TransferHelper.safeTransfer(baseToken, to, baseAmount);
        }
    __SNIP__
}
```
Therefore, if `to` is Pool address itself(to = address(this)), no transfer occurs and balance does not change.
In this case balance is greater than reserve by more than amount to be transferred by the swap.

## Impact
Attacker can steal tokens by directly swapping the gap between balance and reserve of token.

## Code Snippet
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L447-L452
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L493-L498
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L561-L565

## Tool used

Manual Review

## Recommendation
if `to` is pool address itself, reserve amount should not be changed.

```solidity
function _sellQuote(
        address baseToken,
        uint256 quoteAmount,
        uint256 minBaseAmount,
        address to,
        address rebateTo
    ) private nonReentrant whenNotPaused returns (uint256 baseAmount) {
    __SNIP__
        
--      tokenInfos[baseToken].reserve = uint192(tokenInfos[baseToken].reserve - baseAmount); 
++      if (to != address(this))
++          tokenInfos[baseToken].reserve = uint192(tokenInfos[baseToken].reserve - baseAmount); 
        tokenInfos[quoteToken].reserve = uint192(tokenInfos[quoteToken].reserve + quoteAmount);

        if (to != address(this)) {
            TransferHelper.safeTransfer(baseToken, to, baseAmount);
        }
    __SNIP__
}
```