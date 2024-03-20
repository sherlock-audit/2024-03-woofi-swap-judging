Acrobatic Sable Falcon

high

# The `swap` function of the `WooPPV2` contract is vulnerable.

## Summary
The 'Swap' function of the 'WooPPV2' contract allows users to swap without sending a fromToken if the pool's balance is greater than the pool's reserve.
The router is intended to send money to the pool for a swap and then execute the swap.
However, WooPPV2's `swap` function is an external function that can be called directly, allowing users to directly swap the difference between the balance and reserve of tokens (base or quote) in the pool without going through WooRouter/WooCrossChainRouter.

## Vulnerability Detail
`_sellBase`, `_sellQuote`, `_swapBaseToBase` checks only if base/quote token is valid one and `to` is not address(0) and if `fromAmount` is less than the balance substracted by reserve in fromToken, then swap is available.

Assume that balance of quote token(usdtToken) is greater than its reserve by 1000 USDT.
This difference occurs because swap fees are collected in quote tokens.
Then attacker can run swap function swap function using fromToken as usdtToken, fromAmount as 1000 USDT.
Moreover, attacker can steal tokens front running admin's call to `skim`, `claimFee`, `inCaseTokenGotStuck` by swapping the difference between balance and reserve of tokens.

## Impact
Swap fee in protocol can be stolen by front running by attacker.
When token got stuck in pool, it can be stolen too.
 
## Code Snippet
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L420-L465
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L467-L511
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L513-L578
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L319-L321
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L173-L178

## Tool used

Manual Review

## Recommendation
Recommend that restrict calling directly swap from any address, and instead create storage variable for whitelisted addresses like WooRouter, WooChainRouter and allow only whitelisted addresses swap .