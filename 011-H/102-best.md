Agreeable Orange Griffin

high

# Rebate system is flawed.

## Summary

Rebate system is currently not correctly implemented due to which the protocol might loss value.

## Vulnerability Detail

`WooPPV2` charges fee from the users who swaps token using it. Also some percent of this fee generated is given to the broker who routed the trades towards the pool. In order to that, `WooPPV2::_sellBase(...)`, `WooPPV2::_sellQuote(...)` and `WooPPV2::_swapBaseToBase(...)` emits `WooSwap(...)` event.

```solidity
File: WooPPV2.sol

    function _sellQuote(address baseToken, uint256 quoteAmount, uint256 minBaseAmount, address to, address rebateTo)
         
         ...

        emit WooSwap(
            quoteToken,
            baseToken,
            quoteAmount + swapFee,
            baseAmount,
            msg.sender,
            to,
@>           rebateTo,
            quoteAmount + swapFee,
            swapFee
        );
    }
```

GitHub: [[500](https://github.com/sherlock-audit/2024-03-woofi-swap/WooPoolV2/contracts/WooPPV2.sol#L500)]

This swap event will be indexed by the protocol's offline  indexer and `rebateTo` address that was passed as an argument to the swap function will be checked as well whether it is valid `broker` whitelisted in the protocol. If yes only then percent of fee (0.5bps) will be transferred to `WooRebateManager` contract for that address. If the `rebateTo` is not verified broker then the whole fee will go to the protocol. 

But currently there is problem with the implementation of this mechanism. The `WooPPV2::swap(...)` accepts any address as a `rebateTo` address. This is not problem as far as the `rebateTo` address is not whitelisted. But a user can pick an address of a whitelisted brocker and pass it as a `rebateTo` address. Now what's going to happen is this broker will receive the fee rebate and the protocol will always be in loss of fee revenue. 

```solidity
File: WooPPV2.sol

    function swap(
        address fromToken,
        address toToken,
        uint256 fromAmount,
        uint256 minToAmount,
        address to,
@>        address rebateTo
    ) external override returns (uint256 realToAmount) {
        if (fromToken == quoteToken) {
            // case 1: quoteToken --> baseToken
            realToAmount = _sellQuote(toToken, fromAmount, minToAmount, to, rebateTo);
        } else if (toToken == quoteToken) {
            // case 2: fromToken --> quoteToken
            realToAmount = _sellBase(fromToken, fromAmount, minToAmount, to, rebateTo);
        } else {
            // case 3: fromToken --> toToken (base to base)
            realToAmount = _swapBaseToBase(fromToken, toToken, fromAmount, minToAmount, to, rebateTo);
        }
    }
```
GitHub: ([158](https://github.com/sherlock-audit/2024-03-woofi-swap/WooPoolV2/contracts/WooPPV2.sol#L158))

This problem can be mitigated by setting the `msg.sender` address as the address of `rebateTo`. But this is not resolved here. This contract will be used by `WooRouterV2.sol` that uses `WooPPV2` for the swap. User are supposed to be interact with the `WooRouterV2.sol` for not dealing with the lower level details of `WooPPV2`. That means now when the call is made to `WooPPV2::swap(...)`, `WooRouterV2` will be the `msg.sender`. So the issue is still present.

That is not all, `WooCrossChainRouterV4` and `WooCrossRouterForWidget` also uses this function `WooPPV2::swap(...)` function as you can see here 👇


https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L114


And here 👇

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/CrossChain/WooCrossRouterForWidget.sol#L82

But according to the sponsors, Cross chain router and widget are not compatible with rebate system and rebate is not supported over there. That is why the address of `to` is passed as rebate receiver address here👇instead of any user provided address

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L349

But on the contrary, Widget contract allows it to pass any `rebateTo` value as well which is the source of confusion



https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/CrossChain/WooCrossRouterForWidget.sol#L81-L89



But we know that the `WooPPV2::swap(...)` will be used when the tokens are received on the destination chain's Cross chain router. So an argument can be made here that the destination trades are not compatible for the rebates. But again this can be bypassed. If a verified broker uses this function and passes it's own address as `to` address then the fee rebate can still be received. But We know that in order for this to happen, the broker if contract, should 1) have same address on the destination chain. 2) should be whitelisted on the destination chain (if needed) as well. But this is not very rare scenario. This can happen when a broker is serving on multiple chains.

Also if the broker is an EOA, then limit can be bypassed very easily.

Because of all of the above given reasons, the current rebate system is not working as it should. Because of this the protocol is losing value.

## Impact

Loss of value for the protocol.

## Code Snippet

https://github.com/sherlock-audit/2024-03-woofi-swap/WooPoolV2/contracts/WooPPV2.sol

https://github.com/sherlock-audit/2024-03-woofi-swap/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L349

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/CrossChain/WooCrossRouterForWidget.sol#L81-L89

## Tool used

- Manual Review

## Recommendation

It is recommended to make the rebate system more organized. There are pros and cons of various fix for this. The best one according to me is, implementing a separate contract that maintain the whitelisted address list (if not there already) and related function. Now use this in the `WooRouterV2`, `WooCrossChainRouterV4` and `WooCrossRouterForWidget` and check if the `msg.sender` is equal to `rebateTo` address and if it is verified. If yes then pass `msg.sender` as the `rebateTo` otherwise `address(0)`. Also add a check in the `WooPPV2.sol` to add any rebate address only when it is called by `router` contract. If not then add address of `msg.sender`.
