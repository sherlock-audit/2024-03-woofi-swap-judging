Muscular Cedar Koala

high

# swap mechanisms allowing outdated slippage and allow pending transaction to be unexpectedly executed

## Summary
swap mechanisms lack `deadline` checks. 
## Vulnerability Detail
if we look at the swap functions in contracts we can see there is no deadline check in them.
## Impact
AMMs provide their users with an option to limit the execution of their pending actions, such as swaps or adding and removing liquidity. The most common solution is to include a deadline timestamp as a parameter (for example see Uniswap V2 and Uniswap V3). If such an option is not present, users can unknowingly perform bad trades:
e.g.
Alice wants to swap 100 tokens for 1 ETH and later sell the 1 ETH for 1000 DAI.

The transaction is submitted to the mempool, however, Alice chose a transaction fee that is too low for miners to be interested in including her transaction in a block. The transaction stays pending in the mempool for extended periods, which could be hours, days, weeks, or even longer.

When the average gas fee dropped far enough for Alice's transaction to become interesting again for miners to include it, her swap will be executed. In the meantime, the price of ETH could have drastically changed. She will still get 1 ETH but the DAI value of that output might be significantly lower.

She has unknowingly performed a bad trade due to the pending transaction she forgot about.

An even worse way this issue can be maliciously exploited is through MEV:

The swap transaction is still pending in the mempool. Average fees are still too high for miners to be interested in it.

The price of tokens has gone up significantly since the transaction was signed, meaning Alice would receive a lot more ETH when the swap is executed. But that also means that her slippage value ( `minToAmount` / base/qoute) is outdated and would allow for significant slippage.

A MEV bot detects the pending transaction. Since the outdated maximum slippage value now allows for high `slippage`, the bot sandwiches Alice, resulting in significant profit for the bot and significant loss for Alice.
## Code Snippet
```solidity 

function externalSwap(
        address approveTarget,
        address swapTarget,
        address fromToken,
        address toToken,
        uint256 fromAmount,
        uint256 minToAmount,
        address payable to,
        bytes calldata data
    ) external payable override nonReentrant returns (uint256 realToAmount) {
        require(approveTarget != address(0), "WooRouter: approveTarget_ADDR_ZERO");
        require(swapTarget != address(0), "WooRouter: swapTarget_ADDR_ZERO");
        require(fromToken != address(0), "WooRouter: fromToken_ADDR_ZERO");
        require(toToken != address(0), "WooRouter: toToken_ADDR_ZERO");
        require(to != address(0), "WooRouter: to_ADDR_ZERO");
        require(isWhitelisted[approveTarget], "WooRouter: APPROVE_TARGET_NOT_ALLOWED");
        require(isWhitelisted[swapTarget], "WooRouter: SWAP_TARGET_NOT_ALLOWED");

        uint256 preBalance = _generalBalanceOf(toToken, address(this));
        _internalFallbackSwap(approveTarget, swapTarget, fromToken, fromAmount, data);
        uint256 postBalance = _generalBalanceOf(toToken, address(this));

        require(preBalance <= postBalance, "WooRouter: balance_ERROR");
        realToAmount = postBalance - preBalance;
        require(realToAmount >= minToAmount && realToAmount > 0, "WooRouter: realToAmount_NOT_ENOUGH");
        _generalTransfer(toToken, to, realToAmount);

        emit WooRouterSwap(SwapType.DodoSwap, fromToken, toToken, fromAmount, realToAmount, msg.sender, to, address(0));
    }
```
   
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/WooRouterV2.sol#L162
    
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/WooRouterV2.sol#L113

    
## Tool used

Manual Review

## Recommendation
- consider implementing `Deadline` check to all swap functions. 
you can check like that as almost most of the swap projects like [uniswap ](https://github.com/Uniswap/v2-periphery/blob/0335e8f7e1bd1e8d8329fd300aea2ef2f36dd19f/contracts/UniswapV2Router02.sol#L244) did like that
```solidity 
modifier ensure(uint deadline) {
	require(deadline >= block.timestamp, 'UniswapV2Router: EXPIRED');
	_;
}
``` 