Tangy Gunmetal Robin

medium

# Potential damages due to incorrect implementation of the ````ZIP```` algorithm

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
