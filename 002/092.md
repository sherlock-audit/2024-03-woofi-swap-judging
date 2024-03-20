Damp Wintergreen Seagull

high

# Swapping via `WooCrossRouterForWidget.crossSwap()` is not viable

## Summary

Third party protocols can interact with woofi protocol via the `WooCrossRouterForWidget.crossSwap()` function, where the incemented nonce is used as a `refId` instead of a hardoced value that's supposed to indicate the type of the executed process by the `stargateRouter` on the destination chain, and this will result in locking users assets in the stargateBridge contract.

## Vulnerability Detail

- Third party protocols can interact with woofi protocol via the `WooCrossRouterForWidget.crossSwap()` function that calls `WooCrossChainRouterV4.crossSwap()` to process cross-chain swapping and bridging, and this is processed via `stargateRouter` that uses layerZero for bridging messages from the source chain to the destination chain where the bridged tokens are going to be received (after doing swap on the destination chain by the `stargateRouter`).

- The transaction will be as follows:

  1.  A third party protocol calls widget contract to execute `crossSwap()`, which will invoke `WooCrossChainRouterV4.crossSwap()` function, where swapping is done if required, then a stargate swap call is prepared via `_bridgeByStargate()`:

  ```javascript
  function crossSwap(
        uint256 refId,
        address payable to,
        SrcInfos memory srcInfos,
        DstInfos calldata dstInfos,
        Src1inch calldata src1inch,
        Dst1inch calldata dst1inch
    ) external payable whenNotPaused nonReentrant {
        //some code...
        _bridgeByStargate(refId, to, msgValue, bridgeAmount, srcInfos, dstInfos, dst1inch);
        //some code...
    }


      function _bridgeByStargate(
        uint256 refId,
        address payable to,
        uint256 msgValue,
        uint256 bridgeAmount,
        SrcInfos memory srcInfos,
        DstInfos calldata dstInfos,
        Dst1inch calldata dst1inch
    ) internal {

        //some code...

        bytes memory payload = abi.encode(refId, to, dstInfos.toToken, dstInfos.minToAmount, dst1inch);

        uint256 dstMinBridgeAmount = (bridgeAmount * (10000 - bridgeSlippage)) / 10000;
        bytes memory dstWooCrossChainRouter = abi.encodePacked(wooCrossRouters[dstInfos.chainId]);

        IStargateRouter.lzTxObj memory obj = IStargateRouter.lzTxObj(
            dstInfos.dstGasForCall,
            dstInfos.airdropNativeAmount,
            abi.encodePacked(to)
        );
        IStargateRouter stargateRouter = IStargateRouter(sgInfo.sgRouter());

        if (srcInfos.bridgeToken == weth) {
            IWETH(weth).withdraw(bridgeAmount);
            msgValue += bridgeAmount;
        } else {
            TransferHelper.safeApprove(srcInfos.bridgeToken, sgInfo.sgRouter(), bridgeAmount);
        }


          stargateRouter.swap{value: msgValue}(
              dstInfos.chainId, // dst chain id
              sgInfo.sgPoolIds(sgInfo.sgChainIdLocal(), srcInfos.bridgeToken), // bridge token's pool id on src chain
              sgInfo.sgPoolIds(dstInfos.chainId, dstInfos.bridgeToken), // bridge token's pool id on dst chain
              payable(_msgSender()), // rebate address
              bridgeAmount, // swap amount on src chain
              dstMinBridgeAmount, // min received amount on dst chain
              obj, // config: dstGasForCall, dstAirdropNativeAmount, dstReceiveAirdropNativeTokenAddr
              dstWooCrossChainRouter, // smart contract to call on dst chain
              payload // payload to piggyback
          );

    }
  ```

  where [`stargateRouter.swap()`](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Router.sol#L107C5-L134C6):

  ```javascript
      function swap(
          uint16 _dstChainId,
          uint256 _srcPoolId,
          uint256 _dstPoolId,
          address payable _refundAddress,
          uint256 _amountLD,
          uint256 _minAmountLD,
          lzTxObj memory _lzTxParams,
          bytes calldata _to,
          bytes calldata _payload
      ) external payable override nonReentrant {
          require(_amountLD > 0, "Stargate: cannot swap 0");
          require(_refundAddress != address(0x0), "Stargate: _refundAddress cannot be 0x0");
          Pool.SwapObj memory s;
          Pool.CreditObj memory c;
          {
              Pool pool = _getPool(_srcPoolId);
              {
                  uint256 convertRate = pool.convertRate();
                  _amountLD = _amountLD.div(convertRate).mul(convertRate);
              }


              s = pool.swap(_dstChainId, _dstPoolId, msg.sender, _amountLD, _minAmountLD, true);
              _safeTransferFrom(pool.token(), msg.sender, address(pool), _amountLD);
              c = pool.sendCredits(_dstChainId, _dstPoolId);
          }
          bridge.swap{value: msg.value}(_dstChainId, _srcPoolId, _dstPoolId, _refundAddress, c, s, _lzTxParams, _to, _payload);
      }
  ```

  2. [`stargateRouter.swap()`](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Router.sol#L107C5-L134C6) will call bridge router that uses a layerzero endpoint to bridge messaging between chains:

  ```javascript
      function swap(
          uint16 _chainId,
          uint256 _srcPoolId,
          uint256 _dstPoolId,
          address payable _refundAddress,
          Pool.CreditObj memory _c,
          Pool.SwapObj memory _s,
          IStargateRouter.lzTxObj memory _lzTxParams,
          bytes calldata _to,
          bytes calldata _payload
      ) external payable onlyRouter {
          bytes memory payload = abi.encode(TYPE_SWAP_REMOTE, _srcPoolId, _dstPoolId, _lzTxParams.dstGasForCall, _c, _s, _to, _payload);
          _call(_chainId, TYPE_SWAP_REMOTE, _refundAddress, _lzTxParams, payload);
      }
      //.....

      function _call(
          uint16 _chainId,
          uint8 _type,
          address payable _refundAddress,
          IStargateRouter.lzTxObj memory _lzTxParams,
          bytes memory _payload
      ) internal {
          bytes memory lzTxParamBuilt = _txParamBuilder(_chainId, _type, _lzTxParams);
          uint64 nextNonce = layerZeroEndpoint.getOutboundNonce(_chainId, address(this)) + 1;
          layerZeroEndpoint.send{value: msg.value}(_chainId, bridgeLookup[_chainId], _payload, _refundAddress, address(this), lzTxParamBuilt);
          emit SendMsg(_type, nextNonce);
      }
  ```

3. Once the transaction is checked and verified by the layerzero endpoint; it will call the stargate bridge adapter on the destination chain on [`stargateBridge.lzReceive()`](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Bridge.sol#L57C1-L111C6), where the `payload` represents the data encoded by `WooCrossChainRouterV4._bridgeByStargate()`:

   ```javascript
       function lzReceive(
           uint16 _srcChainId,
           bytes memory _srcAddress,
           uint64 _nonce,
           bytes memory _payload
       ) external override {
           require(msg.sender == address(layerZeroEndpoint), "Stargate: only LayerZero endpoint can call lzReceive");
           require(
               _srcAddress.length == bridgeLookup[_srcChainId].length && keccak256(_srcAddress) == keccak256(bridgeLookup[_srcChainId]),
               "Stargate: bridge does not match"
           );

           uint8 functionType;
           assembly {
               functionType := mload(add(_payload, 32))
           }

           if (functionType == TYPE_SWAP_REMOTE) {
               (
                   ,
                   uint256 srcPoolId,
                   uint256 dstPoolId,
                   uint256 dstGasForCall,
                   Pool.CreditObj memory c,
                   Pool.SwapObj memory s,
                   bytes memory to,
                   bytes memory payload
               ) = abi.decode(_payload, (uint8, uint256, uint256, uint256, Pool.CreditObj, Pool.SwapObj, bytes, bytes));
               address toAddress;
               assembly {
                   toAddress := mload(add(to, 20))
               }
               router.creditChainPath(_srcChainId, srcPoolId, dstPoolId, c);
               router.swapRemote(_srcChainId, _srcAddress, _nonce, srcPoolId, dstPoolId, dstGasForCall, toAddress, s, payload);
           } else if (functionType == TYPE_ADD_LIQUIDITY) {
               (, uint256 srcPoolId, uint256 dstPoolId, Pool.CreditObj memory c) = abi.decode(_payload, (uint8, uint256, uint256, Pool.CreditObj));
               router.creditChainPath(_srcChainId, srcPoolId, dstPoolId, c);
           } else if (functionType == TYPE_REDEEM_LOCAL_CALL_BACK) {
               (, uint256 srcPoolId, uint256 dstPoolId, Pool.CreditObj memory c, uint256 amountSD, uint256 mintAmountSD, bytes memory to) = abi
                   .decode(_payload, (uint8, uint256, uint256, Pool.CreditObj, uint256, uint256, bytes));
               address toAddress;
               assembly {
                   toAddress := mload(add(to, 20))
               }
               router.creditChainPath(_srcChainId, srcPoolId, dstPoolId, c);
               router.redeemLocalCallback(_srcChainId, _srcAddress, _nonce, srcPoolId, dstPoolId, toAddress, amountSD, mintAmountSD);
           } else if (functionType == TYPE_WITHDRAW_REMOTE) {
               (, uint256 srcPoolId, uint256 dstPoolId, Pool.CreditObj memory c, uint256 amountSD, bytes memory to) = abi.decode(
                   _payload,
                   (uint8, uint256, uint256, Pool.CreditObj, uint256, bytes)
               );
               router.creditChainPath(_srcChainId, srcPoolId, dstPoolId, c);
               router.redeemLocalCheckOnRemote(_srcChainId, _srcAddress, _nonce, srcPoolId, dstPoolId, amountSD, to);
           }
       }
   ```

   4. The `stargateRouter` on the destination chain will be called based on the decoded function placeholder that's extracted from the sent payload, where the [following placeholders](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Bridge.sol#L23C1-L26C54) are defined in the stargate bidge contract:

   ```javascript
       uint8 internal constant TYPE_SWAP_REMOTE = 1;
       uint8 internal constant TYPE_ADD_LIQUIDITY = 2;
       uint8 internal constant TYPE_REDEEM_LOCAL_CALL_BACK = 3;
       uint8 internal constant TYPE_WITHDRAW_REMOTE = 4;
   ```

   5. For the cross-chain swapping, the `functionType` would be **`TYPE_SWAP_REMOTE`**, and the [`stargateRouter.swapRemote()`](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Router.sol#L376C5-L425C6) function will be called, where it will call the `WooCrossChainRouterV4.sgReceive()` of the destination chain:

   ```javascript
   function swapRemote(
       uint16 _srcChainId,
       bytes memory _srcAddress,
       uint256 _nonce,
       uint256 _srcPoolId,
       uint256 _dstPoolId,
       uint256 _dstGasForCall,
       address _to,
       Pool.SwapObj memory _s,
       bytes memory _payload
   ) external onlyBridge {
       _swapRemote(_srcChainId, _srcAddress, _nonce, _srcPoolId, _dstPoolId, _dstGasForCall, _to, _s, _payload);
   }
   ```

   ```javascript
   function _swapRemote(
       uint16 _srcChainId,
       bytes memory _srcAddress,
       uint256 _nonce,
       uint256 _srcPoolId,
       uint256 _dstPoolId,
       uint256 _dstGasForCall,
       address _to,
       Pool.SwapObj memory _s,
       bytes memory _payload
   ) internal {
       Pool pool = _getPool(_dstPoolId);
       // first try catch the swap remote
       try pool.swapRemote(_srcChainId, _srcPoolId, _to, _s) returns (uint256 amountLD) {
           if (_payload.length > 0) {
               // then try catch the external contract call
               try IStargateReceiver(_to).sgReceive{gas: _dstGasForCall}(_srcChainId, _srcAddress, _nonce, pool.token(), amountLD, _payload) {
                   // do nothing
               } catch (bytes memory reason) {
                   cachedSwapLookup[_srcChainId][_srcAddress][_nonce] = CachedSwap(pool.token(), amountLD, _to, _payload);
                   emit CachedSwapSaved(_srcChainId, _srcAddress, _nonce, pool.token(), amountLD, _to, _payload, reason);
               }
           }
       } catch {
           revertLookup[_srcChainId][_srcAddress][_nonce] = abi.encode(
               TYPE_SWAP_REMOTE_RETRY,
               _srcPoolId,
               _dstPoolId,
               _dstGasForCall,
               _to,
               _s,
               _payload
           );
           emit Revert(TYPE_SWAP_REMOTE_RETRY, _srcChainId, _srcAddress, _nonce);
       }
   }
   ```

   6. **The `functionType` is extracted from the decoded payload** that is prepared by the `WooCrossChainRouterV4._bridgeByStargate()`, and as can be noticed from [`stargateBridge.lzReceive()`](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Bridge.sol#L57C1-L111C6) above; **this value is the `refId`** :

   ```javascript
   //@note : stargateBridge.lzReceive():
   function lzReceive(
        uint16 _srcChainId,
        bytes memory _srcAddress,
        uint64 _nonce,
        bytes memory _payload
    ) external override {
        //some code...

        uint8 functionType;
        assembly {
            functionType := mload(add(_payload, 32))
        }
        //some code....
    }

   ```

   ```javascript
   //@note : WooCrossChainRouterV4._bridgeByStargate():
   function _bridgeByStargate(
           uint256 refId,
           address payable to,
           uint256 msgValue,
           uint256 bridgeAmount,
           SrcInfos memory srcInfos,
           DstInfos calldata dstInfos,
           Dst1inch calldata dst1inch
       ) internal {
           //some code...

           bytes memory payload = abi.encode(refId, to, dstInfos.toToken, dstInfos.minToAmount, dst1inch);

       //some code..
           stargateRouter.swap{value: msgValue}(
               dstInfos.chainId, // dst chain id
               sgInfo.sgPoolIds(sgInfo.sgChainIdLocal(), srcInfos.bridgeToken), // bridge token's pool id on src chain
               sgInfo.sgPoolIds(dstInfos.chainId, dstInfos.bridgeToken), // bridge token's pool id on dst chain
               payable(_msgSender()), // rebate address
               bridgeAmount, // swap amount on src chain
               dstMinBridgeAmount, // min received amount on dst chain
               obj, // config: dstGasForCall, dstAirdropNativeAmount, dstReceiveAirdropNativeTokenAddr
               dstWooCrossChainRouter, // smart contract to call on dst chain
               payload // payload to piggyback
           );

       }
   ```

   7. But if we have another look at the `WooCrossRouterForWidget.crossSwap()`, it will be noticed that the `refId` is set to be the nonce that's incremented after each call, while this should be a **hardcoded** value referring to the type of action on the `stargateRouter` on the destination chain, which is in our case the `TYPE_SWAP_REMOTE = 1`:

   ```javascript
   function crossSwap(
           address payable to,
           IWooCrossChainRouterV3.SrcInfos memory srcInfos,
           IWooCrossChainRouterV3.DstInfos memory dstInfos,
           IWooCrossChainRouterV3.Src1inch calldata src1inch,
           IWooCrossChainRouterV3.Dst1inch calldata dst1inch,
           FeeInfo calldata feeInfo
       ) external payable whenNotPaused nonReentrant {
           //some code...

           uint256 refId = nonceCounter.increment(dstInfos.chainId);

           crossRouter.crossSwap{value: msgValue}(refId, to, srcInfos, dstInfos, src1inch, dst1inch);
       }
   ```

## Impact

- This will result in:

  - The first call done by `WooCrossRouterForWidget.crossSwap()` wil be successful as the `refId` will be equal to the nonce of 1.
  - The subsequent calls will not be executed by the `stargateBridge`, resulting in locking the bridged assets in the `stargateBridge` contract (see [`stargateBridge.lzReceive()`](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Bridge.sol#L57C5-L111C6)).

- Note that it's worth mentioning that not checking the `refId` argument of the `_bridgeByStargate()` when users calling the `WooCrossChainRouterV4.crossSwap()` directly not via a third-party will result in the same issue above as well, but not reported separately as the woofi protocol relies on the input sanitization via their UI.

## Code Snippet

[WooCrossRouterForWidget.crossSwap function](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/CrossChain/WooCrossRouterForWidget.sol#L131C6-L133C99)

```javascript
   function crossSwap(
           address payable to,
           IWooCrossChainRouterV3.SrcInfos memory srcInfos,
           IWooCrossChainRouterV3.DstInfos memory dstInfos,
           IWooCrossChainRouterV3.Src1inch calldata src1inch,
           IWooCrossChainRouterV3.Dst1inch calldata dst1inch,
           FeeInfo calldata feeInfo
       ) external payable whenNotPaused nonReentrant {
           //some code...

           uint256 refId = nonceCounter.increment(dstInfos.chainId);

           crossRouter.crossSwap{value: msgValue}(refId, to, srcInfos, dstInfos, src1inch, dst1inch);
       }
```

## Tool used

Manual Review

## Recommendation

Update `WooCrossRouterForWidget.crossSwap()` function to send the correct `refId`:

```diff
function crossSwap(
        address payable to,
        IWooCrossChainRouterV3.SrcInfos memory srcInfos,
        IWooCrossChainRouterV3.DstInfos memory dstInfos,
        IWooCrossChainRouterV3.Src1inch calldata src1inch,
        IWooCrossChainRouterV3.Dst1inch calldata dst1inch,
        FeeInfo calldata feeInfo
    ) external payable whenNotPaused nonReentrant {
        //some code...

-       uint256 refId = nonceCounter.increment(dstInfos.chainId);

-       crossRouter.crossSwap{value: msgValue}(refId, to, srcInfos, dstInfos, src1inch, dst1inch);
+       crossRouter.crossSwap{value: msgValue}(1, to, srcInfos, dstInfos, src1inch, dst1inch);
    }
```
