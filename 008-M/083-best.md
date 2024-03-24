Damp Wintergreen Seagull

medium

# `WooCrossChainRouterV4.crossSwap()`: doesn't check if the `msg.value` is sufficient for destination call which would result in bridged tokens being stuck in the `stargateRouter` contract

## Summary

Insufficient gas sent from the source chain to cover the destination call gas fees (insufficient `dstInfos.dstGasForCall` ) would result in bridged tokens being stuck in the `stargateRouter` contract.

## Vulnerability Detail

- `WooCrossChainRouterV4.crossSwap()` function is supposed to be called by users to process cross-chain swapping/bridging, and this is processed via `stargateRouter` that uses layerZero for bridging messages from the source chain to the destination chain where the bridged tokens are going to be received (after doing swap on the destination chain by the `stargateRouter` if required).

- The process will be as follows:

  1.  Users call `WooCrossChainRouterV4.crossSwap()` function, where swapping is done if required, then a stargate swap call is prepared via `_bridgeByStargate()`:

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

  where `obj` represents the gas parameters that are going to be send to the layerzero endpoint `send()` function, and the `dstInfos.dstGasForCall` represents **the gas to cover transaction execution on the destination chain**.
  and [`stargateRouter.swap()`](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Router.sol#L107C5-L134C6):

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

  2. [`stargateRouter.swap()`](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Router.sol#L107C5-L134C6) will call the stargate bridge router that uses a layerzero endpoint to bridge messaging between chains:

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

  4.  The `stargateRouter` on the destination chain will be called based on the decoded function placeholder that's extracted from the sent payload, where the [following placeholders](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Bridge.sol#L23C1-L26C54) are defined in the stargate bidge contract:

  ```javascript
      uint8 internal constant TYPE_SWAP_REMOTE = 1;
      uint8 internal constant TYPE_ADD_LIQUIDITY = 2;
      uint8 internal constant TYPE_REDEEM_LOCAL_CALL_BACK = 3;
      uint8 internal constant TYPE_WITHDRAW_REMOTE = 4;
  ```

  5.  For the cross-chain swapping, the `functionType` would be `TYPE_SWAP_REMOTE`, and the [`stargateRouter.swapRemote()`](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Router.sol#L376C5-L425C6) function will be called, where it will call the `WooCrossChainRouterV4.sgReceive()` of the destination chain:

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

## Impact

**The following scenarios could happen due to insufficient gas provided for the call on the destination chain:**

#### First Scenario

- If the sent gas is sufficient to execute the call from the `stargateBridge` to the `stargateRouter` but the remaining gas is insufficient to execute the call from the `stargateRouter` to the `WooCrossChainRouterV4.sgReceive()`: since the call from the `stargateRouter` to the `WooCrossChainRouterV4.sgReceive()` of the destination chain is executed in the second try/catch block; then it will be catched by the `stargateRouter` and saved in `cachedSwapLookup[_srcChainId][_srcAddress][_nonce]` to be retried later via [`stargateRouter.clearCachedSwap`](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Router.sol#L285C3-L295C6).

- **And since the `WooCrossChainRouterV4` contract doesn't implement a method to retry failed `stargateRouter` messages;** this would result in locking the bridged tokens in the `stargateRouter` contract **unless** the failed transaction parameters (`srcChainId`, `srcAddress` & `nonce`) are manually collected and the transaction is retried again via [`stargateRouter.clearCachedSwap`](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Router.sol#L285C3-L295C6).

#### Second Scenario

- If the transaction fails in the first try/catch block of the `stargateRouter._swapRemote()` when `pool.swapRemote()` fails due to insufficient gas where the failed transaction will be saved in `revertLookup[_srcChainId][_srcAddress][_nonce]`; then another scenario would happen if the gas is insufficient to retry the failed transaction via [`stargateRouter.retryRevert()`](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Router.sol#L250C5-L283C6), and in this case the bridged tokens will be **permanently** locked in the `stargateRouter` contract:

  ```javascript
  //@note : stargateRouter.retryRevert() function:
      function retryRevert(
          uint16 _srcChainId,
          bytes calldata _srcAddress,
          uint256 _nonce
      ) external payable {
          bytes memory payload = revertLookup[_srcChainId][_srcAddress][_nonce];
          require(payload.length > 0, "Stargate: no retry revert");


          // empty it
          revertLookup[_srcChainId][_srcAddress][_nonce] = "";


          uint8 functionType;
          assembly {
              functionType := mload(add(payload, 32))
          }


          if (functionType == TYPE_REDEEM_LOCAL_CALLBACK_RETRY) {
              (, uint256 srcPoolId, uint256 dstPoolId, address to, uint256 amountSD, uint256 mintAmountSD) = abi.decode(
                  payload,
                  (uint8, uint256, uint256, address, uint256, uint256)
              );
              _redeemLocalCallback(_srcChainId, _srcAddress, _nonce, srcPoolId, dstPoolId, to, amountSD, mintAmountSD);
          }
          // for retrying the swapRemote. if it fails again, retry
          else if (functionType == TYPE_SWAP_REMOTE_RETRY) {
              (, uint256 srcPoolId, uint256 dstPoolId, uint256 dstGasForCall, address to, Pool.SwapObj memory s, bytes memory p) = abi.decode(
                  payload,
                  (uint8, uint256, uint256, uint256, address, Pool.SwapObj, bytes)
              );
              _swapRemote(_srcChainId, _srcAddress, _nonce, srcPoolId, dstPoolId, dstGasForCall, to, s, p);
          } else {
              revert("Stargate: invalid function type");
          }
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

#### Third Scenario

- Another scenario would happen if the provided gas is insufficient to execute the call by the stargate bridge, where this will result in blocking the stargate bridge channel as the `stargateBridge.lzReceive()` doesn't implement a non-blocking mechanism for the failed transaction (doesn't execute the call in a try/catch block), so it will be catched and stored by the layerzero endpoint [`receivePayload()`](https://github.com/LayerZero-Labs/LayerZero/blob/48c21c3921931798184367fc02d3a8132b041942/contracts/Endpoint.sol#L118C8-L124C10) to be manually retried later by the layerzero endpoint [`retryPayload()` function](https://github.com/LayerZero-Labs/LayerZero/blob/48c21c3921931798184367fc02d3a8132b041942/contracts/Endpoint.sol#L127C5-L142C6):

```javascript
//@note : layerZeroEndPoint.retryPayload() function:
        try ILayerZeroReceiver(_dstAddress).lzReceive{gas: _gasLimit}(_srcChainId, _srcAddress, _nonce, _payload) {
            // success, do nothing, end of the message delivery
        } catch (bytes memory reason) {
            // revert nonce if any uncaught errors/exceptions if the ua chooses the blocking mode
            storedPayload[_srcChainId][_srcAddress] = StoredPayload(uint64(_payload.length), _dstAddress, keccak256(_payload));
            emit PayloadStored(_srcChainId, _srcAddress, _dstAddress, _nonce, _payload, reason);
        }
```

## Code Snippet

[WooCrossChainRouterV4.crossSwap function](https://github.com/woonetwork/WooPoolV2/blob/a99e13de1492c17a325fff6cddb3696cd7db7dc9/contracts/CrossChain/WooCrossChainRouterV4.sol#L141)

```javascript
    function crossSwap(
        uint256 refId,
        address payable to,
        SrcInfos memory srcInfos,
        DstInfos calldata dstInfos,
        Src1inch calldata src1inch,
        Dst1inch calldata dst1inch
    ) external payable whenNotPaused nonReentrant {
        require(srcInfos.fromToken != address(0), "WooCrossChainRouterV3: !srcInfos.fromToken");
        require(
            dstInfos.toToken != address(0) && dstInfos.toToken != sgInfo.sgETHs(dstInfos.chainId),
            "WooCrossChainRouterV3: !dstInfos.toToken"
        );
        require(to != address(0), "WooCrossChainRouterV3: !to");

        uint256 msgValue = msg.value;
        uint256 bridgeAmount;
        uint256 fee = 0;

        {
            // Step 1: transfer
            if (srcInfos.fromToken == ETH_PLACEHOLDER_ADDR) {
                require(srcInfos.fromAmount <= msgValue, "WooCrossChainRouterV3: !srcInfos.fromAmount");
                srcInfos.fromToken = weth;
                IWETH(weth).deposit{value: srcInfos.fromAmount}();
                msgValue -= srcInfos.fromAmount;
            } else {
             //some code...
            }

            // Step 2: local swap by 1inch router
            //some code...

        }

        //some code...

        // Step 4: cross chain swap by StargateRouter
        _bridgeByStargate(refId, to, msgValue, bridgeAmount, srcInfos, dstInfos, dst1inch);

      //some code...
    }
```

[WooCrossChainRouterV4.\_bridgeByStargate function/L256-L266](https://github.com/woonetwork/WooPoolV2/blob/a99e13de1492c17a325fff6cddb3696cd7db7dc9/contracts/CrossChain/WooCrossChainRouterV4.sol#L256C9-L266C11)

```javascript
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
```

## Tool used

Manual Review

## Recommendation

In `WooCrossChainRouterV4._bridgeByStargate()` function: validate that `msg.value` is sufficient for required gas to execute the transaction on the destination chain (`dstInfos.dstGasForCall`), this can be done by enforcing a` minimum gas*safety factor` for each destination chain.
