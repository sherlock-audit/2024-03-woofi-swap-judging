Damp Wintergreen Seagull

high

# `WooCrossChainRouterV4.sgReceive()` function can receive calls from any source chain to drain its funds

## Summary

`WooCrossChainRouterV4.sgReceive()` function doesn't validate the address that initiated the bridging call in the source chain, which opens the door for actors to drain the accumulated fees in the contract.

## Vulnerability Detail

- `WooCrossChainRouterV4.sgReceive()` functionis supposed to be called by the `stargateRouter` that transferred the bridging message from the cross-chain router in the source chain to the cross-chain router in the destination chain, where ths message is decoded and the bridged tokens are transferred to the receiver in the destination chain:

  ```javascript
  function sgReceive(
          uint16, // srcChainId
          bytes memory, // srcAddress
          uint256, // nonce
          address bridgedToken,
          uint256 amountLD,
          bytes memory payload
      ) external {
          require(msg.sender == sgInfo.sgRouter(), "WooCrossChainRouterV3: INVALID_CALLER");

          // make sure the same order to abi.encode when decode payload
          (uint256 refId, address to, address toToken, uint256 minToAmount, Dst1inch memory dst1inch) = abi.decode(
              payload,
              (uint256, address, address, uint256, Dst1inch)
          );

          // toToken won't be SGETH, and bridgedToken won't be ETH_PLACEHOLDER_ADDR
          if (bridgedToken == sgInfo.sgETHs(sgInfo.sgChainIdLocal())) {
              // bridgedToken is SGETH, received native token
              _handleNativeReceived(refId, to, toToken, amountLD, minToAmount, dst1inch);
          } else {
              // bridgedToken is not SGETH, received ERC20 token
              _handleERC20Received(refId, to, toToken, bridgedToken, amountLD, minToAmount, dst1inch);
          }
      }
  ```

- But as can be noticed; there's no validation on the sender of the bridged message being a valid/whitelisted cross-chain router contract or not.

## Impact

This will open the door for any malicious actor to craft a bridging message in any of the source chains and send it to the cross-router of any of the destination chains via `stargateRouter`, where this message is transferring the accumulated fees of the cross-chain contract (being native token or any ERC20).

## Code Snippet

[WooCrossChainRouterV4.sgReceive function](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L157C5-L181C6)

```javascript
function sgReceive(
        uint16, // srcChainId
        bytes memory, // srcAddress
        uint256, // nonce
        address bridgedToken,
        uint256 amountLD,
        bytes memory payload
    ) external {
        require(msg.sender == sgInfo.sgRouter(), "WooCrossChainRouterV3: INVALID_CALLER");

        // make sure the same order to abi.encode when decode payload
        (uint256 refId, address to, address toToken, uint256 minToAmount, Dst1inch memory dst1inch) = abi.decode(
            payload,
            (uint256, address, address, uint256, Dst1inch)
        );

        // toToken won't be SGETH, and bridgedToken won't be ETH_PLACEHOLDER_ADDR
        if (bridgedToken == sgInfo.sgETHs(sgInfo.sgChainIdLocal())) {
            // bridgedToken is SGETH, received native token
            _handleNativeReceived(refId, to, toToken, amountLD, minToAmount, dst1inch);
        } else {
            // bridgedToken is not SGETH, received ERC20 token
            _handleERC20Received(refId, to, toToken, bridgedToken, amountLD, minToAmount, dst1inch);
        }
    }
```

## Tool used

Manual Review

## Recommendation

- Add a mechanism to whitelist source chain contracts, and check against it in the `sgReceive()` function.
- Don't allow accumulating any fees in the `WooCrossChainRouterV4` contract, this can be done by directly sending any charged fees to the `feeAddr` once charged (mainly charged ehn external swaps are done via 1inch aggregator).
