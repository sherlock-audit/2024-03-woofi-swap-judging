Icy Denim Cougar

medium

# Extra gas in native token will be sent to the WooCrossRouterForWidget contract instead of the user

## Summary
When users do a cross swap using the widget contract the excess fee will be sent to the widget contract but not to the user.
## Vulnerability Detail
First, let's understand the cross swap cycle when its initiated by an user from Widget contract:

[User calls Widget](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/CrossChain/WooCrossRouterForWidget.sol#L104-L111)
[Widget calls WooFiCrosschainRouter](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/CrossChain/WooCrossRouterForWidget.sol#L133)
[WooFiCrosschainRouter calls StargateRouter](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L256-L267) **4th argument is the "msg.sender" which is the refund address for LayerZero**
[StargateRouter calls StargateBridge](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Router.sol#L133)
[StargateBridge calls L0Endpoint](https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Bridge.sol#L304)
[L0Endpoint calls UltraLightNode](https://github.com/LayerZero-Labs/LayerZero/blob/48c21c3921931798184367fc02d3a8132b041942/contracts/Endpoint.sol#L95)

and finally the fee is calculated in the UltraLightNode contract as follows:
```solidity
function send(address _ua, uint64, uint16 _dstChainId, bytes calldata _path, bytes calldata _payload, address payable _refundAddress, address _zroPaymentAddress, bytes calldata _adapterParams) external payable override onlyEndpoint {
        .
        .
        .
        // compute all the fees
        -> uint relayerFee = _handleRelayer(dstChainId, uaConfig, ua, payload.length, _adapterParams);
        -> uint oracleFee = _handleOracle(dstChainId, uaConfig, ua);
        -> uint nativeProtocolFee = _handleProtocolFee(relayerFee, oracleFee, ua, _zroPaymentAddress);

        // total native fee, does not include ZRO protocol fee
        -> uint totalNativeFee = relayerFee.add(oracleFee).add(nativeProtocolFee);

        // assert the user has attached enough native token for this address
        -> require(totalNativeFee <= msg.value, "LayerZero: not enough native for fees");
        // refund if they send too much
        -> uint amount = msg.value.sub(totalNativeFee);
        if (amount > 0) {
            -> (bool success, ) = _refundAddress.call{value: amount}("");
            -> require(success, "LayerZero: failed to refund");
        }

        // emit the data packet
        bytes memory encodedPayload = abi.encodePacked(nonce, localChainId, ua, dstChainId, dstAddress, payload);
        emit Packet(encodedPayload);
    }
```

As we can observe in above code snippet, if there are excess native sent then it's refunded back to the refund address. Now, let's trace back and see what's the refund address that's been sent to UltraLightNode. The refund address is set to "msg.sender" first in the WooFiCrosschainRouter (see above) and then the address passed on to others. Since the "msg.sender" is the Widget contract and not the user, the excess native tokens will be sent to the Widget contract.
## Impact
Although it seems like an user mistake to sent more native than calculated, the issue is I think medium because:
Users query the LayerZero fee off-chain and sign the tx onchain. The time spent between querying off chain and sending the tx can make the fee sent lesser or higher. If its lesser the tx will revert, if its higher the excess is lost for the user. Hence, it is very likely that the refund is required. Ideally users should be sending such fee amount that it is slightly more than the estimated fee. 
## Code Snippet
https://github.com/LayerZero-Labs/LayerZero/blob/48c21c3921931798184367fc02d3a8132b041942/contracts/UltraLightNodeV2.sol#L116-L161
## Tool used

Manual Review

## Recommendation
instead of msg.sender, use tx.origin inside the crosschainrouter contract