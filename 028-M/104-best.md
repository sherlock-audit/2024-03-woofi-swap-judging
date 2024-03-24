Puny Blue Hawk

high

# All Accumulated Fee Will be drain by attacker

## Summary
The Approval are not removed from router contract and router contract allow arbitrary call to swap tokens on 1inch. it will allow attacker to steal accumulated Fee.

## Vulnerability Detail
When ever there is external swap executed. The protocol approve the router contract to execute the swap, if the swap fail or not possible than protocol transfer directly to receiver and remove approval from router , however there is one case in which approval are not removed from router due to which the Accumulated fee which are stored in router contract can be steal if attacker follow following step.

1).   The `toToken` and `fromToken` are same.
2). the amount to be swap is equal to fee amount accumulated.
3). to address set to attacker address or other address own by attacker.

The 1inch router is whitelisted so arbitrary call will not be blocked and the `minAmount` received checked will be bypass if `toTokan` and `fromToken` are same. so the attacker can call `WooCrossChainRouterV4::crossSwap` function , design the arbitrary calldata by keeping in mind all the required checks and steal the Fee accumulated. 

## Impact
All the accumulated fees can be drain by the attacker.

## Code Snippet
[LOC](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L416)
[LOC](https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/CrossChain/WooCrossRouterForWidget.sol#L104)

The function where approval are not removed:
```javascript
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

        if (toToken == bridgedToken) {
            TransferHelper.safeTransfer(bridgedToken, to, bridgedAmount);
            emit WooCrossSwapOnDstChain(
                refId,
                msgSender,
                to,
                bridgedToken,
                bridgedAmount,
                toToken,
                toToken,
                minToAmount,
                bridgedAmount,
                dst1inch.swapRouter == address(0) ? 0 : 1,
                0
            );
        } else {
            // Deduct the external swap fee
            // bridgedAmount = 10 Token
            // 
            uint256 fee = (bridgedAmount * dstExternalFeeRate) / FEE_BASE;
            bridgedAmount -= fee;
          ...
           } else {
                try wooRouter.swap(bridgedToken, toToken, bridgedAmount, minToAmount, payable(to), to) returns (
                    uint256 realToAmount
                ) {
                ....  
                } catch {
            // @audit-issue : no removal of approval
                    TransferHelper.safeTransfer(bridgedToken, to, bridgedAmount);
                    emit WooCrossSwapOnDstChain(
                        refId,
                        msgSender,
                        to,
                        bridgedToken,
                        bridgedAmount,
                        toToken,
                        bridgedToken,
                        minToAmount,
                        bridgedAmount,
                        dst1inch.swapRouter == address(0) ? 0 : 1,
                        0
                    );
                }
            }
        }
    }


```
## Tool used

Manual Review

## Recommendation

Remove Approval in every case as The protocol support arbitrary data call to 1inch router.
```diff
@@ -475,6 +494,7 @@ contract WooCrossChainRouterV4 is IWooCrossChainRouterV3, Ownable, Pausable, Ree
                         0
                     );
                 } catch {
+            TransferHelper.safeApprove(weth, address(wooRouter), 0);
```
