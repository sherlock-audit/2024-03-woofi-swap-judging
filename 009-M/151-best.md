Sunny Lava Orca

medium

# crossSwap function can revert when the bridgeToken is WETH

## Summary

## Vulnerability Detail
When the bridgeToken is WETH, the _bridgeByStargate function unwraps WETH and adds ETH to the msg.value.

```solidity
if (srcInfos.bridgeToken == weth) {
            
            IWETH(weth).withdraw(bridgeAmount);
            msgValue += bridgeAmount;
        }
```
 Then it calls the stargateRouter.swap function with the pool ID of the bridge token. 

```solidity
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
The problem is that the stargateRouter.swap function will try to transfer the bridgeToken from the caller and revert because the _bridgeByStargate unwrapped the WETH.

https://github.com/stargate-protocol/stargate/blob/c647a3a647fc693c38b16ef023c54e518b46e206/contracts/Router.sol#L107-L134

```solidity
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
## Impact
The crossSwap function can not be usable with WETH.
## Code Snippet
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/65185691c91541e33f84b77d4c6290182f137092/WooPoolV2/contracts/CrossChain/WooCrossChainRouterV4.sol#L219-L267
## Tool used

Manual Review

## Recommendation
Don't unwrap WETH if the bridge token is WETH.