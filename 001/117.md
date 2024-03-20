Acrobatic Sable Falcon

medium

# Woooracle doesn't handle properly stale woPrice for each base token.

## Summary
Woooracle doesn't handle properly stale woPrice for each base token. 
Last timestamp being posted price is applied to all base tokens simultaneously even if one of base tokens has not been posted price for a long time. 

## Vulnerability Detail
timestamp storage variable is used for checking if woPrice is stale and it is updated when price/state of any token is updated.
```solidity
    function postPrice(address _base, uint128 _price) external onlyAdmin {
        infos[_base].price = _price;
        if (msg.sender != wooPP) {
            timestamp = block.timestamp;
        }
   }

    function postState(
        address _base,
        uint128 _price,
        uint64 _spread,
        uint64 _coeff
    ) external onlyAdmin {
        _setState(_base, _price, _spread, _coeff);
        timestamp = block.timestamp;
    }
```
`timestamp` is updated if price/state of any token is posted, and it is used for all base tokens for checking staleness. 
```solidity
    function price(address _base) public view override returns (uint256 priceOut, bool feasible) {
        uint256 woPrice_ = uint256(infos[_base].price);
        uint256 woPriceTimestamp = timestamp;

        (uint256 cloPrice_, ) = _cloPriceInQuote(_base, quoteToken);

@>      bool woFeasible = woPrice_ != 0 && block.timestamp <= (woPriceTimestamp + staleDuration);
        bool woPriceInBound = cloPrice_ == 0 ||
            ((cloPrice_ * (1e18 - bound)) / 1e18 <= woPrice_ && woPrice_ <= (cloPrice_ * (1e18 + bound)) / 1e18);

        if (woFeasible) {
            priceOut = woPrice_;
            feasible = woPriceInBound;
        } else {
            priceOut = clOracles[_base].cloPreferred ? cloPrice_ : 0;
            feasible = priceOut != 0;
        }
    }
```

## Impact
If there is no swap for a specific token for a long period of time, price staleness is not accurately guaranteed and the swap may be executed at the wrong price.

## Code Snippet
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L139-L144
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L149-L156
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L161-L176
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L183-L191
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L199-L208
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L215-L229
https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/wooracle/WooracleV2_2.sol#L243-L260

## Tool used

Manual Review

## Recommendation
`timestamp` should be used as the mapping type stored for each base token and independently updated for each token.