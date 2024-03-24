Jumpy Seaweed Haddock

medium

# Migration of Quote Token Will Revert Due to Using Different BalanceOf

## Summary

Different `balance`/`balanceOf` used in `migrateToNewPool` makes the function not work (always revert).

## Vulnerability Detail

`WooPPV2#migrateToNewPool` approves `balance(token)` and then calls the `depositAll` in the new pool. `depositAll` uses `balanceOf(token)`, rather than `balance(token)`, and this will be the root cause of this issue writeup.

The difference between the two balance functions is that `balance` subtracts the `unclaimedFee` from the token balance. Therefore, when `unclaimedFee > 0`, then balance(token) is less than `balanceOf(token)`.

```solidity
function balance(address token) public view returns (uint256) {
        return token == quoteToken ? _rawBalance(token) - unclaimedFee : _rawBalance(token);
    }
```

During migration, the transfer attempt will revert due to insufficient approval as the approved amount (`balance`) is less than the attempted transfer amount (`balanceOf`). Even if `claimFee` is called before the migration, it only takes a single swap, either incidentally or via a malicious frontrunner to make the unclaimedFee go above 0 and therefore make the migration revert.

## Impact

Migration of quote tokens to a new pool will revert. Even if fees are claimed, a single swap could DOS a subsequent attempt at migration.

## Code Snippet

https://github.com/sherlock-audit/2024-03-woofi-swap/blob/main/WooPoolV2/contracts/WooPPV2.sol#L344

## Tool used

Manual Review

## Recommendation

Either of these solutions will work:

1. Use the same `balance` in `depositAll` and line `TransferHelper.safeApprove(token, newPool, bal);`

2. claim fee within the `MigrateToNewPool` function before the balance approvals and transfers.
