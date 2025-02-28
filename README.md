# NoFeeSwap Security Report

### Nofeeswap.sol 

#### Reentrancy Vulnerability in unlock Function - HIGH SEVERITY

The unlock function makes an external call to an untrusted address (unlockTarget) before checking the readNonzeroAmounts() condition. This creates a potential reentrancy vector, as the external call could manipulate state before the check is performed.


The `unlockProtocol` function (lines 150-157) stores two addresses in transient storage:
```solidity
function unlockProtocol(address unlockTarget, address caller) {
  // Writes 'unlockTarget' on the dedicated transient storage slot.
  writeTransient(unlockTargetSlot, unlockTarget);

  // Writes 'caller' on the dedicated transient storage slot.
  writeTransient(callerSlot, caller);
}

```
This function marks the protocol as "unlocked" and tracks who requested the unlock. There's no validation or access control here to limit which addresses can be used as `unlockTarget`.

Potential reentrancy vulnerability

1. The `unlock` function in Nofeeswap.sol calls `unlockProtocol` to mark the state as unlocked
2. It then performs an external call to the `unlockTarget` address
3. After the external call, it checks `require(readNonzeroAmounts() == 0, OutstandingAmount())`
4. Finally, it calls `lockProtocol()` to reset the state

There is a potential reentrancy vulnerability here because:

1. The external call happens before the `readNonzeroAmounts()` check
2. If the `unlockTarget` is malicious, it could call back into the contract before the check is performed
3. There's no reentrancy guard to prevent this

#### Lack of Transfer Return Value Validation in take() Methods - HIGH SEVERITY

The take() functions in the Nofeeswap contract fail to validate the return values of token transfers. These functions call transfer() directly on arbitrary token addresses without checking whether the transfers succeeded.

```
function take(
  address token,
  address to,
  uint256 amount
) external override {
  isProtocolUnlocked();
  updateTransientBalance(msg.sender, token.tag(), amount.toInt256());
  token.transfer(to, amount);  // Return value not checked
}
```

Some tokens revert on transfer failure others return false instead of reverting. When the protocol calls token.transfer() without validating its return value, failed transfers can go undetected, causing the protocol's internal accounting to become inconsistent with actual token balances.

This vulnerability can lead to serious accounting discrepancies:

* The protocol will update its internal transient balances assuming transfers succeeded
* If a transfer silently fails, users could effectively receive "phantom" tokens in the protocol while actual tokens remain locked
* This could potentially be exploited to manipulate protocol reserves or create artificial liquidity

#### Vulnerable Reserve Updates in sync() Functions - HIGH SEVERITY

The sync() functions in the Nofeeswap contract update token reserves based on the current balance of tokens in the contract without validating how those balances were changed.

```
function sync(
  address token
) external override {
  writeReserveToken(token, false);
  if (token != address(0)) {
    writeReserveValue(token.balanceOfSelf());  // Directly uses current balance
  }
}

function sync(
  address token,
  uint256 tokenId
) external override {
  writeReserveToken(token, true);
  writeReserveTokenId(tokenId);
  writeReserveValue(token.balanceOfSelf(tokenId));  // Directly uses current balance
}
```

The function blindly records the contract's token balance as the official reserve without verifying whether those balances resulted from protocol-authorized operations. This allows external actors to manipulate the contract's reserve values by sending tokens directly to the contract address.

This vulnerability enables several attack vectors:

* Reserve manipulation: Attackers can artificially inflate reserves by sending tokens directly to the contract and calling sync(), potentially affecting pricing mechanisms, collateralization ratios, or other protocol operations that rely on accurate reserve data.
* Flash loan attacks: An attacker could use flash loans to temporarily manipulate contract balances, call sync(), and then exploit the temporarily inflated reserves for financial gain.
* Economic attacks: In a liquidity pool context, artificially modified reserves could lead to incorrect price calculations, enabling profitable arbitrage at the expense of legitimate users.
* Special token issues: Rebasing tokens, fee-on-transfer tokens, or tokens with built-in inflation mechanisms could cause continuous accounting discrepancies when sync() is called.

### StorageAccess.sol 

#### Storage Slot Exposure - CRITICAL SEVERITY

The `Nofeeswap` contract inherits from `StorageAccess`, which exposes three public view functions that allow unrestricted reading of arbitrary storage slots. These functions have no access controls, meaning any external actor can directly read any storage slot in the contract, including sensitive data.

The inheritance of StorageAccess provides the following methods without any access restrictions:

```
function storageAccess(bytes32 slot) external view returns (bytes32)

function storageAccess(bytes32 startSlot, uint256 nSlots) external view returns (bytes32[] memory)

function storageAccess(bytes32[] calldata slots) external view returns (bytes32[] memory)
```

These functions allow anyone to read any storage slot by providing its key. The contract uses specific key derivation functions like `getSingleBalanceSlot` and `getAllowanceSlot` to organize its data, but these slots can be directly calculated by an attacker.

```
contract StorageAccess is IStorageAccess {
  /// @inheritdoc IStorageAccess
  function storageAccess(
    bytes32 slot
  ) external view override returns (bytes32) {
    assembly ("memory-safe") {
      mstore(0, sload(slot))
      return(0, 0x20)
    }
  }

  //... rest of the code
}
```

#### Lack of Access Control on Storage Reading Functions - CRITICAL SEVERITY

The StorageAccess contract, inherited by Nofeeswap, provides functionality to read arbitrary storage slots without any access control mechanisms. While the contract implements access controls for state-modifying functions through the isProtocolUnlocked() check, the storage reading functions have no restrictions, allowing any external actor to access sensitive protocol data.

The unrestricted access to storage reading functions allows any address to:

* Access sensitive user financial data (balances, allowances)
* Read protocol administration information, including the admin address
* Extract proprietary parameters related to pool pricing and logic
* Monitor internal protocol state for potential exploitation
* Access information that could enable other attack vectors

This vulnerability fundamentally undermines the confidentiality model of the entire protocol, potentially exposing users to privacy violations and targeted attacks.

The following functions from StorageAccess are inherited by Nofeeswap without any access controls:

```
function storageAccess(bytes32 slot) external view override returns (bytes32) {
  assembly ("memory-safe") {
    mstore(0, sload(slot))
    return(0, 0x20)
  }
}

function storageAccess(bytes32 startSlot, uint256 nSlots) external view override returns (bytes32[] memory) {
  // No access control check
  // Implementation details...
}

function storageAccess(bytes32[] calldata slots) external view override returns (bytes32[] memory) {
  // No access control check
  // Implementation details...
}
```
This contrasts with other sensitive functions in the contract that do implement access controls:

```
function modifyBalance(address owner, Tag tag, int256 amount) external override {
  isProtocolUnlocked(); // Access control check
  // Implementation details...
}
```

#### Unbounded Array Iteration - Low Severity

The StorageAccess contract, which is inherited by Nofeeswap, contains functions that allow reading multiple storage slots without imposing any upper bound on the number of slots that can be read in a single call.

This issue may lead to transactions consuming excessive gas, potentially reaching the block gas limit and causing transaction failures if an excessive number of slots is requested. While this doesn't directly impact fund security, it could impact contract usability and availability in specific scenarios.

```
function storageAccess(
  bytes32 startSlot,
  uint256 nSlots
) external view override returns (bytes32[] memory) {
  assembly ("memory-safe") {
    // ... 
    // A loop over the number of slots to be read with no upper bound check
    for {} 1 {} {
      // ...
      if iszero(lt(freeMemoryPointer, end)) { break }
    }
    // ...
  }
}
```
These functions will attempt to read as many slots as requested, even if the request exceeds practical gas limits.

#### Insecure Inheritance Exposes Protected Contract Data - HIGH SEVERITY

The Nofeeswap contract inherits from StorageAccess, which provides unrestricted methods to read any storage slot. This inheritance pattern allows all storage variables in Nofeeswap to be exposed, including those intended to be private or protected, effectively breaking the access control mechanisms of the entire inheritance tree.

Due to this inheritance pattern:

* All private and internal state variables in Nofeeswap become readable by any external caller
* Storage variables that should only be accessible through controlled getter methods are directly exposed
* Any future contracts that inherit from Nofeeswap will automatically inherit this vulnerability
* Protocol-specific data that was designed to be encapsulated becomes publicly accessible

This fundamentally breaks the encapsulation model of the contract system and exposes potentially sensitive internal state.

Solidity's inheritance model places storage variables sequentially in storage slots. When Nofeeswap inherits from StorageAccess, it gains all the public methods of StorageAccess, including:

```
function storageAccess(bytes32 slot) external view override returns (bytes32)
```

This allows anyone to directly read any storage slot in the Nofeeswap contract, regardless of the visibility modifiers (private, internal, etc.) used for state variables.

For example, in the Nofeeswap constructor:

```
constructor(address _delegatee, address admin) {
  nofeeswap = address(this);
  delegatee = _delegatee;
  writeProtocol(uint256(uint160(admin)) & type(uint160).max);
}
```

The admin address is stored in a storage slot that should be protected, but can be directly accessed through the inherited storageAccess methods.

#### Potential Slot Manipulation in Future Upgrades - HIGH SEVERITY

The Nofeeswap contract inherits from StorageAccess, which allows reading arbitrary storage slots. This becomes a critical concern in the context of the project's governance system, which is explicitly designed to enable upgrades through the GovernorBravoDelegate contract.

The combination of unrestricted storage access and an upgradeability mechanism creates a dangerous scenario where:

* Future upgrades may alter the storage layout of the contract
* Storage slots that contain non-sensitive data in current versions might store sensitive information in upgraded versions
* Attackers could monitor storage slots across upgrades to gain information advantage
* The governance system could inadvertently compromise security by introducing changes that interact poorly with the unrestricted storage access

This vulnerability becomes particularly serious as the project seems to be designed with governance-controlled upgrades in mind, as evidenced by the governance system implemented in GovernorBravoDelegate.

The GovernorBravoDelegate contract allows executing arbitrary transactions through governance proposals:

```
function execute(uint proposalId) external payable {
    require(state(proposalId) == ProposalState.Queued, "GovernorBravo::execute: proposal can only be executed if it is queued");
    Proposal storage proposal = proposals[proposalId];
    proposal.executed = true;
    for (uint i = 0; i < proposal.targets.length; i++) {
        timelock.executeTransaction{value: proposal.values[i]}(proposal.targets[i], proposal.values[i], proposal.signatures[i], proposal.calldatas[i], proposal.eta);
    }
    emit ProposalExecuted(proposalId);
}
```

Meanwhile, the Nofeeswap contract allows unrestricted access to any storage slot:

```
function storageAccess(bytes32 slot) external view override returns (bytes32) {
    assembly ("memory-safe") {
        mstore(0, sload(slot))
        return(0, 0x20)
    }
}
```

When combined, these features create a scenario where upgrades executed through governance could inadvertently expose sensitive information through the unrestricted storage access functions.