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

### TransientAccess.sol

#### Infinite Loop Risk in TransientAccess Contract - Medium Severity

The TransientAccess contract implements a non-standard infinite loop pattern in the assembly code that relies on a specific break condition to terminate. This pattern appears in all three transientAccess functions and is structured as follows:

```
for {} 1 {} {
  mstore(freeMemoryPointer, tload(startSlot))
  freeMemoryPointer := add(freeMemoryPointer, 0x20)
  startSlot := add(startSlot, 1)
  if iszero(lt(freeMemoryPointer, end)) { break }
}
```
This creates an unconditional loop that only terminates when the freeMemoryPointer is no longer less than the end value. If this condition is never met due to input manipulation or unexpected conditions, the function will consume all available gas and revert.

This vulnerability could:

* Allow attackers to cause Denial of Service (DoS) for specific protocol operations that rely on transient storage access
* Create unpredictable gas consumption, leading to failed transactions during crucial market movements
* Enable front-running attacks where malicious actors manipulate transient storage to cause excessive gas consumption for legitimate users
* Disrupt protocol operations during high congestion periods

The root cause is the combination of:

* Using a non-standard infinite loop pattern that relies solely on a break condition
* Lack of input validation for parameters that influence the loop's execution (particularly nSlots and slots.length)
* No safeguards against excessive gas consumption

In a DeFi context, where malicious actors have financial incentives to disrupt protocol operations, this pattern introduces unnecessary risk.

#### Arithmetic Operations Without Overflow Checks - Low Severity

The TransientAccess contract performs arithmetic operations in assembly blocks without explicit overflow checks. While Solidity 0.8.28 has built-in overflow protection for regular code, assembly code bypasses these safeguards. The vulnerability specifically appears in memory pointer arithmetic when handling array construction and when incrementing slot pointers:

```
freeMemoryPointer := add(freeMemoryPointer, 0x20)
startSlot := add(startSlot, 1)
let end := add(freeMemoryPointer, shl(5, nSlots))
```

These operations could potentially overflow if extremely large inputs are provided, especially for the nSlots parameter which is used to calculate memory boundaries.

In a DeFi protocol, this vulnerability could potentially lead to:

* Memory corruption if pointers wrap around due to overflow
* Incorrect transient storage access, potentially affecting swap calculations
* Unexpected gas consumption or out-of-gas errors during execution
* In extreme cases, potential misreads of transient storage values that could affect financial calculations

While the main Nofeeswap contract implements multiple safety checks for financial operations, the lack of validation for array sizes and slot counts before calling TransientAccess functions leaves a small attack surface.

The root cause is threefold:

```
// From TransientAccess, second function
let length := shl(5, nSlots)
let end := add(freeMemoryPointer, length)

// From TransientAccess, third function
let end := add(freeMemoryPointer, shl(5, slots.length))
```

* Direct use of low-level assembly arithmetic operations that bypass Solidity's built-in overflow protection
* Lack of explicit bounds checking on input parameters like nSlots before performing arithmetic calculations
* The protocol design assumes trusted inputs or reasonable limits without enforcing them at the assembly level  

#### Lack of Input Validation - Medium Severity

Both the TransientAccess and StorageAccess contracts lack proper input validation for parameters that control the number of storage slots to read. Specifically, the nSlots parameter in the second function and the slots.length in the third function of both contracts are used without any bounds checking. This allows callers to specify arbitrarily large arrays, potentially leading to excessive gas consumption or out-of-gas errors.
The vulnerability is particularly here because these functions may be called through user-initiated transactions, potentially allowing malicious users to manipulate protocol operations.

```
function transientAccess(
  bytes32 startSlot,
  uint256 nSlots
) external view override returns (bytes32[] memory) {
  // No validation on nSlots before using it in calculations
  assembly ("memory-safe") {
    // ...
    let length := shl(5, nSlots)
    // ...
  }
}

function transientAccess(
  bytes32[] calldata slots
) external view override returns (bytes32[] memory) {
  // No validation on slots.length before using it in calculations
  assembly ("memory-safe") {
    // ...
    let end := add(freeMemoryPointer, shl(5, slots.length))
    // ...
  }
}
```

This vulnerability could lead to:

* Denial of Service (DoS) attacks by deliberately consuming excessive gas
* Transaction failures at critical moments during swap operations
* Economic attacks where an attacker forces other users' transactions to fail during price movements
* Excessive gas consumption leading to higher costs for protocol users or operators
* Potential blockchain congestion if many large-array operations are executed

The main Nofeeswap contract relies on these storage access functions for critical operations, making the impact of this vulnerability significant for the overall protocol security.

The root cause of this vulnerability is twofold:

* Missing Input Validation: The contracts fail to implement any bounds checking on array sizes before processing
* Trust Assumptions: The contracts appear to be designed with the assumption that callers will provide reasonable inputs

Additionally, while the Nofeeswap contract implements various validations, it doesn't validate inputs before calling the storage access functions.

#### Memory Safety Issues - Medium Severity

The TransientAccess contract contain multiple memory safety issues in their assembly blocks. While they use the "memory-safe" annotation, the contracts manually manipulate memory pointers without following all best practices for EVM memory management.

The primary concerns are:

* Free Memory Pointer Not Updated: The contracts read the free memory pointer from 0x40 but never write back to it after allocating memory. This can cause conflicts with other memory operations in the same transaction.
* No Memory Bounds Validation: The contracts don't verify that the calculated memory regions are valid or within reasonable bounds before performing operations.
* Unbounded Memory Allocation: With no input validation, the contracts could attempt to allocate excessive amounts of memory based on user input.
* Pointer Arithmetic Without Checks: Memory pointer arithmetic is performed without checks for overflow or underflow conditions.

In a DeFi protocol, memory safety issues can lead to:

* Transaction failures at critical moments during swaps
* Potential data corruption affecting financial calculations
* Unpredictable behavior when the protocol is under high load
* Conflicts with other memory operations in complex transaction flows


```
assembly ("memory-safe") {
  let freeMemoryPointer := mload(0x40)
  let start := freeMemoryPointer
  // Memory allocation but free pointer never updated
  // ...
  return(start, sub(end, start))
}
```

The root cause is a combination of:

* Low-Level Memory Management: Direct assembly usage bypasses Solidity's memory safety
* Incomplete Memory Practices: Not updating the free memory pointer after allocation
* Optimization Focus: Prioritizing gas optimization over memory safety practices
* Lack of Defensive Programming: Assuming memory operations will always succeed within expected bounds

#### Lack of Access Control - HIGH SEVERITY

The TransientAccess contract lack access control mechanisms for their storage reading functions. Any external address can call these functions to read arbitrary storage slots or transient storage from the protocol. This unrestricted access to storage data poses a significant privacy and security risk.

While the main Nofeeswap contract implements some access controls for protocol operations, it inherits these unrestricted storage access functions without adding additional access limitations. This allows potential attackers to inspect internal protocol state and user data without authorization.

This vulnerability can lead to:

* Privacy Leakage: Sensitive user data and positions could be exposed
* Competitive Disadvantage: Business logic and parameters meant to be private could be revealed to competitors
* Information Asymmetry: Sophisticated users with knowledge of storage layouts could gain unfair advantages over regular users

```
// No access modifiers or checks
function storageAccess(bytes32 slot) external view override returns (bytes32) {
  assembly ("memory-safe") {
    mstore(0, sload(slot))
    return(0, 0x20)
  }
}
```

The root cause appears to be inheritance Without Restriction: Inheriting base contracts without adding access control layers.

#### Gas-Inefficient Array Construction - Low Severity

The TransientAccess contract use inefficient patterns for constructing and returning arrays, particularly in the functions that return multiple storage slots. These inefficiencies can lead to excessive gas consumption, especially when reading large numbers of slots, which could be problematic for a gas-sensitive DeFi protocol focused on fee-free swaps.
The main inefficiencies are:

* Redundant Memory Operations: The contracts allocate memory and copy data in ways that involve more operations than necessary.
* Non-Optimized Looping: The custom loop structure adds overhead compared to more gas-efficient alternatives.
* ABI Encoding Overhead: The contracts manually implement ABI encoding for dynamic arrays, which is generally less gas-efficient than using Solidity's built-in mechanisms.
* Excessive Pointer Manipulations: Each iteration of the loop involves multiple pointer adjustments.
* Manual Return Data Preparation: Using return(start, size) from assembly requires additional manual memory management.

```
function transientAccess(bytes32[] calldata slots) external view override returns (bytes32[] memory) {
  assembly ("memory-safe") {
    let freeMemoryPointer := mload(0x40)
    let start := freeMemoryPointer
    mstore(freeMemoryPointer, 0x20)
    mstore(add(freeMemoryPointer, 0x20), slots.length)
    freeMemoryPointer := add(freeMemoryPointer, 0x40)
    let end := add(freeMemoryPointer, shl(5, slots.length))
    let calldataPointer := slots.offset
    
    // Inefficient loop structure
    for {} 1 {} {
      mstore(freeMemoryPointer, tload(calldataload(calldataPointer)))
      freeMemoryPointer := add(freeMemoryPointer, 0x20)
      calldataPointer := add(calldataPointer, 0x20)
      if iszero(lt(freeMemoryPointer, end)) { break }
    }
    
    return(start, sub(end, start))
  }
}
```

The inefficiencies stem from:

* Low-Level Manual Optimization: Attempting to optimize at the assembly level but not fully optimizing the algorithm
* Complex Memory Management: Managing memory manually instead of leveraging compiler optimizations
* Prioritizing Code Clarity: Some inefficiencies may be accepted trade-offs for readability or maintainability
* One-Size-Fits-All Approach: Using the same pattern for all array sizes rather than optimizing for common cases