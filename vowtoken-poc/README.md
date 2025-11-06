# VOWToken CEI Vulnerability - Proof of Concept

**Critical reentrancy vulnerability in VOWToken (ERC777) enabling timing attacks on DeFi integrators.**

## Overview

This PoC demonstrates a Check-Effects-Interactions (CEI) pattern violation in VOWToken's `tokensReceived` function. The vulnerability creates a timing window where user balances appear inflated, enabling attackers to drain integrated vaults and over-credit reward systems.

**Discovered by:** Hackerdemy Team  
**Blockchain:** Ethereum Mainnet  
**Affected Contract:** 0x1bbf25e71ec48b84d773809b4ba55b6f4be946fb (+ 5 other deployments)

## Quick Start

```bash
# 1. Clone repository
git clone https://github.com/OmachokoYakubu/vowtoken-cei-vulnerability-poc.git
cd vowtoken-cei-vulnerability-poc/vowtoken-poc

# 2. Configure environment
cp .env.example .env
# Edit .env and add your Ethereum RPC URL
# Example: RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY

# 3. Install dependencies
forge install

# 4. Run all three integrated tests
forge test --match-contract PoC_VOWToken_Unified -vvv
```

## Expected Results

**Test 1 - Vault Drain:**
- Alice profits: 60 VOW
- Vault drained: 100 VOW
- Attack confirmed ✓

**Test 2 - Rewarder Over-Credit:**
- Alice balance: 60 VOW
- Points awarded: 100
- Over-credit: 40 points ✓

**Test 3 - Nested Reentrancy:**
- Multi-level exploitation confirmed ✓

## Environment Setup

Required in `.env`:
```bash
RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
BLOCK_NUMBER=23727881  # Pinned for reproducibility
TARGET=0x1bbf25e71ec48b84d773809b4ba55b6f4be946fb
```

## Repository Structure

```
vowtoken-poc/
├── test/
│   └── PoC_VOWToken_Unified.t.sol  # All 3 integrated PoC tests
├── lib/
│   └── forge-std/                  # Foundry standard library
├── foundry.toml                    # Forge configuration
├── .env.example                    # Environment template
├── .gitignore                      # Git exclusions
└── README.md                       # This file
```

## Vulnerability Summary

**Location:** VOWToken.sol, lines 942-958 (tokensReceived function)

**Root Cause:**
```solidity
function tokensReceived(...) external {
    // VULNERABLE: External calls before state settlement
    if (_amount != 0)
        this.send(from, _amount, "");  // ← Bounce (triggers hook with inflated balance)
    
    this.operatorSend(from, to, amount, data, _data);  // ← Forward (settles balance)
}
```

**Exploit Flow:**
1. Attacker sends tokens to VOWToken with proxied payload
2. `this.send()` triggers attacker's hook with inflated balance
3. During hook, attacker calls vulnerable integrator (vault/rewarder)
4. Integrator snapshots inflated balance → over-mints shares/credits
5. `this.operatorSend()` settles actual balance (lower)
6. Attacker redeems over-allocated shares for profit

## Impact

- **Direct TVL at Risk:** $4,901 USD (VOWToken)
- **Cascading Risk:** UNLIMITED (any DeFi protocol integrating VOWToken)
- **Severity:** CRITICAL
- **Exploitation:** Concrete fund loss demonstrated

## Test Details

All three tests are in `test/PoC_VOWToken_Unified.t.sol`:

1. **`test_PRIMARY_vault_overmint_and_drain()`**
   - Demonstrates complete attack chain
   - Result: 60 VOW profit from vault drainage

2. **`test_SUPPLEMENTARY_rewarder_overcredit()`**
   - Proves vulnerability affects ANY integrator
   - Result: 40 reward points over-credited

3. **`test_OPTIONAL_nested_reentrancy()`**
   - Validates multi-level exploitation
   - Result: Timing window persists across nested calls

## Running Individual Tests

```bash
# Test 1: Vault drainage
forge test --match-test test_PRIMARY_vault_overmint_and_drain -vvv

# Test 2: Rewarder over-credit
forge test --match-test test_SUPPLEMENTARY_rewarder_overcredit -vvv

# Test 3: Nested reentrancy
forge test --match-test test_OPTIONAL_nested_reentrancy -vvv
```

## Technical Details

- **Mainnet Fork Block:** 23727881
- **Solidity Version:** 0.8.20
- **Test Framework:** Foundry/Forge
- **Standards:** ERC777, ERC1820
- **Gas Used:** 439K - 688K per test

## Author

**Hackerdemy Team**  
GitHub: @OmachokoYakubu  
Email: yakububuomachoko@rocketmail.com

## License

MIT - For educational and security research purposes only.
