from glider import *


def query():
    """
    @title: Flash Loan + Oracle Manipulation Combined Attack
    @description: Detects combined vulnerability pattern of flash loan
    exploitation with price oracle manipulation for protocol exploitation.
    
    Flash Loan Pattern:
    - Large uncollateralized loan in single transaction
    - Loan must be repaid + fee by transaction end
    - No collateral required, only code constraint
    
    Oracle Manipulation Pattern:
    - Protocol uses spot price without TWAP
    - Price used for critical operations (liquidations, pricing)
    - No time-weighted average price protection
    - No staleness checks on price data
    - No circuit breaker on price changes
    
    Combined Attack:
    1. Attacker takes massive flash loan
    2. Dumps tokens to crash pool price
    3. Uses manipulated price in protocol
    4. Performs privileged operation (liquidation, arbitrage, etc.)
    5. Reverses attack and repays flash loan
    6. Protocol loses funds, attacker profits
    
    Real-World Exploits:
    - bZx (Feb 2020) - $600K+ via Uniswap price manipulation
    - Harvest Finance (Oct 2020) - $34M via oracle + flash loan
    - Multiple Curve clone attacks - Price oracle exploitation
    - SymbioticWithdrawalQueue (Nov 2024) - Oracle no TWAP/staleness check
    
    Detection focuses on:
    1. Protocols using spot price (no TWAP)
    2. Flash loan receivers with price-dependent logic
    3. Critical operations based on instantaneous price
    4. Lack of price oracle validation/staleness checks
    5. No circuit breaker or bounds on price changes
    6. Withdrawal queues without price protection
    
    @author: Glider Vulnerability Research
    @tags: flash loan, oracle manipulation, price, TWAP, DeFi attack
    @references:
    - https://twitter.com/samczsun/status/1367819267139264514
    - https://docs.aave.com/developers/guides/flash-loans
    - https://en.wikipedia.org/wiki/Oracle_manipulation
    - https://etherscan.io/address/0x351875e6348120b71281808870435bF6d5F406BD
    """
    
    # Find contracts with oracle price usage
    oracle_patterns = [
        "getPrice", "latestPrice", "latestRound", "price",
        "priceOf", "getRate", "exchangeRate"
    ]
    
    defi_patterns = [
        "liquidate", "borrow", "lend", "mint", "burn",
        "swap", "deposit", "withdraw", "claim", "execute"
    ]
    
    oracle_contracts = (
        Contracts()
        .non_interface_contracts()
        .with_one_of_the_function_names(oracle_patterns + defi_patterns)
        .exec(150)
    )
    
    vulnerable_contracts = []
    
    for contract in oracle_contracts:
        vulnerabilities = []
        
        # Check 1: Uses spot price without TWAP
        if uses_spot_price_no_twap(contract):
            vulnerabilities.append("SPOT_PRICE_NO_TWAP")
        
        # Check 2: Critical operation depends on single price point
        if critical_op_single_price(contract):
            vulnerabilities.append("CRITICAL_OP_SINGLE_PRICE")
        
        # Check 3: Price used without staleness check
        if missing_price_staleness_check(contract):
            vulnerabilities.append("MISSING_STALENESS_CHECK")
        
        # Check 4: Withdrawal queue without price protection
        if withdrawal_queue_no_protection(contract):
            vulnerabilities.append("WITHDRAWAL_NO_PROTECTION")
        
        # Check 5: No circuit breaker on price changes
        if missing_circuit_breaker(contract):
            vulnerabilities.append("MISSING_CIRCUIT_BREAKER")
        
        # Check 6: Price oracle not validated (could be malicious)
        if price_oracle_not_validated(contract):
            vulnerabilities.append("ORACLE_NOT_VALIDATED")
        
        if vulnerabilities:
            vulnerable_contracts.append(contract)
    
    return vulnerable_contracts


def uses_spot_price_no_twap(contract):
    """
    Detect contracts using spot price without TWAP protection.
    """
    functions = contract.functions().exec()
    
    spot_unsafe_patterns = [
        "pool.price", "spotPrice", "getPrice", "price0", "price1",
        "get_dy", "get_dx", "exchange_rate", "priceOf"
    ]
    twap_safe_patterns = ["twap", "oracle", "chainlink", "average", "weighted"]
    
    for func in functions:
        instructions = func.instructions().exec()
        
        has_spot_price = False
        has_twap = False
        
        for instr in instructions:
            components = instr.get_components_recursive()
            for component in components:
                expr = component.expression
                if expr:
                    expr_lower = expr.lower()
                    if any(pattern.lower() in expr_lower for pattern in spot_unsafe_patterns):
                        has_spot_price = True
                    if any(pattern in expr_lower for pattern in twap_safe_patterns):
                        has_twap = True
        
        if has_spot_price and not has_twap:
            return True
    
    return False


def critical_op_single_price(contract):
    """
    Detect critical operations depending on single price point.
    """
    critical_functions = [
        "liquidate", "borrow", "mint", "deposit",
        "claimRewards", "rebalance", "arbitrage", "execute"
    ]
    
    functions = contract.functions().exec()
    
    for func in functions:
        func_name = func.name.lower()
        
        if not any(crit in func_name for crit in critical_functions):
            continue
        
        instructions = func.instructions().exec()
        
        price_usages = 0
        for instr in instructions:
            components = instr.get_components_recursive()
            for component in components:
                expr = component.expression
                if expr:
                    expr_lower = expr.lower()
                    if "price" in expr_lower or "getrate" in expr_lower or "exchange" in expr_lower:
                        price_usages = price_usages + 1
        
        if price_usages > 0 and price_usages <= 2:
            return True
    
    return False


def missing_price_staleness_check(contract):
    """
    Detect price oracle usage without staleness validation.
    """
    functions = contract.functions().exec()
    
    for func in functions:
        instructions = func.instructions().exec()
        
        has_price_call = False
        for instr in instructions:
            source = instr.source_code().lower()
            if any(x in source for x in ["price", "latestround", "getprice"]):
                has_price_call = True
                break
        
        if not has_price_call:
            continue
        
        has_staleness_check = False
        for instr in instructions:
            source = instr.source_code().lower()
            if "require" in source and "timestamp" in source:
                if "block.timestamp" in source or "now" in source:
                    has_staleness_check = True
        
        if not has_staleness_check:
            return True
    
    return False


def withdrawal_queue_no_protection(contract):
    """
    Detect withdrawal queues without price protection.
    """
    functions = contract.functions().exec()
    
    withdrawal_keywords = ["queue", "withdraw", "pending"]
    
    for func in functions:
        func_name = func.name.lower()
        
        if not any(kw in func_name for kw in withdrawal_keywords):
            continue
        
        source = func.source_code().lower()
        
        # Check if withdrawal uses price
        uses_price = "price" in source or "rate" in source or "value" in source
        
        if uses_price:
            # Check if price is validated
            has_validation = "require" in source and ("price" in source or "rate" in source)
            
            if not has_validation:
                return True
    
    return False


def missing_circuit_breaker(contract):
    """
    Detect price oracle usage without circuit breaker protection.
    """
    functions = contract.functions().exec()
    
    for func in functions:
        source = func.source_code()
        
        if "price" not in source.lower():
            continue
        
        circuit_breaker_patterns = [
            "max", "min", "%", "deviation", "bounded",
            "require", "revert", "bounds", "cap",
            "limit", "exceed", "threshold"
        ]
        
        has_circuit_breaker = False
        for pattern in circuit_breaker_patterns:
            if pattern in source.lower():
                has_circuit_breaker = True
                break
        
        if not has_circuit_breaker:
            critical_ops = ["liquidate", "borrow", "mint", "burn", "execute", "withdraw"]
            if any(op in func.name.lower() for op in critical_ops):
                return True
    
    return False


def price_oracle_not_validated(contract):
    """
    Detect price oracle usage without validation.
    """
    functions = contract.functions().exec()
    
    init_functions = [f for f in functions 
                      if f.name in ["__init__", "initialize", "constructor", "setup"]]
    
    for func in init_functions:
        args = func.arguments().list()
        
        oracle_param = None
        for arg in args:
            arg_var = arg.get_variable()
            arg_name = arg_var.name if arg_var else ""
            if "oracle" in arg_name.lower() or "price" in arg_name.lower():
                oracle_param = arg_name
                break
        
        if not oracle_param:
            continue
        
        instructions = func.instructions().exec()
        
        oracle_validated = False
        for instr in instructions:
            source = instr.source_code()
            if oracle_param in source and ("require" in source or "assert" in source):
                oracle_validated = True
        
        if not oracle_validated:
            return True
    
    return False
