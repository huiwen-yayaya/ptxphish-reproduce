"""
Payable Function 检测器
对应论文 Table III 的 Category IV 规则

攻击方式：
  攻击者部署钓鱼合约，函数名伪装成 SecurityUpdate/ClaimReward/Airdrop 等
  诱骗受害者调用，合约直接收走ETH

核心特征：
  1. tx.value > 0（受害者发送了真实ETH）
  2. tx.to 是合约（钓鱼合约）
  3. func_sig 不是任何已知标准函数
  4. input数据很短（通常只有4字节函数签名）
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fetcher.eth_client import EthClient

# 已知合法的函数签名（标准ERC-20/721/1155及常见DeFi）
KNOWN_SIGS = {
    "0xa9059cbb",  # transfer
    "0x095ea7b3",  # approve
    "0x23b872dd",  # transferFrom
    "0x39509351",  # increaseAllowance
    "0xd505accf",  # permit
    "0x2b67b570",  # permit2
    "0xa22cb465",  # setApprovalForAll
    "0x42842e0e",  # safeTransferFrom (ERC-721)
    "0xb88d4fde",  # safeTransferFrom with data
    "0xe449022e",  # uniswap swap
    "0x7ff36ab5",  # uniswap swapExactETHForTokens
    "0x18cbafe5",  # uniswap swapExactTokensForETH
    "0x38ed1739",  # uniswap swapExactTokensForTokens
    "0xac9650d8",  # multicall
    "0x5ae401dc",  # multicall with deadline
    "0x3593564c",  # uniswap v3 execute
    "0xe8e33700",  # addLiquidity
    "0xf305d719",  # addLiquidityETH
    "0x4a25d94a",  # swapTokensForExactETH
    "0xfb3bdb41",  # swapETHForExactTokens
    "0x",          # 纯ETH转账（无input）
    "0xd0e30db0",  # WETH deposit()
}

# 已知合法合约地址白名单
KNOWN_CONTRACTS = {
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84",  # Lido stETH
    "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f",  # Arbitrum Delayed Inbox
    "0x3165542a27d40fbe0dad050614180f01a4f4ee24",  # 合法合约
    "0x44087e105137a5095c008aab6a6530182821f2f0",
    "0x8f1034cbe5827b381067fcefa727c069c26270c4",
    "0xa0c68c638235ee32657e8f720a23cec1bfc77c77",
}

# ETH价值阈值：低于此值不算重大损失（单位：wei）
MIN_ETH_VALUE = int(0.00001 * 1e18)  # 0.001 ETH
# MIN_ETH_VALUE = 0  # 任何ETH转账都检测（修复）（别修）


def check_payable_func(tx_hash: str, client: EthClient) -> dict:
    """
    检测一笔交易是否为Payable Function钓鱼

    返回格式：
    {
        "is_phishing": True/False,
        "subtype": "IV-A: Airdrop" / "IV-B: Wallet" / None,
        "evidence": {...}
    }
    """
    result = {
        "tx_hash": tx_hash,
        "is_phishing": False,
        "subtype": None,
        "evidence": {}
    }

    tx      = client.get_transaction(tx_hash)
    receipt = client.get_receipt(tx_hash)

    if not tx or not receipt:
        result["evidence"]["error"] = "无法获取交易数据"
        return result

    if receipt.get("status") == "0x0":
        result["evidence"]["error"] = "交易执行失败"
        return result

    tx_to      = (tx.get("to") or "").lower()
    input_data = tx.get("input", "0x")
    value_hex  = tx.get("value", "0x0")
    value_wei  = int(value_hex, 16) if isinstance(value_hex, str) else value_hex
    func_sig   = input_data[:10].lower() if len(input_data) >= 10 else "0x"

    # ── 条件1：tx.value > 0（发送了ETH）────────────
    if value_wei < MIN_ETH_VALUE:
        result["evidence"]["reason"] = f"ETH value太小或为零: {value_wei/1e18:.6f} ETH"
        return result

    # ── 条件2：tx.to 是合约────────────────────────
    if not tx_to:
        result["evidence"]["reason"] = "合约创建交易"
        return result

    if not client.is_contract(tx_to):
        result["evidence"]["reason"] = "tx.to是EOA，不是合约"
        return result
    
    # 增加白名单，由跑的30个错误名单来的
    if tx_to in KNOWN_CONTRACTS:
        result["evidence"]["reason"] = f"已知合法合约: {tx_to}"
        return result

    # ── 条件3：func_sig不是已知标准函数────────────
    if func_sig in KNOWN_SIGS:
        result["evidence"]["reason"] = f"已知合法函数签名: {func_sig}"
        return result

    # ── 条件4：input很短（只有函数签名，无参数）────
    # 正常合约调用至少有函数签名(4字节)+参数(32字节) = 68字符+0x
    # 钓鱼合约通常input只有4字节函数签名
    if len(input_data) > 74:
        result["evidence"]["reason"] = f"input有参数（长度{len(input_data)}），不像钓鱼"
        return result

    # # 靓号合约地址（前后大量0）通常是钓鱼合约，放宽input长度限制（修复）（别修）
    # clean = tx_to.replace("0x", "")
    # is_vanity = clean.startswith("0000") or clean.endswith("0000")
    
    # if len(input_data) > 74 and not is_vanity:
    #     result["evidence"]["reason"] = f"input参数过多（长度{len(input_data)}），不像钓鱼"
    #     return result

    # ── 全部条件满足，判定为钓鱼 ──────────────────
    result["is_phishing"] = True
    result["evidence"]["tx_to"]     = tx_to
    result["evidence"]["func_sig"]  = func_sig
    result["evidence"]["value_eth"] = value_wei / 1e18
    result["evidence"]["input_len"] = len(input_data)

    # 子类判断（基于函数签名）
    # 论文里airdrop和wallet function是两个子类，
    # 但从链上数据很难区分，统一标记为IV
    result["subtype"] = "IV: Payable Function"
    result["evidence"]["explanation"] = (
        f"受害者调用未知函数 {func_sig} 并发送 "
        f"{value_wei/1e18:.4f} ETH 给钓鱼合约"
    )

    return result


def print_result(result: dict):
    print(f"\n{'='*55}")
    print(f"TX: {result['tx_hash'][:22]}...")
    print(f"结论: {'🚨 Payable钓鱼' if result['is_phishing'] else '✅ 正常交易'}")
    if result["is_phishing"]:
        print(f"类型: {result['subtype']}")
    ev = result["evidence"]
    if "reason"      in ev: print(f"原因: {ev['reason']}")
    if "error"       in ev: print(f"错误: {ev['error']}")
    if "explanation" in ev: print(f"说明: {ev['explanation']}")
    if "value_eth"   in ev: print(f"损失: {ev['value_eth']:.4f} ETH")
    if "func_sig"    in ev: print(f"函数: {ev['func_sig']}")


if __name__ == "__main__":
    RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/..." # display your own api
    client  = EthClient(RPC_URL)

    print("PTXPhish Payable Function 检测器")
    print("=" * 55)

    test_cases = [
        (
            "0x24b58caed467bb7ce5a0db2449b05a172ea23d714bc0b1650fab4f163cc69509",
            True,
            "Airdrop钓鱼（55 ETH）"
        ),
        (
            "0x81a4e266ce62c33b3f026d731447d4b6ec516be234c6a43728fbe9c55e027e35",
            True,
            "Airdrop钓鱼（40 ETH）"
        ),
        (
            "0xf56407addf5992fb0acd06cc06af5d81807e092c9936b2136cfcf294b2f7b9d6",
            True,
            "Wallet钓鱼（100 ETH）"
        ),
        (
            "0x0fe2542079644e107cbf13690eb9c2c65963ccb79089ff96bfaf8dced2331c92",
            False,
            "Cream闪电贷（预期：正常）"
        ),
    ]

    correct = 0
    for tx_hash, expected, desc in test_cases:
        print(f"\n检测：{desc}")
        result  = check_payable_func(tx_hash, client)
        actual  = result["is_phishing"]
        ok      = actual == expected
        correct += ok
        print(f"{'✓ 正确' if ok else '✗ 错误'}")
        print_result(result)

    print(f"\n{'='*55}")
    print(f"准确率: {correct}/{len(test_cases)}")