"""
Ice Phishing 检测器
对应论文 Table III 的 Category I 规则

核心逻辑：
  正常转账：tx.from 自己花自己的钱
  冰钓攻击：tx.from != transfer.from
            攻击者调用受害者已授权的transferFrom
            花的是受害者的钱，不是自己的
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fetcher.eth_client import EthClient

# ERC-20函数签名（calldata前4字节）
SIG_APPROVE             = "0x095ea7b3"
SIG_INCREASE_ALLOWANCE  = "0x39509351"
SIG_TRANSFER_FROM       = "0x23b872dd"
SIG_PERMIT              = "0xd505accf"
SIG_PERMIT2             = "0x2b67b570"
SIG_SET_APPROVAL_FOR_ALL= "0xa22cb465"

# 知名DeFi协议白名单
# 这些地址发起的转账是正常DeFi操作，不是钓鱼
# 对应论文Table III的 "tx.from ∉ Authorized List" 条件
AUTHORIZED_CONTRACTS = {
    # Uniswap
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap V2 Router
    "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3 Router
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",  # Uniswap V3 Router2
    # Aave
    "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9",  # Aave V2 LendingPool
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",  # Aave V3 Pool
    # Curve
    "0x45f783cce6b7ff23b2ab2d70e416cdb7d6055f51",  # Curve Y Pool
    "0xa5407eae9ba41422680e2e00537571bcc53efbfd",  # Curve sUSD Pool
    # Compound / Cream
    "0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b",  # Compound Comptroller
    "0x16de59092dae5ccf4a1e6439d611fd0653f0bd01",  # Cream yDAI
    "0x4b5bfd52124784745c1071dcb244c6688d2533d3",  # Cream yCurve
    # 1inch
    "0x1111111254fb6c44bac0bed2854e76f90643097d",  # 1inch V4
    "0x1111111254eeb25477b68fb85ed929f73a960582",  # 1inch V5
    # Balancer
    "0xba12222222228d8ba445958a75a0704d566bf2c8",  # Balancer Vault
    # ether.fi
    "0x989468982b08aefa46e37cd0086142a86fa466d7",  # ether.fi Atomic Solver v3
    "0x2322ba43eff1542b6a7baed35e66099ea0d12bd1",  # ether.fi Deployer 3
    "0x30fe242a69d7694a931791429815db792e24cf97",  # Aave Collector
}


def check_ice_phishing(tx_hash: str, client: EthClient) -> dict:
    """
    检测一笔交易是否为Ice Phishing
    
    返回格式：
    {
        "is_phishing": True/False,
        "subtype": "approve" / "permit" / "setApprovalForAll" / None,
        "evidence": {...}   # 判断依据
    }
    """
    result = {
        "tx_hash": tx_hash,
        "is_phishing": False,
        "subtype": None,
        "evidence": {}
    }

    # ── 拉取交易数据 ──────────────────────────────
    tx      = client.get_transaction(tx_hash)
    receipt = client.get_receipt(tx_hash)

    if not tx or not receipt:
        result["evidence"]["error"] = "无法获取交易数据"
        return result

    # 失败的交易不是钓鱼
    if receipt.get("status") == "0x0":
        result["evidence"]["error"] = "交易执行失败"
        return result

    tx_from = tx["from"].lower()
    tx_to   = (tx.get("to") or "").lower()
    input_data = tx.get("input", "0x")

    # ── 前置条件检查（论文Table III Prerequisites）────
    # 条件1：交易必须有Transfer事件
    transfers = client.decode_transfer_logs(receipt)
    if not transfers:
        result["evidence"]["reason"] = "没有Transfer事件"
        return result

    # 条件2：tx.from != transfer.from（花的不是自己的钱）
    # 条件3：转走了transfer.from的全部/大部分余额（高价值转移）
    # suspicious_transfers = []
    # for t in transfers:
    #     if t["from"] != tx_from and t["value"] > 0:
    #         suspicious_transfers.append(t)
    # 零地址是mint操作，不是钓鱼
    ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

    func_sig = input_data[:10].lower() if len(input_data) >= 10 else ""

    suspicious_transfers = []
    if tx_from not in AUTHORIZED_CONTRACTS:
        for t in transfers:
            if t["from"] == tx_from:          continue
            if t["from"] == ZERO_ADDRESS:     continue
            # if t["to"]   == ZERO_ADDRESS:     continue  # burn操作
            # if t["to"]   == tx_from:          continue  # 钱转回给自己
            if t["value"] == 0:               continue
            if client.is_contract(t["from"]): continue
            suspicious_transfers.append(t)

    if not suspicious_transfers:
        contract_victims = []
        for t in transfers:
            if (t["from"] != tx_from
                    and t["from"] != ZERO_ADDRESS
                    # and t["to"]   != ZERO_ADDRESS  # burn操作
                    # and t["to"]   != tx_from       # 钱转回给自己
                    and t["value"] > 0
                    and client.is_contract(t["from"])
                    and (func_sig == SIG_TRANSFER_FROM
                         or tx_from.lower().replace("0x","").startswith("0000")
                         or tx_from.lower().replace("0x","").endswith("0000"))):
                contract_victims.append(t)

        if contract_victims:
            result["is_phishing"] = True
            result["subtype"] = "I-A: Approve (合约受害者)"
            result["evidence"]["tx_from"] = tx_from
            result["evidence"]["explanation"] = "攻击者调用transferFrom转走合约账户资产"
            result["evidence"]["suspicious_transfers"] = contract_victims[:3]
            return result

        result["evidence"]["reason"] = "无可疑EOA转账，正常交易"
        return result

    # ── 到这里满足前置条件，判断子类 ──────────────
    result["evidence"]["tx_from"] = tx_from
    result["evidence"]["suspicious_transfers"] = suspicious_transfers[:3]
    result["evidence"]["total_suspicious"] = len(suspicious_transfers)

    # 检查受害者历史里有没有approve/permit记录
    # 简化版：直接看当前交易的calldata签名
    # 完整版应该查transfer.from的历史交易（需要更多API调用）
    

    # ── 子类 I-A：Approve ─────────────────────────
    if func_sig in [SIG_APPROVE, SIG_INCREASE_ALLOWANCE]:
        result["is_phishing"] = True
        result["subtype"] = "I-A: Approve"
        result["evidence"]["func_sig"] = func_sig
        result["evidence"]["explanation"] = (
            "受害者调用approve授权给攻击者地址，"
            "攻击者随后可调用transferFrom转走代币"
        )
        return result

    # ── 子类 I-B：Permit ──────────────────────────
    if func_sig in [SIG_PERMIT, SIG_PERMIT2]:
        result["is_phishing"] = True
        result["subtype"] = "I-B: Permit"
        result["evidence"]["func_sig"] = func_sig
        result["evidence"]["explanation"] = (
            "链下签名permit，攻击者广播到链上，"
            "绕过approve直接获得transferFrom权限"
        )
        return result

    # ── 子类 I-C：SetApprovalForAll ───────────────
    if func_sig == SIG_SET_APPROVAL_FOR_ALL:
        result["is_phishing"] = True
        result["subtype"] = "I-C: SetApprovalForAll"
        result["evidence"]["func_sig"] = func_sig
        result["evidence"]["explanation"] = (
            "一次性授权整个NFT系列给攻击者"
        )
        return result

    # ── 前置条件满足但子类未匹配 ──────────────────
    # tx.from != transfer.from 且有高价值转移
    # 很可能是通过之前的approve触发的transferFrom
    if func_sig == SIG_TRANSFER_FROM:
        result["is_phishing"] = True
        result["subtype"] = "I-A: Approve (transferFrom执行阶段)"
        result["evidence"]["func_sig"] = func_sig
        result["evidence"]["explanation"] = (
            "攻击者直接调用transferFrom，"
            "说明受害者之前已经approve过攻击者地址"
        )
        return result

    # 满足前置条件但无法确定子类
    result["is_phishing"] = True
    result["subtype"] = "I: Ice Phishing (未知子类)"
    result["evidence"]["func_sig"] = func_sig

    return result


def print_result(result: dict):
    """格式化打印检测结果"""
    print(f"\n{'='*55}")
    print(f"TX: {result['tx_hash'][:20]}...")
    print(f"结论: {'🚨 冰钓攻击' if result['is_phishing'] else '✅ 正常交易'}")

    if result["is_phishing"]:
        print(f"类型: {result['subtype']}")

    ev = result["evidence"]
    if "reason" in ev:
        print(f"原因: {ev['reason']}")
    if "explanation" in ev:
        print(f"说明: {ev['explanation']}")
    if "tx_from" in ev:
        print(f"tx.from:  {ev['tx_from']}")
    if "suspicious_transfers" in ev:
        print(f"可疑转账（tx.from≠transfer.from）：")
        for t in ev["suspicious_transfers"]:
            val = t["value"] / 1e18
            print(f"  {t['from'][:12]}... → {t['to'][:12]}...  {val:.4f} token")
        if ev.get("total_suspicious", 0) > 3:
            print(f"  ... 共{ev['total_suspicious']}笔")


# ── 测试 ─────────────────────────────────────────
if __name__ == "__main__":
    RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/..." # display your own api
    client = EthClient(RPC_URL)

    print("PTXPhish Ice Phishing 检测器")
    print("=" * 55)

    test_cases = [
        (
            "0x3f4946fb8ab2c240a223b8ab58193451c5b243c98a69838256d079809f2d75a0",
            True,
            "Approve冰钓（来自dataset）"
        ),
        (
            "0x35ed074ae9b9028c597e86d717826944a70f79376813b04c4faf082a46246646",
            True,
            "Approve冰钓（来自dataset）"
        ),
        (
            "0x0fe2542079644e107cbf13690eb9c2c65963ccb79089ff96bfaf8dced2331c92",
            False,
            "Cream闪电贷（预期：正常）"
        ),
    ]

    correct = 0
    for tx_hash, expected, desc in test_cases:
        result = check_ice_phishing(tx_hash, client)
        actual = result["is_phishing"]
        status = "✓" if actual == expected else "✗"
        correct += (actual == expected)
        print(f"\n{status} {desc}")
        print_result(result)

    print(f"\n准确率: {correct}/{len(test_cases)}")