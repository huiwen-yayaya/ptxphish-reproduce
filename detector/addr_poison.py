"""
Address Poisoning 检测器
对应论文 Table III 的 Category III 规则

检测视角：受害者上当转账给假地址
核心逻辑：
  1. tx有Transfer事件，value > 0（真实损失）
  2. transfer.to 在受害者历史里找到相似地址（前4位+后4位相同）
  3. 说明受害者被假地址欺骗，误转给了靓号假地址
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fetcher.eth_client import EthClient

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


def is_similar_address(addr1: str, addr2: str) -> bool:
    """前4位 + 后4位相同 = 高度相似（论文定义）"""
    if not addr1 or not addr2:
        return False
    a1 = addr1.lower().replace("0x", "")
    a2 = addr2.lower().replace("0x", "")
    if len(a1) != 40 or len(a2) != 40:
        return False
    return a1[:4] == a2[:4] and a1[-4:] == a2[-4:] and a1 != a2


def check_addr_poisoning(tx_hash: str, client: EthClient) -> dict:
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

    tx_from   = tx["from"].lower()
    transfers = client.decode_transfer_logs(receipt)

    if not transfers:
        result["evidence"]["reason"] = "没有Transfer事件"
        return result

    # 只看受害者自己发出的转账（tx.from == transfer.from）
    # 且有真实价值（value > 0）
    victim_transfers = [
        t for t in transfers
        if t["from"].lower() == tx_from
        and t["to"] != ZERO_ADDRESS
        and t["value"] > 0
    ]

    if not victim_transfers:
        result["evidence"]["reason"] = "无受害者转账"
        return result

    # 获取受害者历史转账，查找相似地址
    history = client.get_asset_transfers(tx_from, max_count=100)
    history_addrs = set()
    for h in history:
        if h.get("to"):
            history_addrs.add(h["to"].lower())

    for t in victim_transfers:
        fake_addr = t["to"].lower()

        # 在历史里找前4+后4相同的真实地址
        genuine_addr = None
        for h_addr in history_addrs:
            if is_similar_address(fake_addr, h_addr):
                genuine_addr = h_addr
                break

        if not genuine_addr:
            continue

        # 确认真实地址有过有价值的转账
        genuine_value = 0
        for h in history:
            if (h.get("to") or "").lower() == genuine_addr:
                genuine_value += float(h.get("value") or 0)

        if genuine_value == 0:
            continue

        # 命中！判断子类
        result["is_phishing"] = True
        result["evidence"]["tx_from"]       = tx_from
        result["evidence"]["fake_addr"]     = fake_addr
        result["evidence"]["genuine_addr"]  = genuine_addr
        result["evidence"]["genuine_value"] = genuine_value
        result["evidence"]["lost_value"]    = t["value"]

        # 子类判断（基于value大小）
        if t["value"] < 1e6:  # 极小值
            result["subtype"] = "III-C: Dust value transfer"
            result["evidence"]["explanation"] = "极小量转账，受害者误转给靓号假地址"
        else:
            result["subtype"] = "III-A/B: Address poisoning"
            result["evidence"]["explanation"] = (
                f"受害者误将资产转给靓号假地址，"
                f"真实地址前4+后4相同但中间不同"
            )
        return result

    result["evidence"]["reason"] = "未发现靓号假地址匹配"
    return result


def print_result(result: dict):
    print(f"\n{'='*55}")
    print(f"TX: {result['tx_hash'][:22]}...")
    print(f"结论: {'🚨 地址投毒' if result['is_phishing'] else '✅ 正常交易'}")
    if result["is_phishing"]:
        print(f"类型: {result['subtype']}")
    ev = result["evidence"]
    if "reason"       in ev: print(f"原因: {ev['reason']}")
    if "error"        in ev: print(f"错误: {ev['error']}")
    if "explanation"  in ev: print(f"说明: {ev['explanation']}")
    if "fake_addr"    in ev:
        print(f"假地址:  {ev['fake_addr']}")
        print(f"真地址:  {ev['genuine_addr']}")
        print(f"历史累计转给真地址: {ev['genuine_value']:.2f}")
        print(f"本次损失: {ev['lost_value'] / 1e6:.2f} (raw={ev['lost_value']})")


if __name__ == "__main__":
    RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/..." # display your own api
    client  = EthClient(RPC_URL)

    print("PTXPhish Address Poisoning 检测器")
    print("=" * 55)

    test_cases = [
        (
            "0x06c5ce3e16a10eecb1742f5a84cbff603642e4d7e107579e353165d586bd63b6",
            True,
            "地址投毒（有历史匹配，来自dataset）"
        ),
        (
            "0xb4fd512570202f3b13d43cbeca828507739eb0d33b607f712e927157b6a895c2",
            True,
            "地址投毒（无历史匹配，来自dataset）"
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
        result  = check_addr_poisoning(tx_hash, client)
        actual  = result["is_phishing"]
        ok      = actual == expected
        correct += ok
        print(f"{'✓ 正确' if ok else '✗ 错误'}")
        print_result(result)

    print(f"\n{'='*55}")
    print(f"准确率: {correct}/{len(test_cases)}")