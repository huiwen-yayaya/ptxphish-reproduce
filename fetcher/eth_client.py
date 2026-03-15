import requests
import json
import time

class EthClient:
    """
    封装以太坊JSON-RPC调用
    负责拉取交易数据，供检测规则使用
    """
    
    def __init__(self, rpc_url: str):
        self.rpc_url = rpc_url
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
    
    def _call(self, method: str, params: list) -> dict:
        """底层RPC调用，带简单重试"""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }
        for attempt in range(3):
            try:
                resp = self.session.post(self.rpc_url, json=payload, timeout=10)
                resp.raise_for_status()
                result = resp.json()
                if "error" in result:
                    raise Exception(f"RPC error: {result['error']}")
                return result.get("result")
            except Exception as e:
                if attempt == 2:
                    raise e
                time.sleep(1)
    
    def get_transaction(self, tx_hash: str) -> dict:
        """
        拉取交易基本信息
        返回：from, to, value, input(calldata), blockNumber等
        """
        return self._call("eth_getTransactionByHash", [tx_hash])
    
    def get_receipt(self, tx_hash: str) -> dict:
        """
        拉取交易收据
        返回：logs(Transfer事件), status(成功/失败)
        关键：Ice Phishing的转账记录藏在logs里
        """
        return self._call("eth_getTransactionReceipt", [tx_hash])
    
    def get_block(self, block_number: int) -> dict:
        """
        拉取整个区块（含所有交易）
        block_number传int，自动转hex
        """
        hex_num = hex(block_number)
        return self._call("eth_getBlockByNumber", [hex_num, True])
    
    def get_balance(self, address: str, block_number: int = None) -> int:
        """
        查询某地址在某区块时的ETH余额
        返回wei单位的int
        """
        block = hex(block_number) if block_number else "latest"
        result = self._call("eth_getBalance", [address, block])
        return int(result, 16) if result else 0
    
    def is_contract(self, address: str) -> bool:
        """
        判断地址是合约还是EOA
        合约地址的bytecode不为空
        EOA的bytecode为 0x
        """
        code = self._call("eth_getCode", [address, "latest"])
        return code is not None and code != "0x"

    def decode_transfer_logs(self, receipt: dict) -> list:
        """
        从收据的logs里解析ERC-20 Transfer事件
        Transfer事件的topic[0]是固定的keccak256签名
        返回: [{from, to, value, contract_address}, ...]
        
        这是Ice Phishing检测的关键数据源：
        tx.from != transfer.from 就是冰钓的核心特征
        """
        # ERC-20 Transfer事件的固定签名
        TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        
        transfers = []
        logs = receipt.get("logs", [])
        
        for log in logs:
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue
            if topics[0].lower() != TRANSFER_TOPIC:
                continue
            
            # topics[1] = from地址（32字节，取后20字节）
            # topics[2] = to地址（32字节，取后20字节）
            from_addr = "0x" + topics[1][-40:]
            to_addr   = "0x" + topics[2][-40:]
            
            # data字段 = 转账金额
            data = log.get("data", "0x0")
            value = int(data, 16) if data and data != "0x" else 0
            
            transfers.append({
                "from": from_addr.lower(),
                "to":   to_addr.lower(),
                "value": value,
                "token_contract": log["address"].lower()
            })
        
        return transfers
    
    def get_asset_transfers(self, address: str, category: list = None, max_count: int = 100) -> list:
        """
        获取地址的历史转账记录
        使用Alchemy专有接口 alchemy_getAssetTransfers
        """
        if category is None:
            category = ["erc20", "erc721", "erc1155"]

        params = [{
            "fromAddress": address,
            "category": category,
            "maxCount": hex(max_count),
            "order": "desc",  # 最新的在前
            "withMetadata": False,
            "excludeZeroValue": False,
        }]

        result = self._call("alchemy_getAssetTransfers", params)
        return result.get("transfers", [])


# ============ 快速测试 ============
if __name__ == "__main__":
    RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/..." # display your own api
    
    client = EthClient(RPC_URL)
    
    # 用我们之前在Etherscan看过的那笔Cream攻击交易测试
    TEST_TX = "0x0fe2542079644e107cbf13690eb9c2c65963ccb79089ff96bfaf8dced2331c92"
    
    print("=" * 50)
    print("测试1：拉取交易基本信息")
    tx = client.get_transaction(TEST_TX)
    print(f"  from:  {tx['from']}")
    print(f"  to:    {tx['to']}")
    print(f"  value: {int(tx['value'], 16) / 1e18:.4f} ETH")
    print(f"  block: {int(tx['blockNumber'], 16)}")
    
    print("\n测试2：解析Transfer事件")
    receipt = client.get_receipt(TEST_TX)
    transfers = client.decode_transfer_logs(receipt)
    print(f"  共发现 {len(transfers)} 个Transfer事件")
    for i, t in enumerate(transfers[:3]):  # 只显示前3个
        val = t['value'] / 1e18
        print(f"  [{i+1}] {t['from'][:10]}... → {t['to'][:10]}...  {val:.4f} token")
    if len(transfers) > 3:
        print(f"  ... 还有 {len(transfers)-3} 个")
    
    print("\n✓ EthClient 正常工作")
