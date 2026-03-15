print("Python环境正常")
print(f"测试一下：1 + 1 = {1 + 1}")

# 测试api，能否正常发送网络请求
import urllib.request
import json

url = "https://eth-mainnet.g.alchemy.com/v2/..." # display your own api

payload = json.dumps({
    "jsonrpc": "2.0",
    "method": "eth_blockNumber",
    "params": [],
    "id": 1
})

req = urllib.request.Request(
    url,
    data=payload.encode(),
    headers={"Content-Type": "application/json"}
)

with urllib.request.urlopen(req) as response:
    result = json.loads(response.read())
    block_hex = result["result"]
    block_num = int(block_hex, 16)
    print(f"当前以太坊最新块号：{block_num}")
