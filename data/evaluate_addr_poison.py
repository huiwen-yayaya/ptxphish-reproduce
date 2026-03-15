import sys
import random
import time
import os
sys.path.append('/Users/Documents/meow/ptxphish')
import openpyxl
from fetcher.eth_client import EthClient
from detector.addr_poison import check_addr_poisoning

RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/..." # display your own api
client  = EthClient(RPC_URL)

wb = openpyxl.load_workbook('/Users/Documents/meow/ptxphish/PTXPhish-main/dataset/PTXPHISH.xlsx')
ws = wb['Sheet1']

poison_txs = []
benign_txs = []

for i, row in enumerate(ws.iter_rows(values_only=True)):
    if i < 4: continue
    row = list(row)
    for col in [14, 16, 18]:
        if row[col] and str(row[col]).startswith('0x'):
            poison_txs.append(str(row[col]).strip())
    if row[27] and str(row[27]).startswith('0x'):
        benign_txs.append(str(row[27]).strip())
    if row[28] and str(row[28]).startswith('0x'):
        benign_txs.append(str(row[28]).strip())

sample_poison = poison_txs
sample_benign = benign_txs

test_cases = (
    [(tx, True)  for tx in sample_poison] +
    [(tx, False) for tx in sample_benign]
)

# ── 输出到屏幕和文件 ──────────────────────────────
os.makedirs("result", exist_ok=True)
open("result/result_addr.txt", "w").close()

def log(msg=""):
    print(msg)
    with open("result/result_addr.txt", "a", encoding="utf-8") as f:
        f.write(msg + "\n")

tp = fp = tn = fn = skipped = 0
error_list = []

log(f"Address Poisoning样本: {len(poison_txs)}")
log(f"Benign样本: {len(benign_txs)}")
log(f"\n评估中（共{len(test_cases)}笔）...\n")

for i, (tx_hash, expected) in enumerate(test_cases):
    try:
        result = check_addr_poisoning(tx_hash, client)
        actual = result["is_phishing"]

        if expected and actual:       tp += 1
        elif expected and not actual: fn += 1; error_list.append(("漏报", tx_hash, result))
        elif not expected and actual: fp += 1; error_list.append(("误报", tx_hash, result))
        else:                         tn += 1

        label = "🚨" if actual else "✅"
        ok    = "✓" if actual == expected else "✗"
        log(f"{ok} [{i+1:3d}] {label} {tx_hash}")

        if (i + 1) % 5 == 0:
            time.sleep(1)

    except Exception as e:
        skipped += 1
        log(f"? [{i+1:3d}] 跳过: {tx_hash} → {e}")

total     = tp + fp + tn + fn
accuracy  = (tp + tn) / total if total else 0
precision = tp / (tp + fp)    if (tp + fp) else 0
recall    = tp / (tp + fn)    if (tp + fn) else 0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

log(f"\n{'='*50}")
log(f"样本量: {total}笔（跳过{skipped}笔）")
log(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}")
log(f"准确率:  {accuracy:.1%}")
log(f"精确率:  {precision:.1%}")
log(f"召回率:  {recall:.1%}")
log(f"F1:      {f1:.4f}")

if error_list:
    log(f"\n错误案例（{len(error_list)}个）:")
    for kind, tx, res in error_list:
        log(f"  {kind}: {tx}")
        log(f"    evidence: {res['evidence']}")