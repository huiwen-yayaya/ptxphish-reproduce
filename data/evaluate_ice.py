import sys
import random
sys.path.append('/Users/Documents/meow/ptxphish')

import openpyxl
from fetcher.eth_client import EthClient
from detector.ice_phishing_test import check_ice_phishing

RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/..." # display your own api
client  = EthClient(RPC_URL)

# ── 读取数据集 ────────────────────────────────────
wb = openpyxl.load_workbook('/Users/Documents/meow/ptxphish/PTXPhish-main/dataset/PTXPHISH.xlsx')
ws = wb['Sheet1']

approve_txs = []
benign_txs  = []

for i, row in enumerate(ws.iter_rows(values_only=True)):
    if i < 4: continue
    row = list(row)
    if row[0]  and str(row[0]).startswith('0x'):
        approve_txs.append(str(row[0]).strip())
    if row[27] and str(row[27]).startswith('0x'):
        benign_txs.append(str(row[27]).strip())
    if row[28] and str(row[28]).startswith('0x'):
        benign_txs.append(str(row[28]).strip())

# # ── 随机抽样（先跑小批量，避免API超限）────────────
# random.seed(42)
# sample_phishing = random.sample(approve_txs, 50)
# sample_benign   = random.sample(benign_txs,  50)

sample_phishing = approve_txs
sample_benign   = benign_txs

# sample_phishing = approve_txs[943:]
# sample_benign   = benign_txs[247:]

test_cases = (
    [(tx, True)  for tx in sample_phishing] +
    [(tx, False) for tx in sample_benign]
)
# random.shuffle(test_cases)

# ── 评估 ──────────────────────────────────────────
import os
os.makedirs("result", exist_ok=True)

def log(msg=""):
    print(msg)
    with open("result/result_ice.txt", "a", encoding="utf-8") as f:
        f.write(msg + "\n")

# 清空旧结果
open("result/result_ice.txt", "w").close()

tp = fp = tn = fn = 0
errors = []
log(f"评估中(共{len(test_cases)}笔)...\n")
for i, (tx_hash, expected) in enumerate(test_cases):
    try:
        result = check_ice_phishing(tx_hash, client)
        actual = result["is_phishing"]
        if expected and actual:       tp += 1
        elif expected and not actual: fn += 1; errors.append(("漏报", tx_hash, result))
        elif not expected and actual: fp += 1; errors.append(("误报", tx_hash, result))
        else:                         tn += 1
        label = "🚨" if actual else "✅"
        ok    = "✓" if actual == expected else "✗"
        log(f"{ok} [{i+1:3d}] {label} {tx_hash}")
    except Exception as e:
        log(f"? [{i+1:3d}] 错误: {tx_hash}... → {e}")

# ── 结果统计 ──────────────────────────────────────
total     = tp + fp + tn + fn
accuracy  = (tp + tn) / total if total else 0
precision = tp / (tp + fp)    if (tp + fp) else 0
recall    = tp / (tp + fn)    if (tp + fn) else 0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

log(f"\n{'='*50}")
log(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}")
log(f"准确率:  {accuracy:.1%}")
log(f"精确率:  {precision:.1%}")
log(f"召回率:  {recall:.1%}")
log(f"F1:      {f1:.4f}")

if errors:
    log(f"\n错误案例({len(errors)}个):")
    for kind, tx, res in errors:
        log(f"  {kind}: {tx}")
        log(f"    subtype:  {res['subtype']}")
        log(f"    evidence: {res['evidence']}")