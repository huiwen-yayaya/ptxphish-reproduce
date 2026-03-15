# PTXPhish Reproduction

A reproduction of the rule-based phishing detection system from **PTXPhish: Characterizing and Detecting Payload-based Transaction Phishing Scams on Ethereum** (NDSS 2025).

This project implements all four attack category detectors from the paper and evaluates them on the public PTXPhish dataset.

---

## Results

| Detector | Samples | Precision | Recall | F1 |
|----------|---------|-----------|--------|-----|
| Ice Phishing (Category I) | 5,232 | 99.8% | 100.0% | **0.9988** |
| NFT Order Scam (Category II) | 4,594 | 98.9% | 100.0% | **0.9943** |
| Payable Function (Category IV) | 5,579 | 100.0% | 99.6% | **0.9981** |
| Address Poisoning (Category III) | 4,211 | 91.5% | 52.7% | **0.6685** |

---

## Notes on Address Poisoning Recall

The Address Poisoning detector achieves only 52.7% recall. This is a known limitation of the paper's prerequisite condition: detection requires that the victim has previously sent funds to the genuine address (so a lookalike can be identified). In practice, ~47% of poisoning victims in the dataset have no such history in their last 100 transactions. This limitation is explicitly stated in the paper.

---

## Project Structure

```
ptxphish/
├── fetcher/
│   └── eth_client.py          # Ethereum RPC client (Alchemy API wrapper)
├── detector/
│   ├── ice_phishing_test.py   # Category I: Ice Phishing 
│   ├── nft_order.py           # Category II: NFT Order Scam 
│   ├── addr_poison.py         # Category III: Address Poisoning 
│   └── payable_func.py        # Category IV: Payable Function 
├── data/
│   ├── evaluate_ice.py        # Full-dataset evaluation for Ice Phishing
│   ├── evaluate_nft.py        # Full-dataset evaluation for NFT Order Scam
│   ├── evaluate_addr_poison.py# Full-dataset evaluation for Address Poisoning
│   ├── evaluate_payable.py    # Full-dataset evaluation for Payable Function
│   └── extract_data.py        # Dataset extraction utility
├── result/
│   ├── result_ice.txt         # Ice Phishing evaluation output
│   ├── result_nft.txt         # NFT Order Scam evaluation output
│   ├── result_addr.txt        # Address Poisoning evaluation output
│   └── result_payable.txt     # Payable Function evaluation output
└── PTXPhish-main/
    └── dataset/
        └── PTXPHISH.xlsx      # Public dataset (download separately, see below)
```

---

## Setup

### 1. Requirements

```bash
pip install requests openpyxl
```

Python 3.11+ recommended.

### 2. Alchemy API Key

This project uses the [Alchemy](https://www.alchemy.com/) Ethereum RPC API to fetch on-chain transaction data in real time.

1. Create a free account at https://www.alchemy.com/
2. Create a new app → select **Ethereum Mainnet**
3. Copy your API key

Every Python file that makes RPC calls contains a placeholder:

```python
RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/..."  # replace with your own API key
```

**Files that need the API key replaced:**

- `fetcher/eth_client.py` (or pass it in when instantiating `EthClient`)
- `detector/ice_phishing_test.py`
- `detector/nft_order.py`
- `detector/addr_poison.py`
- `detector/payable_func.py`
- `data/evaluate_ice.py`
- `data/evaluate_nft.py`
- `data/evaluate_addr_poison.py`
- `data/evaluate_payable.py`

### 3. Dataset

Download the PTXPhish dataset from the official repository:

```
https://github.com/blocksecteam/PTXPhish
```

Place `PTXPHISH.xlsx` at:

```
PTXPhish-main/dataset/PTXPHISH.xlsx
```

---

## Usage

### Run a single detector

```bash
python3 detector/ice_phishing_test.py
python3 detector/nft_order.py
python3 detector/addr_poison.py
python3 detector/payable_func.py
```

Each detector script contains a small set of test cases and prints results to the terminal.

### Run full dataset evaluation

```bash
python3 data/evaluate_ice.py
python3 data/evaluate_nft.py
python3 data/evaluate_addr_poison.py
python3 data/evaluate_payable.py
```

Results are printed to the terminal and saved to the `result/` directory.

---

## Detection Logic

### Category I — Ice Phishing

Flags transactions where `transfer.from ≠ tx.from` (spending someone else's tokens) and the function signature matches `approve` / `permit` / `setApprovalForAll` / `transferFrom`. Only EOA victims are considered; contract-to-contract transfers are excluded via `eth_getCode`. An additional rule handles contract-account victims (e.g., multi-sig wallets) using vanity address detection.

### Category II — NFT Order Scam

- **II-A Bulk Transfer**: Calls to the OpenSea BulkTransfer contract (`0x0000000000c2d1...`)
- **II-B Proxy Upgrade**: Function signatures `upgradeTo` (`0x3659cfe6`) or `upgradeToAndCall` (`0x4f1ef286`)
- **II-C Free Buy Order**: Calls to Blur Exchange or Seaport contracts with order execution functions

### Category III — Address Poisoning

Checks whether `transfer.to` has a lookalike address in the sender's outbound transfer history. Two addresses are similar if they share the same first 4 and last 4 hex characters (paper definition). Uses `alchemy_getAssetTransfers` to fetch the last 100 outbound transfers.

### Category IV — Payable Function

Flags transactions where: ETH is sent (`tx.value > 0`), the recipient is a contract, the function signature is not in a whitelist of known legitimate functions, and the input data is short (≤ 74 bytes). Known legitimate contracts (WETH, Lido stETH, Arbitrum Inbox, ether.fi) are explicitly whitelisted.

---

## Reference

```
H. Wu et al., "PTXPhish: Characterizing and Detecting Payload-based
Transaction Phishing Scams on Ethereum," NDSS 2025.

Dataset: https://github.com/blocksecteam/PTXPhish
```