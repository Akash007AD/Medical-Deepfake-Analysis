# Medical Deepfake Detection Pipeline

A research-oriented cryptographic authentication pipeline for verifying the authenticity and integrity of DICOM medical images — no deep learning, no GPU required.

---

## How It Works

Images pass through 5 sequential security layers. Failure at any layer immediately rejects the image.

```text
DICOM Image
     │
     ▼
[L1] Metadata Gate          ← required tags, timestamp chain, FOV sanity
     │
     ▼
[L2] BLAKE3 + Ed25519       ← cryptographic hash + scanner signature
     │
     ▼
[L3] PRNU Fingerprint       ← physical sensor noise correlation
     │
     ▼
[L4] Merkle Tree Audit      ← tile-level pixel integrity check
     │
     ▼
[L5] Ledger Provenance      ← blockchain-style enrollment record
     │
     ▼
AUTHENTICATED ✓
```

---

## Test Scenarios

| Scenario | Expected | Fails At |
|---|---|---|
| Real authentic CT | ✓ PASS | — |
| AI-generated (corrupt metadata) | ✗ REJECT | Layer 1 |
| Pixel-tampered CT | ✗ REJECT | Layer 2 |
| Image from wrong scanner | ✗ REJECT | Layer 3 |

---

## Installation

```bash
git clone https://github.com/Akash007AD/Medical-Deepfake-Analysis.git
cd medical-deepfake-pipeline

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

**Dependencies:** `pydicom blake3 cryptography numpy scipy Pillow`

---

## Usage

```bash
python pipeline.py
```

The script auto-generates synthetic test DICOMs, enrolls the real image, then runs all 4 scenarios.

---

## Project Structure

```
medical-deepfake-pipeline/
├── pipeline.py
├── requirements.txt
├── README.md
├── .gitignore
└── test_dicoms/          ← auto-generated on run
```

---

## Future Work

- PACS integration
- Real blockchain backend (Hyperledger / Ethereum)
- HSM-based key storage
- Real scanner PRNU extraction from flat-field calibration images
- Tamper localization heatmap
- Web dashboard

---

## Disclaimer

Research prototype only. Not for clinical use without proper validation and regulatory approval.

---

## License

MIT