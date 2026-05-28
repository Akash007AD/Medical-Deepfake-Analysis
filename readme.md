````md id="z50eqz"
# Medical Deepfake Detection Pipeline

A research-oriented cryptographic authentication pipeline for detecting tampering and verifying the authenticity of DICOM medical images.

This project focuses on integrity verification and provenance tracking instead of traditional AI/CNN-based fake image detection.

---

# Features

## Multi-Layer Authentication Pipeline

The system verifies DICOM medical images using 5 security layers:

1. DICOM Metadata Validation
2. BLAKE3 Cryptographic Hashing
3. Ed25519 Digital Signature Verification
4. PRNU Scanner Fingerprint Correlation
5. Merkle Tree Integrity Audit
6. Blockchain-style Provenance Ledger

---

# Pipeline Architecture

```text
DICOM Image
     ↓
Metadata Gate
     ↓
BLAKE3 + Ed25519 Signature Verification
     ↓
PRNU Device Fingerprint Correlation
     ↓
Merkle Tree Selective Audit
     ↓
Ledger / Provenance Verification
     ↓
AUTHENTICATED
````

---

# Technologies Used

* Python
* pydicom
* cryptography
* blake3
* numpy
* scipy
* Merkle Trees
* PRNU Forensics
* Digital Signatures

---

# Project Goal

This project demonstrates a secure medical image authentication workflow capable of:

* detecting pixel tampering
* verifying scan provenance
* validating scanner authenticity
* ensuring image integrity
* preventing unauthorized modification

without using deep learning or computer vision models.

---

# Installation

## Clone Repository

```bash
git clone https://github.com/your-username/medical-deepfake-pipeline.git
cd medical-deepfake-pipeline
```

## Create Virtual Environment

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

---

# Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Run Project

```bash
python medical_deepfake_pipeline.py
```

---

# Test Cases Included

The pipeline automatically creates and tests:

| Test Case            | Expected Result |
| -------------------- | --------------- |
| Real authentic CT    | PASS            |
| AI-generated image   | FAIL            |
| Pixel-tampered image | FAIL            |
| Wrong scanner image  | FAIL            |

---

# Example Output

```text
Layer 1 — Metadata Gate
✓ All metadata valid

Layer 2 — BLAKE3 Hash + Ed25519 Signature
✓ Signature valid

Layer 3 — PRNU Device Fingerprint
✓ Scanner fingerprint matched

Layer 4 — Merkle Tree Audit
✓ Merkle root verified

Layer 5 — Ledger Provenance
✓ Ledger record found

► AUTHENTICATED ✓
```

---

# Research Scope

This project is currently a research prototype / proof-of-concept system and not production-grade medical infrastructure.

Possible future improvements:

* PACS integration
* Real blockchain backend
* Hardware security modules (HSM)
* Real scanner PRNU extraction
* Cloud deployment
* Web dashboard
* Tamper localization visualization

---

# Project Structure

```text
medical-deepfake-pipeline/
│
├── medical_deepfake_pipeline.py
├── requirements.txt
├── README.md
├── .gitignore
├── test_dicoms/
└── venv/
```

---

# Disclaimer

This project is intended for:

* academic research
* educational purposes
* cybersecurity experimentation
* medical image integrity studies

It should not be used in clinical environments without proper validation and regulatory approval.

---

# License

MIT License

```
```
