"""
Medical Deepfake Detection Pipeline
=====================================
Cryptographic authentication of DICOM medical images.
No computer vision. No GPU. Runs on any device.

Layers:
  1. DICOM Metadata Gate
  2. BLAKE3 Hash + Ed25519 Digital Signature
  3. PRNU Device Fingerprint Correlation
  4. Merkle Tree Selective Audit
  5. Ledger Provenance Check

Install:  pip install pydicom blake3 cryptography numpy Pillow
Run:      python pipeline.py
"""

import os
import json
import time
import hashlib
import struct
import blake3
import numpy as np
import pydicom
from pydicom.dataset import Dataset, FileDataset
from pydicom.sequence import Sequence
from pydicom.uid import generate_uid
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from pathlib import Path
import copy


# ─────────────────────────────────────────────
#  COLOUR OUTPUT  (works on any terminal)
# ─────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):    print(f"  {GREEN}✓{RESET}  {msg}")
def fail(msg):  print(f"  {RED}✗{RESET}  {msg}")
def info(msg):  print(f"  {CYAN}→{RESET}  {msg}")
def warn(msg):  print(f"  {YELLOW}!{RESET}  {msg}")
def header(msg):print(f"\n{BOLD}{CYAN}{'─'*55}{RESET}\n{BOLD}  {msg}{RESET}\n{'─'*55}")


# ═══════════════════════════════════════════════════════
#  STEP 0 ── CREATE FAKE DICOM FILES FOR TESTING
# ═══════════════════════════════════════════════════════

def create_test_dicom(path: str, modality: str = "CT",
                      scanner_id: str = "SCANNER_001",
                      corrupt_meta: bool = False,
                      seed: int = 42,
                      prnu_profile: "np.ndarray | None" = None) -> None:
    """
    Creates a realistic synthetic DICOM file.
    corrupt_meta=True  → simulates missing/bad metadata (AI-generated image)
    seed               → different seeds = different 'patients'
    """
    np.random.seed(seed)

    # Simulate CT pixel data: 512×512, 16-bit Hounsfield units
    # Real CT: air≈-1000 HU, soft tissue≈+40 HU, bone≈+700 HU
    pixels = np.zeros((512, 512), dtype=np.int16)
    # background air
    pixels[:] = -1000
    # body oval
    y_idx, x_idx = np.ogrid[:512, :512]
    body = ((x_idx - 256)**2 / 200**2 + (y_idx - 256)**2 / 180**2) < 1
    pixels[body] = np.random.randint(30, 60, pixels[body].shape)
    # bone ring
    bone = (((x_idx-256)**2/190**2 + (y_idx-256)**2/170**2) < 1) & \
           (((x_idx-256)**2/175**2 + (y_idx-256)**2/155**2) > 1)
    pixels[bone] = 700
    # small organ
    organ = ((x_idx - 280)**2 / 30**2 + (y_idx - 240)**2 / 25**2) < 1
    pixels[organ] = np.random.randint(50, 120, pixels[organ].shape)

    ds = FileDataset(path, {}, preamble=b"\0"*128)

    # ── File Meta ──────────────────────────────────────
    ds.file_meta                          = Dataset()
    ds.file_meta.MediaStorageSOPClassUID  = "1.2.840.10008.5.1.4.1.1.2"
    ds.file_meta.MediaStorageSOPInstanceUID = generate_uid()
    ds.file_meta.TransferSyntaxUID        = "1.2.840.10008.1.2.1"
    ds.is_implicit_VR                     = False
    ds.is_little_endian                   = True

    # ── Patient / Study info ───────────────────────────
    if not corrupt_meta:
        ds.PatientName              = f"Test^Patient^{seed}"
        ds.PatientID                = f"PAT{seed:04d}"
        ds.StudyDate                = "20240315"
        ds.SeriesDate               = "20240315"
        ds.ContentDate              = "20240315"
        ds.StudyTime                = "083000"
        ds.Modality                 = modality
        ds.Manufacturer             = "TestScanner Corp"
        ds.ManufacturerModelName    = scanner_id
        ds.DeviceSerialNumber       = f"SN-{scanner_id}-9876"
        ds.SliceThickness           = "2.5"
        ds.PixelSpacing             = [0.703, 0.703]
        ds.Rows                     = 512
        ds.Columns                  = 512
        ds.BitsAllocated            = 16
        ds.BitsStored               = 16
        ds.HighBit                  = 15
        ds.PixelRepresentation      = 1
        ds.SOPClassUID              = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID           = generate_uid()
        ds.StudyInstanceUID         = generate_uid()
        ds.SeriesInstanceUID        = generate_uid()
        ds.InstanceNumber           = "1"
    else:
        # AI-generated image: missing critical tags
        ds.PatientID    = ""
        ds.StudyDate    = ""
        ds.Modality     = ""          # blank modality — red flag
        ds.Manufacturer = ""
        ds.Rows         = 512
        ds.Columns      = 512
        ds.BitsAllocated= 16
        ds.BitsStored   = 16
        ds.HighBit      = 15
        ds.PixelRepresentation = 1

    # Embed scanner PRNU into pixel data (simulates physical sensor characteristic)
    if prnu_profile is not None and not corrupt_meta:
        pixels_f = pixels.astype(np.float32)
        pixels_f = pixels_f + prnu_profile * np.abs(pixels_f)
        pixels   = np.clip(pixels_f, -32768, 32767).astype(np.int16)
    ds.PixelData = pixels.tobytes()
    pydicom.dcmwrite(path, ds, write_like_original=False)


# ═══════════════════════════════════════════════════════
#  LAYER 1 ── DICOM METADATA GATE
# ═══════════════════════════════════════════════════════

REQUIRED_TAGS = [
    ("PatientID",           "Patient ID"),
    ("StudyDate",           "Study date"),
    ("Modality",            "Modality"),
    ("Manufacturer",        "Scanner manufacturer"),
    ("SliceThickness",      "Slice thickness"),
    ("Rows",                "Image rows"),
    ("Columns",             "Image columns"),
    ("SOPInstanceUID",      "SOP Instance UID"),
]

def layer1_metadata_gate(ds: Dataset) -> tuple[bool, list[str]]:
    """
    Check DICOM metadata for completeness and consistency.
    Returns (passed: bool, issues: list[str])
    """
    issues = []

    # 1a. Required tag presence
    for tag_name, label in REQUIRED_TAGS:
        val = getattr(ds, tag_name, None)
        if val is None or str(val).strip() == "":
            issues.append(f"Missing/empty: {label} ({tag_name})")

    # 1b. Timestamp chain: StudyDate ≤ SeriesDate ≤ ContentDate
    try:
        study  = getattr(ds, "StudyDate",   "")
        series = getattr(ds, "SeriesDate",  "")
        content= getattr(ds, "ContentDate", "")
        if study and series and content:
            if not (study <= series <= content):
                issues.append(
                    f"Timestamp chain violated: "
                    f"StudyDate={study} SeriesDate={series} ContentDate={content}"
                )
    except Exception:
        pass

    # 1c. FOV consistency: PixelSpacing × Rows/Cols should be reasonable
    try:
        ps   = getattr(ds, "PixelSpacing", None)
        rows = getattr(ds, "Rows", None)
        cols = getattr(ds, "Columns", None)
        if ps and rows and cols:
            fov_x = float(ps[0]) * int(rows)
            fov_y = float(ps[1]) * int(cols)
            # Typical CT FOV: 100–600 mm
            if not (100 <= fov_x <= 600 and 100 <= fov_y <= 600):
                issues.append(
                    f"Suspicious FOV: {fov_x:.1f}mm × {fov_y:.1f}mm "
                    f"(expected 100–600mm)"
                )
    except Exception:
        pass

    # 1d. Modality must be a known value
    valid_modalities = {"CT", "MR", "CR", "DX", "PT", "US", "MG", "NM", "XA"}
    modality = str(getattr(ds, "Modality", "")).strip().upper()
    if modality and modality not in valid_modalities:
        issues.append(f"Unknown modality: '{modality}'")

    return len(issues) == 0, issues


# ═══════════════════════════════════════════════════════
#  LAYER 2 ── BLAKE3 HASH + Ed25519 SIGNATURE
# ═══════════════════════════════════════════════════════

class CryptoAuthority:
    """
    Simulates the hospital's signing authority.
    In production: private key lives in HSM/TPM inside the scanner.
    """
    def __init__(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key  = self.private_key.public_key()
        info("Scanner key pair generated (Ed25519, 256-bit security)")

    def get_image_hash(self, ds: Dataset) -> bytes:
        """BLAKE3 hash over pixel data + critical metadata tags."""
        h = blake3.blake3()
        # Pixel data
        h.update(bytes(ds.PixelData))
        # Critical metadata (order matters — must be same at verify time)
        for tag in ["PatientID", "StudyDate", "Modality",
                    "Manufacturer", "SOPInstanceUID"]:
            val = str(getattr(ds, tag, "")).encode()
            h.update(val)
        return h.digest()

    def sign(self, image_hash: bytes) -> bytes:
        """Sign the hash with scanner's Ed25519 private key."""
        return self.private_key.sign(image_hash)

    def verify(self, image_hash: bytes, signature: bytes) -> bool:
        """Verify signature with scanner's public key."""
        try:
            self.public_key.verify(signature, image_hash)
            return True
        except InvalidSignature:
            return False


def layer2_hash_and_signature(ds: Dataset,
                               authority: CryptoAuthority,
                               stored_sig: bytes) -> tuple[bool, str]:
    """
    Recompute hash, verify Ed25519 signature.
    Returns (passed, detail_message)
    """
    t0 = time.perf_counter()
    image_hash   = authority.get_image_hash(ds)
    elapsed      = (time.perf_counter() - t0) * 1000
    hash_hex     = image_hash.hex()[:32] + "..."
    passed       = authority.verify(image_hash, stored_sig)
    return passed, f"BLAKE3={hash_hex}  ({elapsed:.2f} ms)"


# ═══════════════════════════════════════════════════════
#  LAYER 3 ── PRNU DEVICE FINGERPRINT CORRELATION
# ═══════════════════════════════════════════════════════

class PRNURegistry:
    """
    Simulates a registry of enrolled scanner PRNU fingerprints.
    PRNU = Photo Response Non-Uniformity — unique sensor noise pattern.
    """
    def __init__(self):
        self._profiles: dict[str, np.ndarray] = {}

    def enroll_scanner(self, scanner_id: str, seed: int) -> None:
        """
        In production: derive PRNU from 50+ flat-field images per scanner.
        Here: each scanner has a unique fixed-pattern noise (PRNU) baked in
        at 'manufacture time' via seed. The test images are then GENERATED
        with that same PRNU embedded, so correlation is high for matching
        scanner and near-zero for mismatching scanner — exactly as in reality.
        """
        rng = np.random.default_rng(seed)
        # PRNU: unique per scanner, amplitude σ≈0.02 of pixel value
        true_prnu = rng.normal(0, 0.02, (512, 512)).astype(np.float32)
        self._profiles[scanner_id] = true_prnu
        info(f"Enrolled scanner fingerprint: {scanner_id}")

    def get_prnu_seed_for_scanner(self, scanner_id: str) -> np.ndarray | None:
        """Return the stored PRNU profile (used when generating test images)."""
        return self._profiles.get(scanner_id)

    def get_noise_residual(self, pixel_array: np.ndarray) -> np.ndarray:
        """
        Extract noise residual = image − denoised(image).
        Uniform box-filter denoising O(N) — no loops, no GPU.
        """
        from scipy.ndimage import uniform_filter
        img      = pixel_array.astype(np.float32)
        denoised = uniform_filter(img, size=3)
        return img - denoised

    def correlate(self, scanner_id: str,
                  noise_residual: np.ndarray) -> tuple[float, bool]:
        """
        Normalized cross-correlation between image residual and stored PRNU.
        Score > 0.08 → likely from this scanner.
        Score ≈ 0    → different scanner or AI-generated.
        """
        if scanner_id not in self._profiles:
            return 0.0, False
        ref    = self._profiles[scanner_id]
        res    = noise_residual
        r_flat = ref.flatten()
        n_flat = res.flatten()
        norm_r = r_flat - r_flat.mean()
        norm_n = n_flat - n_flat.mean()
        denom  = (np.linalg.norm(norm_r) * np.linalg.norm(norm_n))
        if denom == 0:
            return 0.0, False
        score  = float(np.dot(norm_r, norm_n) / denom)
        return score, score > 0.08


def layer3_prnu(ds: Dataset,
                registry: PRNURegistry,
                scanner_id: str) -> tuple[bool, str]:
    t0       = time.perf_counter()
    pixels   = np.frombuffer(bytes(ds.PixelData), dtype=np.int16).reshape(512, 512)
    residual = registry.get_noise_residual(pixels.astype(np.float32))
    score, passed = registry.correlate(scanner_id, residual)
    elapsed  = (time.perf_counter() - t0) * 1000
    return passed, f"Correlation={score:.4f}  threshold=0.05  ({elapsed:.2f} ms)"


# ═══════════════════════════════════════════════════════
#  LAYER 4 ── MERKLE TREE SELECTIVE AUDIT
# ═══════════════════════════════════════════════════════

def _tile_hash(tile_bytes: bytes) -> bytes:
    """BLAKE3 hash of one image tile."""
    return blake3.blake3(tile_bytes).digest()

def _parent_hash(left: bytes, right: bytes) -> bytes:
    """Combine two child hashes into a parent node."""
    return blake3.blake3(left + right).digest()

class MerkleTree:
    """
    Binary Merkle tree built from 64×64 pixel tiles.
    Root hash = fingerprint of entire image structure.
    Any tile modification → root changes → detected.
    """
    def __init__(self, pixel_bytes: bytes,
                 img_rows: int = 512, img_cols: int = 512,
                 tile_size: int = 64):
        self.tile_size = tile_size
        self.img_rows  = img_rows
        self.img_cols  = img_cols
        self.leaves    = self._compute_leaves(pixel_bytes)
        self.tree      = self._build_tree(self.leaves)
        self.root      = self.tree[0]

    def _compute_leaves(self, pixel_bytes: bytes) -> list[bytes]:
        """Hash each 64×64 tile independently."""
        arr   = np.frombuffer(pixel_bytes, dtype=np.uint8)
        # Reshape to rows of bytes (each pixel = 2 bytes for int16)
        tiles = []
        ts    = self.tile_size * 2  # bytes per tile row
        cols_bytes = self.img_cols * 2
        for row in range(0, self.img_rows, self.tile_size):
            for col in range(0, self.img_cols, self.tile_size):
                tile_data = b""
                for r in range(self.tile_size):
                    start = (row + r) * cols_bytes + col * 2
                    tile_data += pixel_bytes[start: start + ts]
                tiles.append(_tile_hash(tile_data))
        return tiles

    def _build_tree(self, leaves: list[bytes]) -> list[bytes]:
        """Build bottom-up binary tree. Returns [root, ...all nodes]."""
        level = leaves[:]
        # Pad to power of 2
        while len(level) & (len(level) - 1):
            level.append(level[-1])
        all_nodes = []
        while len(level) > 1:
            parents = []
            for i in range(0, len(level), 2):
                parents.append(_parent_hash(level[i], level[i+1]))
            all_nodes = parents + all_nodes
            level = parents
        return level + all_nodes  # root first

    def get_proof(self, leaf_idx: int) -> list[tuple[str, bytes]]:
        """Return sibling hashes needed to verify one tile (O log N)."""
        proof  = []
        idx    = leaf_idx
        level  = self.leaves[:]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            sibling = idx ^ 1
            side    = "right" if idx % 2 == 0 else "left"
            proof.append((side, level[sibling]))
            idx //= 2
            level = [_parent_hash(level[i], level[i+1])
                     for i in range(0, len(level), 2)]
        return proof


def layer4_merkle(ds: Dataset,
                  stored_root: bytes) -> tuple[bool, str]:
    t0   = time.perf_counter()
    tree = MerkleTree(bytes(ds.PixelData))
    elapsed = (time.perf_counter() - t0) * 1000
    passed  = (tree.root == stored_root)
    tiles   = len(tree.leaves)
    return passed, (
        f"Root={'match' if passed else 'MISMATCH'}  "
        f"Tiles={tiles}  ({elapsed:.2f} ms)"
    )


# ═══════════════════════════════════════════════════════
#  LAYER 5 ── LEDGER PROVENANCE CHECK
# ═══════════════════════════════════════════════════════

class ProvenanceLedger:
    """
    Simulated immutable ledger (blockchain / hospital DB).
    In production: Hyperledger Fabric or Ethereum smart contract.
    Here: a simple in-memory chained hash log (same principle as blockchain).
    """
    def __init__(self):
        self._chain: list[dict] = []
        # Genesis block
        self._chain.append({
            "index":     0,
            "prev_hash": "0" * 64,
            "data":      "GENESIS",
            "timestamp": datetime.utcnow().isoformat(),
            "block_hash": hashlib.sha256(b"GENESIS").hexdigest()
        })

    def _last_hash(self) -> str:
        return self._chain[-1]["block_hash"]

    def enroll(self, sop_uid: str, merkle_root: bytes,
               scanner_id: str) -> str:
        """Add a record to the ledger. Returns block hash."""
        payload = {
            "index":      len(self._chain),
            "prev_hash":  self._last_hash(),
            "sop_uid":    sop_uid,
            "merkle_root":merkle_root.hex(),
            "scanner_id": scanner_id,
            "timestamp":  datetime.utcnow().isoformat(),
        }
        raw        = json.dumps(payload, sort_keys=True).encode()
        block_hash = hashlib.sha256(raw).hexdigest()
        payload["block_hash"] = block_hash
        self._chain.append(payload)
        return block_hash

    def verify(self, sop_uid: str,
               merkle_root: bytes) -> tuple[bool, str]:
        """Look up SOP UID in ledger and confirm Merkle root matches."""
        for block in self._chain:
            if block.get("sop_uid") == sop_uid:
                stored = block.get("merkle_root", "")
                if stored == merkle_root.hex():
                    return True, f"Found at block #{block['index']}"
                else:
                    return False, "SOP UID found but Merkle root MISMATCH"
        return False, "SOP UID not found in ledger — image never enrolled"

    def chain_integrity_ok(self) -> bool:
        """Verify the ledger itself hasn't been tampered with."""
        for i in range(1, len(self._chain)):
            blk  = self._chain[i]
            prev = self._chain[i-1]
            if blk["prev_hash"] != prev["block_hash"]:
                return False
        return True


def layer5_ledger(ds: Dataset,
                  merkle_root: bytes,
                  ledger: ProvenanceLedger) -> tuple[bool, str]:
    sop_uid      = str(getattr(ds, "SOPInstanceUID", "UNKNOWN"))
    passed, msg  = ledger.verify(sop_uid, merkle_root)
    chain_ok     = ledger.chain_integrity_ok()
    if not chain_ok:
        return False, "Ledger chain integrity FAILED — ledger may be compromised"
    return passed, msg


# ═══════════════════════════════════════════════════════
#  MAIN PIPELINE RUNNER
# ═══════════════════════════════════════════════════════

def run_pipeline(dicom_path: str,
                 authority: CryptoAuthority,
                 stored_sig: bytes,
                 stored_merkle_root: bytes,
                 prnu_registry: PRNURegistry,
                 ledger: ProvenanceLedger,
                 claimed_scanner: str,
                 label: str) -> bool:

    header(f"Testing: {label}")
    info(f"File: {dicom_path}")

    # Load DICOM
    try:
        ds = pydicom.dcmread(dicom_path, force=True)
    except Exception as e:
        fail(f"Cannot read DICOM file: {e}")
        return False

    results = {}
    overall = True

    # ── Layer 1 ────────────────────────────────────────
    print(f"\n  {BOLD}Layer 1 — Metadata Gate{RESET}")
    t0 = time.perf_counter()
    passed, issues = layer1_metadata_gate(ds)
    elapsed = (time.perf_counter() - t0) * 1000
    results["L1"] = passed
    if passed:
        ok(f"All metadata valid  ({elapsed:.2f} ms)")
    else:
        for issue in issues:
            fail(issue)
        overall = False
        print(f"\n  {RED}{BOLD}  ► REJECTED at Layer 1{RESET}")
        return False

    # ── Layer 2 ────────────────────────────────────────
    print(f"\n  {BOLD}Layer 2 — BLAKE3 Hash + Ed25519 Signature{RESET}")
    passed, detail = layer2_hash_and_signature(ds, authority, stored_sig)
    results["L2"] = passed
    if passed:
        ok(f"Signature valid  {detail}")
    else:
        fail(f"Signature INVALID  {detail}")
        overall = False
        print(f"\n  {RED}{BOLD}  ► REJECTED at Layer 2{RESET}")
        return False

    # ── Layer 3 ────────────────────────────────────────
    print(f"\n  {BOLD}Layer 3 — PRNU Device Fingerprint{RESET}")
    passed, detail = layer3_prnu(ds, prnu_registry, claimed_scanner)
    results["L3"] = passed
    if passed:
        ok(f"Scanner fingerprint matched  {detail}")
    else:
        fail(f"Scanner fingerprint MISMATCH  {detail}")
        overall = False
        print(f"\n  {RED}{BOLD}  ► REJECTED at Layer 3{RESET}")
        return False

    # ── Layer 4 ────────────────────────────────────────
    print(f"\n  {BOLD}Layer 4 — Merkle Tree Audit{RESET}")
    passed, detail = layer4_merkle(ds, stored_merkle_root)
    results["L4"] = passed
    if passed:
        ok(f"Merkle root verified  {detail}")
    else:
        fail(f"Merkle root MISMATCH  {detail}")
        overall = False
        print(f"\n  {RED}{BOLD}  ► REJECTED at Layer 4{RESET}")
        return False

    # ── Layer 5 ────────────────────────────────────────
    print(f"\n  {BOLD}Layer 5 — Ledger Provenance{RESET}")
    merkle_tree = MerkleTree(bytes(ds.PixelData))
    passed, detail = layer5_ledger(ds, merkle_tree.root, ledger)
    results["L5"] = passed
    if passed:
        ok(f"Ledger record found  {detail}")
    else:
        fail(f"Ledger check FAILED  {detail}")
        overall = False
        print(f"\n  {RED}{BOLD}  ► REJECTED at Layer 5{RESET}")
        return False

    # ── Final verdict ──────────────────────────────────
    print(f"\n  {GREEN}{BOLD}  ► AUTHENTICATED ✓  All 5 layers passed{RESET}")
    return True


# ═══════════════════════════════════════════════════════
#  TEST SCENARIOS
# ═══════════════════════════════════════════════════════

def main():
    print(f"\n{BOLD}{CYAN}{'═'*55}")
    print("  MEDICAL DEEPFAKE DETECTION PIPELINE")
    print(f"  Cryptographic Authentication — No CV Required")
    print(f"{'═'*55}{RESET}")

    # ── System setup ───────────────────────────────────
    header("System Initialisation")

    # 1. Scanner authority (hospital PKI)
    authority = CryptoAuthority()

    # 2. PRNU registry (known scanners)
    prnu = PRNURegistry()
    prnu.enroll_scanner("SCANNER_001", seed=1001)
    prnu.enroll_scanner("SCANNER_002", seed=1002)

    # 3. Provenance ledger (blockchain simulation)
    ledger = ProvenanceLedger()
    info("Ledger initialised (genesis block created)")

    # ── Create test DICOM files ─────────────────────────
    header("Creating Test DICOM Files")
    os.makedirs("test_dicoms", exist_ok=True)

    real_path  = "test_dicoms/real_ct.dcm"
    tampered_path = "test_dicoms/tampered_ct.dcm"
    fake_path  = "test_dicoms/ai_generated.dcm"
    diff_scan_path = "test_dicoms/different_scanner.dcm"

    prnu1 = prnu.get_prnu_seed_for_scanner("SCANNER_001")
    prnu2 = prnu.get_prnu_seed_for_scanner("SCANNER_002")
    create_test_dicom(real_path,     scanner_id="SCANNER_001", seed=42, prnu_profile=prnu1)
    create_test_dicom(tampered_path, scanner_id="SCANNER_001", seed=42, prnu_profile=prnu1)  # same, will tamper
    create_test_dicom(fake_path,     corrupt_meta=True, seed=99)           # missing metadata, no PRNU
    create_test_dicom(diff_scan_path,scanner_id="SCANNER_002", seed=77, prnu_profile=prnu2)  # different scanner

    info(f"Real CT:            {real_path}")
    info(f"Tampered CT:        {tampered_path}")
    info(f"AI-generated fake:  {fake_path}")
    info(f"Wrong scanner:      {diff_scan_path}")

    # ── Enroll the real image ───────────────────────────
    header("Enrollment (at scanner — happens once at acquisition)")

    ds_real        = pydicom.dcmread(real_path, force=True)
    image_hash     = authority.get_image_hash(ds_real)
    stored_sig     = authority.sign(image_hash)
    merkle_tree    = MerkleTree(bytes(ds_real.PixelData))
    stored_root    = merkle_tree.root
    sop_uid        = str(ds_real.SOPInstanceUID)

    block_hash = ledger.enroll(sop_uid, stored_root, "SCANNER_001")

    ok(f"Hash computed (BLAKE3)")
    ok(f"Signature created (Ed25519) — {len(stored_sig)} bytes")
    ok(f"Merkle root stored — {stored_root.hex()[:24]}...")
    ok(f"Ledger block: {block_hash[:24]}...")

    # ── Tamper with the copy ────────────────────────────
    header("Simulating Pixel Tampering")
    ds_tampered = pydicom.dcmread(tampered_path, force=True)
    pixels = np.frombuffer(bytes(ds_tampered.PixelData),
                           dtype=np.int16).copy().reshape(512, 512)
    # Inject fake tumor (change a 20×20 region)
    pixels[240:260, 250:270] = 800   # abnormally bright region
    ds_tampered.PixelData    = pixels.tobytes()
    pydicom.dcmwrite(tampered_path, ds_tampered, write_like_original=False)
    info("Injected fake 20×20 bright region into tampered_ct.dcm")

    # ══════════════════════════════════════════════════
    #  RUN ALL 4 TEST SCENARIOS
    # ══════════════════════════════════════════════════
    results = {}

    # TEST 1: Real authentic image (should PASS all layers)
    results["Real CT (authentic)"] = run_pipeline(
        real_path, authority, stored_sig, stored_root,
        prnu, ledger, "SCANNER_001",
        "Real CT (should PASS)"
    )

    # TEST 2: AI-generated with corrupt metadata (should FAIL Layer 1)
    results["AI-generated (corrupt meta)"] = run_pipeline(
        fake_path, authority, stored_sig, stored_root,
        prnu, ledger, "SCANNER_001",
        "AI-Generated Image — missing metadata (should FAIL Layer 1)"
    )

    # TEST 3: Real image with tampered pixels (should FAIL Layer 2)
    results["Pixel-tampered CT"] = run_pipeline(
        tampered_path, authority, stored_sig, stored_root,
        prnu, ledger, "SCANNER_001",
        "Pixel-Tampered CT — injected fake region (should FAIL Layer 2)"
    )

    # TEST 4: Image from different/unknown scanner (should FAIL Layer 3)
    # Give it valid sig/root from real image to test that L3 catches it
    ds_diff   = pydicom.dcmread(diff_scan_path, force=True)
    diff_hash = authority.get_image_hash(ds_diff)
    diff_sig  = authority.sign(diff_hash)
    diff_tree = MerkleTree(bytes(ds_diff.PixelData))
    results["Wrong scanner"] = run_pipeline(
        diff_scan_path, authority, diff_sig, diff_tree.root,
        prnu, ledger, "SCANNER_001",   # claim it's from SCANNER_001 (lie)
        "Image from Different Scanner (should FAIL Layer 3 — PRNU mismatch)"
    )

    # ── Summary ─────────────────────────────────────────
    header("SUMMARY")
    passed_count = sum(1 for v in results.values() if v)
    total = len(results)

    for label, passed in results.items():
        if passed:
            ok(f"{label:45s} → AUTHENTICATED")
        else:
            fail(f"{label:45s} → REJECTED")

    print(f"\n  {BOLD}Authenticated: {passed_count}/{total}  |  "
          f"Rejected: {total-passed_count}/{total}{RESET}")
    print(f"\n  {CYAN}Note: Only the 'Real CT' should authenticate.")
    print(f"  All others should be rejected. This is correct behaviour.{RESET}\n")


if __name__ == "__main__":
    main()
