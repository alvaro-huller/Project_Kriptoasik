"""Adaptive LSB: area bertekstur (gradien tinggi) menampung 2-3 bit/kanal, area halus 1 bit.
Kompleksitas dihitung dari 5 bit atas piksel, jadi invarian terhadap perubahan LSB -> ekstraksi deterministik.
Output wajib PNG (lossless)."""
import struct
import numpy as np
from PIL import Image
from .crypto import aes_pack, aes_unpack, CryptoError

MAGIC = b"SVST"


def _plan(arr: np.ndarray) -> np.ndarray:
    gray = (arr >> 3).astype(np.int16).sum(axis=2)
    c = np.abs(gray - np.roll(gray, -1, axis=1)) + np.abs(gray - np.roll(gray, -1, axis=0))
    k = np.where(c < 6, 1, np.where(c < 20, 2, 3)).astype(np.uint8)
    return np.repeat(k[:, :, None], 3, axis=2).reshape(-1)


def capacity_bytes(path: str) -> int:
    arr = np.array(Image.open(path).convert("RGB"))
    return max(int(_plan(arr).sum(dtype=np.int64)) // 8 - 8 - 28, 0)  # header + overhead AES-GCM


def embed(cover_path: str, out_path: str, stego_key: bytes, payload: bytes):
    if not out_path.lower().endswith(".png"):
        raise CryptoError("Output harus .png (lossless)")
    arr = np.array(Image.open(cover_path).convert("RGB"), dtype=np.uint8)
    shape = arr.shape
    blob = aes_pack(stego_key, payload, b"SV-STEGO")          # enkripsi dulu
    data = MAGIC + struct.pack(">I", len(blob)) + blob
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    k = _plan(arr)
    if len(bits) > int(k.sum(dtype=np.int64)):
        raise CryptoError(f"Gambar terlalu kecil. Kapasitas ~{capacity_bytes(cover_path)} byte")
    cum = np.cumsum(k, dtype=np.int64)
    off = cum - k
    m = int(np.searchsorted(cum, len(bits))) + 1
    flat = arr.reshape(-1)
    kk, oo = k[:m], off[:m]
    val = np.zeros(m, dtype=np.uint8)
    for j in range(3):
        sel = (kk > j) & (oo + j < len(bits))
        val[sel] |= (bits[oo[sel] + j] << j).astype(np.uint8)
    clear = (0xFF ^ ((1 << kk.astype(np.uint16)) - 1)).astype(np.uint8)
    flat[:m] = (flat[:m] & clear) | val
    Image.fromarray(flat.reshape(shape), "RGB").save(out_path, format="PNG")


def extract(stego_path: str, stego_key: bytes) -> bytes:
    arr = np.array(Image.open(stego_path).convert("RGB"), dtype=np.uint8)
    k = _plan(arr)
    flat = arr.reshape(-1)
    cum = np.cumsum(k, dtype=np.int64)
    off = cum - k
    total = int(cum[-1])
    bits = np.zeros(total, dtype=np.uint8)
    for j in range(3):
        sel = k > j
        bits[off[sel] + j] = (flat[sel] >> j) & 1
    raw = np.packbits(bits).tobytes()
    if raw[:4] != MAGIC:
        raise CryptoError("Tidak ada data tersembunyi (atau gambar sudah dikompres/diubah)")
    (n,) = struct.unpack(">I", raw[4:8])
    if n > len(raw) - 8:
        raise CryptoError("Header korup")
    return aes_unpack(stego_key, raw[8:8 + n], b"SV-STEGO")
