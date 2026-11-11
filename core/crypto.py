"""Primitif kripto SecureVault: KDF, Vigenere byte-level, AES-256-GCM, ChaCha20-Poly1305 (streaming)."""
import os
import struct
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError:  # cryptography < 44
    Argon2id = None

ARGON_ITER, ARGON_LANES, ARGON_MEM_KIB = 3, 4, 65536


class CryptoError(Exception):
    pass


def _lp(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def argon2id_key(parts, salt: bytes) -> bytes:
    """Argon2id atas gabungan (length-prefixed): password, serial USB, isi .vault_key."""
    material = b"".join(_lp(p) for p in parts)
    if Argon2id is None:
        raise CryptoError("Butuh cryptography>=44 untuk Argon2id")
    kdf = Argon2id(salt=salt, length=32, iterations=ARGON_ITER,
                   lanes=ARGON_LANES, memory_cost=ARGON_MEM_KIB)
    return kdf.derive(material)


def hkdf(key: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(bytes(key))


# ---------- Vigenere (level byte, mod 256) ----------
def vigenere_encrypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise CryptoError("Kunci Vigenere kosong")
    n = len(key)
    return bytes((b + key[i % n]) & 0xFF for i, b in enumerate(data))


def vigenere_decrypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise CryptoError("Kunci Vigenere kosong")
    n = len(key)
    return bytes((b - key[i % n]) & 0xFF for i, b in enumerate(data))


# ---------- AES-256-GCM ----------
def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b""):
    """Return (nonce, ciphertext, tag). Nonce acak baru setiap panggilan."""
    nonce = os.urandom(12)
    out = AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)
    return nonce, out[:-16], out[-16:]


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ciphertext + tag, aad)
    except Exception as e:
        raise CryptoError("Dekripsi gagal: kunci salah atau data diubah") from e


def aes_pack(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    n, c, t = aes_encrypt(key, plaintext, aad)
    return n + c + t


def aes_unpack(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < 28:
        raise CryptoError("Blob terlalu pendek")
    return aes_decrypt(key, blob[:12], blob[12:-16], blob[-16:], aad)


# ---------- Super enkripsi teks: Vigenere -> AES-256-GCM (kunci AES dari input pengguna) ----------
def text_encrypt(aes_pass: str, plaintext: str, vig_key: bytes) -> str:
    """Format base64: salt(16) | nonce(12) | ciphertext | tag(16). Kunci AES = Argon2id(aes_pass, salt)."""
    if not aes_pass:
        raise CryptoError("Kunci AES-256-GCM kosong")
    salt = os.urandom(16)
    key = argon2id_key([aes_pass.encode()], salt)
    stage1 = vigenere_encrypt(plaintext.encode("utf-8"), vig_key)
    return base64.b64encode(salt + aes_pack(key, stage1, b"SV-TEXT")).decode()


def text_decrypt(aes_pass: str, b64: str, vig_key: bytes) -> str:
    if not aes_pass:
        raise CryptoError("Kunci AES-256-GCM kosong")
    try:
        blob = base64.b64decode(b64.strip())
    except Exception as e:
        raise CryptoError("Base64 tidak valid") from e
    if len(blob) < 16 + 28:
        raise CryptoError("Ciphertext terlalu pendek")
    key = argon2id_key([aes_pass.encode()], blob[:16])
    stage1 = aes_unpack(key, blob[16:], b"SV-TEXT")
    return vigenere_decrypt(stage1, vig_key).decode("utf-8", errors="replace")


# ---------- File: ChaCha20-Poly1305 per-chunk ----------
MAGIC = b"SVF1"
CHUNK = 1024 * 1024


def _cnonce(prefix: bytes, counter: int) -> bytes:
    return prefix + struct.pack(">I", counter)


def file_encrypt(key: bytes, src: str, dst: str, progress=None):
    """Format: MAGIC | prefix(8) | ([len u32][ct+tag])* ; AAD = counter|final (anti reorder/truncate)."""
    prefix = os.urandom(8)
    aead = ChaCha20Poly1305(bytes(key))
    total = max(os.path.getsize(src), 1)
    done = 0
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(MAGIC + prefix)
        counter = 0
        buf = fi.read(CHUNK)
        while True:
            nxt = fi.read(CHUNK)
            final = 0 if nxt else 1
            ct = aead.encrypt(_cnonce(prefix, counter), buf, struct.pack(">IB", counter, final))
            fo.write(struct.pack(">I", len(ct)) + ct)
            done += len(buf)
            counter += 1
            if progress:
                progress(done, total)
            if final:
                break
            buf = nxt


def file_decrypt(key: bytes, src: str, dst: str, progress=None):
    aead = ChaCha20Poly1305(bytes(key))
    total = max(os.path.getsize(src), 1)
    tmp = dst + ".part"
    try:
        with open(src, "rb") as fi, open(tmp, "wb") as fo:
            head = fi.read(12)
            if len(head) < 12 or head[:4] != MAGIC:
                raise CryptoError("Bukan file SecureVault")
            prefix = head[4:]
            counter, saw_final = 0, False
            while True:
                raw = fi.read(4)
                if not raw:
                    break
                if len(raw) < 4:
                    raise CryptoError("File terpotong")
                (n,) = struct.unpack(">I", raw)
                ct = fi.read(n)
                if len(ct) != n:
                    raise CryptoError("File terpotong")
                final = 1 if fi.peek(1) == b"" else 0
                try:
                    pt = aead.decrypt(_cnonce(prefix, counter), ct, struct.pack(">IB", counter, final))
                except Exception as e:
                    raise CryptoError("Dekripsi gagal: kunci salah / file diubah") from e
                fo.write(pt)
                counter += 1
                saw_final = bool(final)
                if progress:
                    progress(fi.tell(), total)
            if not saw_final:
                raise CryptoError("File tidak lengkap")
        os.replace(tmp, dst)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


class Keyring:
    """Subkey per fitur dari Master Key (HKDF). wipe() menimpa memori (best effort)."""
    NAMES = ("_mk", "text", "file", "db", "stego", "face", "chain")

    def __init__(self, master_key: bytes):
        self._mk = bytearray(master_key)
        mk = bytes(self._mk)
        self.text = bytearray(hkdf(mk, b"sv/text"))
        self.file = bytearray(hkdf(mk, b"sv/file"))
        self.db = bytearray(hkdf(mk, b"sv/db"))
        self.stego = bytearray(hkdf(mk, b"sv/stego"))
        self.face = bytearray(hkdf(mk, b"sv/face"))
        self.chain = bytearray(hkdf(mk, b"sv/chain"))

    def wipe(self):
        for name in self.NAMES:
            b = getattr(self, name)
            for i in range(len(b)):
                b[i] = 0
