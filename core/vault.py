"""Penyimpanan meta vault. Master Key (MK) acak dibungkus (AES-GCM) dengan KEK = Argon2id(password, serial USB, isi .vault_key).
Dua pembungkus: primary (password + gate wajah) dan fallback (password cadangan, tanpa wajah).
Template wajah (embedding SFace) dienkripsi dengan subkey dari MK; tidak ada foto mentah disimpan."""
import os
import json
import base64
import numpy as np
from .crypto import argon2id_key, aes_pack, aes_unpack, hkdf, CryptoError
from . import usb

b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)


class VaultStore:
    def __init__(self, home: str | None = None):
        self.home = home or os.path.join(os.path.expanduser("~"), ".securevault")
        os.makedirs(self.home, exist_ok=True)
        self.meta_path = os.path.join(self.home, "vault.json")
        self.db_path = os.path.join(self.home, "vault.db")

    def exists(self) -> bool:
        return os.path.isfile(self.meta_path)

    def _load(self):
        with open(self.meta_path) as f:
            return json.load(f)

    def _save(self, meta):
        tmp = self.meta_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(meta, f)
        os.replace(tmp, self.meta_path)

    @staticmethod
    def _kek(pw: str, drive: usb.Drive, keyfile: bytes, salt: bytes) -> bytes:
        return argon2id_key([pw.encode(), drive.serial.encode(), keyfile], salt)

    def setup(self, drive: usb.Drive, password: str, fallback_pw: str, face_template: np.ndarray | None) -> bytes:
        if self.exists():
            raise CryptoError("Vault sudah ada")
        if len(password) < 8 or len(fallback_pw) < 8:
            raise CryptoError("Password minimal 8 karakter")
        if password == fallback_pw:
            raise CryptoError("Password fallback harus berbeda")
        keyfile = usb.read_keyfile(drive) or usb.write_keyfile(drive)
        mk = os.urandom(32)
        meta = {"version": 1}
        for name, pw in (("primary", password), ("fallback", fallback_pw)):
            salt = os.urandom(16)
            meta[name] = {"salt": b64e(salt),
                          "wrap": b64e(aes_pack(self._kek(pw, drive, keyfile, salt), mk, b"SV-MK"))}
        meta["face"] = None
        if face_template is not None:
            meta["face"] = b64e(aes_pack(hkdf(mk, b"sv/face"), face_template.astype(np.float32).tobytes(), b"SV-FACE"))
        self._save(meta)
        return mk

    def unlock(self, drive: usb.Drive, password: str, fallback: bool = False) -> bytes:
        keyfile = usb.read_keyfile(drive)
        if keyfile is None:
            raise CryptoError("USB tidak berisi .vault_key")
        w = self._load()["fallback" if fallback else "primary"]
        kek = self._kek(password, drive, keyfile, b64d(w["salt"]))
        try:
            return aes_unpack(kek, b64d(w["wrap"]), b"SV-MK")
        except CryptoError:
            raise CryptoError("Password / USB salah")

    def has_face(self) -> bool:
        return self.exists() and self._load().get("face") is not None

    def face_template(self, mk: bytes) -> np.ndarray | None:
        enc = self._load().get("face")
        if not enc:
            return None
        raw = aes_unpack(hkdf(mk, b"sv/face"), b64d(enc), b"SV-FACE")
        return np.frombuffer(raw, dtype=np.float32).reshape(1, -1)
