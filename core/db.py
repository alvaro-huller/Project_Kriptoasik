"""SQLite terenkripsi level aplikasi (AES-256-GCM, nonce acak per baris) + hash chain aset."""
import json
import sqlite3
import hashlib
import base64
from datetime import datetime, timezone
from .crypto import aes_encrypt, aes_decrypt, CryptoError


class VaultDB:
    def __init__(self, path: str, db_key: bytes, chain_key: bytes):
        self.key = bytes(db_key)
        self.chain_key = bytes(chain_key)
        self.con = sqlite3.connect(path)
        self.con.executescript("""
        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            nonce BLOB NOT NULL UNIQUE,
            ciphertext BLOB NOT NULL,
            tag BLOB NOT NULL,
            created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS blocks(
            idx INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            nonce BLOB NOT NULL UNIQUE,
            ciphertext BLOB NOT NULL,
            tag BLOB NOT NULL,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL);
        """)
        self.con.commit()

    # ---------- pesan ----------
    def add_message(self, kind: str, label: str, content: bytes) -> int:
        payload = json.dumps({"label": label, "data": base64.b64encode(content).decode()}).encode()
        nonce, ct, tag = aes_encrypt(self.key, payload, kind.encode())  # nonce baru tiap baris
        cur = self.con.execute(
            "INSERT INTO messages(kind,nonce,ciphertext,tag,created) VALUES(?,?,?,?,?)",
            (kind, nonce, ct, tag, _now()))
        self.con.commit()
        return cur.lastrowid

    def list_messages(self):
        return self.con.execute("SELECT id,kind,created FROM messages ORDER BY id DESC").fetchall()

    def get_message(self, mid: int):
        row = self.con.execute("SELECT kind,nonce,ciphertext,tag FROM messages WHERE id=?", (mid,)).fetchone()
        if not row:
            raise CryptoError("Pesan tidak ada")
        kind, nonce, ct, tag = row
        d = json.loads(aes_decrypt(self.key, nonce, ct, tag, kind.encode()))
        return kind, d["label"], base64.b64decode(d["data"])

    def get_raw(self, mid: int):
        """Data mentah tersimpan (terenkripsi): kind, nonce, ciphertext, tag, created."""
        row = self.con.execute("SELECT kind,nonce,ciphertext,tag,created FROM messages WHERE id=?", (mid,)).fetchone()
        if not row:
            raise CryptoError("Pesan tidak ada")
        return row

    def delete_message(self, mid: int):
        self.con.execute("DELETE FROM messages WHERE id=?", (mid,))
        self.con.commit()

    # ---------- blockchain (append-only) ----------
    @staticmethod
    def _hash(idx, ts, data_hash, prev):
        return hashlib.sha256(f"{idx}|{ts}|{data_hash}|{prev}".encode()).hexdigest()

    def add_block(self, asset: dict) -> dict:
        row = self.con.execute("SELECT idx,hash FROM blocks ORDER BY idx DESC LIMIT 1").fetchone()
        idx, prev = (row[0] + 1, row[1]) if row else (0, "0" * 64)
        ts = _now()
        raw = json.dumps(asset, sort_keys=True, ensure_ascii=False).encode()
        h = self._hash(idx, ts, hashlib.sha256(raw).hexdigest(), prev)
        nonce, ct, tag = aes_encrypt(self.chain_key, raw, f"block:{idx}".encode())
        self.con.execute("INSERT INTO blocks VALUES(?,?,?,?,?,?,?)", (idx, ts, nonce, ct, tag, prev, h))
        self.con.commit()
        return {"index": idx, "timestamp": ts, "prev_hash": prev, "hash": h}

    def blocks(self):
        out = []
        for idx, ts, nonce, ct, tag, prev, h in self.con.execute("SELECT * FROM blocks ORDER BY idx"):
            try:
                data = json.loads(aes_decrypt(self.chain_key, nonce, ct, tag, f"block:{idx}".encode()))
            except CryptoError:
                data = {"_error": "tidak bisa didekripsi"}
            out.append({"index": idx, "timestamp": ts, "data": data, "prev_hash": prev, "hash": h})
        return out

    def verify_chain(self):
        """Return (ok, pesan). Hitung ulang setiap hash dan cek tautan prev_hash."""
        prev = "0" * 64
        expected_idx = 0
        for b in self.blocks():
            if b["index"] != expected_idx:
                return False, f"Indeks loncat di blok {b['index']}"
            if "_error" in b["data"]:
                return False, f"Blok {b['index']}: data rusak/diubah"
            raw = json.dumps(b["data"], sort_keys=True, ensure_ascii=False).encode()
            h = self._hash(b["index"], b["timestamp"], hashlib.sha256(raw).hexdigest(), b["prev_hash"])
            if b["prev_hash"] != prev:
                return False, f"Blok {b['index']}: prev_hash tidak cocok"
            if h != b["hash"]:
                return False, f"Blok {b['index']}: hash tidak valid"
            prev = b["hash"]
            expected_idx += 1
        return True, f"Chain valid ({expected_idx} blok)"

    def close(self):
        self.con.close()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
