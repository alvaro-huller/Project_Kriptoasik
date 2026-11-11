import os
import json
import inspect
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit,
                             QTextEdit, QPushButton, QLabel, QFileDialog, QMessageBox, QProgressBar,
                             QTableWidget, QTableWidgetItem, QApplication, QHeaderView)
from core import crypto, stego, usb
from core.db import VaultDB
from core.crypto import CryptoError


def _guard(fn):
    n = len(inspect.signature(fn).parameters) - 1   # jumlah argumen selain self

    def w(self, *args, **kwargs):
        try:
            return fn(self, *args[:n], **kwargs)    # buang argumen 'checked' berlebih
        except (CryptoError, OSError, ValueError) as e:
            QMessageBox.critical(self, "Error", str(e))
    return w


class MainWindow(QMainWindow):
    def __init__(self, keyring: crypto.Keyring, db: VaultDB, drive: usb.Drive):
        super().__init__()
        self.k, self.db, self.drive = keyring, db, drive
        self.setWindowTitle("SecureVault")
        self.resize(900, 640)
        tabs = QTabWidget()
        tabs.addTab(self._text_tab(), "Teks")
        tabs.addTab(self._file_tab(), "File")
        tabs.addTab(self._stego_tab(), "Gambar (Stego)")
        tabs.addTab(self._assets_tab(), "Aset (Blockchain)")
        tabs.addTab(self._db_tab(), "Database")
        self.setCentralWidget(tabs)
        self.statusBar().showMessage(f"USB: {drive}")
        # Dead Man's Switch
        self.dms = QTimer(self)
        self.dms.timeout.connect(self._check_usb)
        self.dms.start(1000)

    # ---------- Dead Man's Switch ----------
    def _check_usb(self):
        if not usb.still_present(self.drive):
            self.kill()

    def kill(self):
        self.dms.stop()
        try:
            self.k.wipe()
            self.db.close()
        finally:
            os._exit(1)

    def closeEvent(self, e):
        self.k.wipe()
        self.db.close()
        super().closeEvent(e)

    # ---------- Teks ----------
    def _text_tab(self):
        tabs = QTabWidget()
        tabs.addTab(self._t_panel(True), "Enkripsi")
        tabs.addTab(self._t_panel(False), "Dekripsi")
        return tabs

    def _t_panel(self, enc: bool):
        w = QWidget(); lay = QVBoxLayout(w)
        inp = QTextEdit(placeholderText="Plaintext" if enc else "Ciphertext (base64)")
        vk = QLineEdit(placeholderText="Kunci Vigenere")
        ak = QLineEdit(placeholderText="Kunci AES-256-GCM", echoMode=QLineEdit.EchoMode.Password)
        out = QTextEdit(readOnly=True)
        btn = QPushButton("Enkripsi" if enc else "Dekripsi")
        btn.clicked.connect(lambda _=False: self._t_run(enc, inp, vk, ak, out))
        lay.addWidget(QLabel("Input " + ("(plaintext)" if enc else "(ciphertext)")))
        lay.addWidget(inp)
        lay.addWidget(QLabel("Kunci Vigenere")); lay.addWidget(vk)
        lay.addWidget(QLabel("Kunci AES-256-GCM")); lay.addWidget(ak)
        lay.addWidget(btn)
        lay.addWidget(QLabel("Tampilan " + ("(ciphertext)" if enc else "(plaintext)")))
        lay.addWidget(out)
        return w

    @_guard
    def _t_run(self, enc, inp, vk, ak, out):
        if enc:
            out.setPlainText(crypto.text_encrypt(ak.text(), inp.toPlainText(), vk.text().encode()))
        else:
            out.setPlainText(crypto.text_decrypt(ak.text(), inp.toPlainText(), vk.text().encode()))

    # ---------- File ----------
    def _file_tab(self):
        w = QWidget(); lay = QVBoxLayout(w)
        self.f_bar = QProgressBar()
        b1, b2 = QPushButton("Enkripsi file (ChaCha20-Poly1305)"), QPushButton("Dekripsi file (.svenc)")
        b1.clicked.connect(self._f_enc); b2.clicked.connect(self._f_dec)
        for x in (b1, b2, self.f_bar):
            lay.addWidget(x)
        lay.addStretch()
        return w

    def _prog(self, d, t):
        self.f_bar.setValue(int(d * 100 / t)); QApplication.processEvents()

    @_guard
    def _f_enc(self):
        src, _ = QFileDialog.getOpenFileName(self, "Pilih file")
        if not src:
            return
        crypto.file_encrypt(bytes(self.k.file), src, src + ".svenc", self._prog)
        QMessageBox.information(self, "Selesai", f"Tersimpan: {src}.svenc")

    @_guard
    def _f_dec(self):
        src, _ = QFileDialog.getOpenFileName(self, "Pilih .svenc", filter="SecureVault (*.svenc)")
        if not src:
            return
        dst, _ = QFileDialog.getSaveFileName(self, "Simpan hasil", src[:-6] if src.endswith(".svenc") else src + ".dec")
        if not dst:
            return
        crypto.file_decrypt(bytes(self.k.file), src, dst, self._prog)
        QMessageBox.information(self, "Selesai", f"Tersimpan: {dst}")

    # ---------- Steganografi ----------
    def _stego_tab(self):
        w = QWidget(); lay = QVBoxLayout(w)
        self.s_msg = QTextEdit(placeholderText="Pesan rahasia yang akan disisipkan")
        b1, b2 = QPushButton("Sisipkan ke gambar"), QPushButton("Ekstrak dari gambar stego")
        b1.clicked.connect(self._s_embed); b2.clicked.connect(self._s_extract)
        self.s_out = QTextEdit(readOnly=True)
        lay.addWidget(self.s_msg); lay.addWidget(b1); lay.addWidget(b2)
        lay.addWidget(QLabel("Hasil")); lay.addWidget(self.s_out)
        return w

    @_guard
    def _s_embed(self):
        msg = self.s_msg.toPlainText()
        if not msg:
            raise ValueError("Pesan kosong")
        cover, _ = QFileDialog.getOpenFileName(self, "Gambar cover", filter="Gambar (*.png *.jpg *.jpeg *.bmp)")
        if not cover:
            return
        out, _ = QFileDialog.getSaveFileName(self, "Simpan stego PNG", "stego.png", "PNG (*.png)")
        if not out:
            return
        stego.embed(cover, out, bytes(self.k.stego), msg.encode("utf-8"))
        self.s_out.setPlainText(f"Berhasil. Kapasitas cover ~{stego.capacity_bytes(cover)} byte.\n"
                                "Simpan sebagai PNG; jangan dikompres JPEG.")

    @_guard
    def _s_extract(self):
        p, _ = QFileDialog.getOpenFileName(self, "Gambar stego", filter="PNG (*.png)")
        if not p:
            return
        self.s_out.setPlainText(stego.extract(p, bytes(self.k.stego)).decode("utf-8", errors="replace"))

    # ---------- Aset (blockchain) ----------
    def _assets_tab(self):
        w = QWidget(); lay = QVBoxLayout(w)
        form = QFormLayout()
        self.a_name, self.a_id, self.a_owner = QLineEdit(), QLineEdit(), QLineEdit()
        form.addRow("Nama aset", self.a_name); form.addRow("ID aset", self.a_id); form.addRow("Pemilik", self.a_owner)
        add, ver = QPushButton("Tambah blok"), QPushButton("Verifikasi chain")
        add.clicked.connect(self._a_add); ver.clicked.connect(self._a_verify)
        self.a_tbl = QTableWidget(0, 5)
        self.a_tbl.setHorizontalHeaderLabels(["Index", "Timestamp", "Data", "Prev hash", "Hash"])
        self.a_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        lay.addLayout(form)
        for x in (add, ver, self.a_tbl):
            lay.addWidget(x)
        self._a_refresh()
        return w

    def _a_refresh(self):
        bl = self.db.blocks()
        self.a_tbl.setRowCount(len(bl))
        for r, b in enumerate(bl):
            for c, v in enumerate([b["index"], b["timestamp"], json.dumps(b["data"], ensure_ascii=False),
                                   b["prev_hash"][:16] + "...", b["hash"][:16] + "..."]):
                self.a_tbl.setItem(r, c, QTableWidgetItem(str(v)))

    @_guard
    def _a_add(self):
        name, aid, owner = self.a_name.text().strip(), self.a_id.text().strip(), self.a_owner.text().strip()
        if not (name and aid and owner):
            raise ValueError("Nama aset, ID aset, dan pemilik wajib diisi")
        self.db.add_block({"asset_id": aid, "name": name, "owner": owner})
        for x in (self.a_name, self.a_id, self.a_owner):
            x.clear()
        self._a_refresh()

    def _a_verify(self):
        ok, msg = self.db.verify_chain()
        (QMessageBox.information if ok else QMessageBox.critical)(self, "Verifikasi chain", msg)

    # ---------- Database ----------
    def _db_tab(self):
        tabs = QTabWidget()
        tabs.addTab(self._db_create_panel(), "Buat Pesan")
        tabs.addTab(self._db_manage_panel(), "Kelola Pesan")
        self._refresh_db()
        return tabs

    def _db_create_panel(self):
        w = QWidget(); lay = QVBoxLayout(w)
        self.d_new = QTextEdit(placeholderText="Isi pesan")
        b = QPushButton("Simpan (dienkripsi AES-256-GCM)")
        b.clicked.connect(self._d_create)
        lay.addWidget(QLabel("Pesan")); lay.addWidget(self.d_new); lay.addWidget(b)
        return w

    def _db_manage_panel(self):
        w = QWidget(); lay = QVBoxLayout(w)
        self.d_tbl = QTableWidget(0, 3)
        self.d_tbl.setHorizontalHeaderLabels(["ID", "Jenis", "Dibuat"])
        self.d_tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.d_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.d_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.d_view = QTextEdit(readOnly=True)
        b1, b2, b3 = QPushButton("Tampilkan"), QPushButton("Dekripsi"), QPushButton("Hapus")
        b1.clicked.connect(self._d_show)
        b2.clicked.connect(self._d_decrypt)
        b3.clicked.connect(self._d_delete)
        row = QHBoxLayout(); row.addWidget(b1); row.addWidget(b2); row.addWidget(b3)
        lay.addWidget(self.d_tbl); lay.addLayout(row); lay.addWidget(self.d_view)
        return w

    def _refresh_db(self):
        rows = self.db.list_messages()
        self.d_tbl.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, v in enumerate(row):
                self.d_tbl.setItem(r, c, QTableWidgetItem(str(v)))

    def _sel_id(self):
        r = self.d_tbl.currentRow()
        if r < 0:
            raise ValueError("Pilih pesan di tabel dulu")
        return int(self.d_tbl.item(r, 0).text())

    @_guard
    def _d_create(self):
        msg = self.d_new.toPlainText()
        if not msg.strip():
            raise ValueError("Pesan kosong")
        mid = self.db.add_message("text", "pesan", msg.encode("utf-8"))
        self.d_new.clear()
        self._refresh_db()
        QMessageBox.information(self, "Tersimpan", f"Pesan tersimpan terenkripsi (ID {mid})")

    @_guard
    def _d_show(self):
        """Tampilkan data mentah tersimpan di database (ciphertext)."""
        import base64
        kind, nonce, ct, tag, created = self.db.get_raw(self._sel_id())
        self.d_view.setPlainText(
            f"Jenis     : {kind}\nDibuat    : {created}\n"
            f"Nonce     : {nonce.hex()}\nTag       : {tag.hex()}\n"
            f"Ciphertext (base64):\n{base64.b64encode(ct).decode()}")

    @_guard
    def _d_decrypt(self):
        _, _, data = self.db.get_message(self._sel_id())
        self.d_view.setPlainText(data.decode("utf-8", errors="replace"))
    
    @_guard
    def _d_delete(self):
        mid = self._sel_id()
        ok = QMessageBox.question(
            self, "Hapus pesan",
            f"Hapus pesan ID {mid} secara permanen? Tidak bisa dikembalikan.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if ok != QMessageBox.StandardButton.Yes:
            return
        self.db.delete_message(mid)
        self.d_view.clear()
        self._refresh_db()
