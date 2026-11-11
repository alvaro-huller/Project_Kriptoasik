import time
import cv2
import numpy as np
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QImage, QPixmap
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QLabel, QPushButton, QLineEdit, QComboBox,
                             QFormLayout, QDialogButtonBox, QMessageBox, QHBoxLayout)
from core import usb
from core.face import FaceEngine, Verifier, average_template


class FaceDialog(QDialog):
    """mode='enroll': ambil 6 sampel -> template. mode='verify': cocokkan + liveness (toleh kiri-kanan)."""

    def __init__(self, mode: str, template=None, parent=None, timeout=25):
        super().__init__(parent)
        self.mode, self.template, self.result_template, self.ok = mode, template, None, False
        self.setWindowTitle("Pendaftaran Wajah" if mode == "enroll" else "Verifikasi Wajah")
        self.view = QLabel(alignment=Qt.AlignmentFlag.AlignCenter)
        self.view.setMinimumSize(480, 360)
        self.info = QLabel("Memulai kamera...")
        cancel = QPushButton("Batal / pakai password cadangan")
        cancel.clicked.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(self.view); lay.addWidget(self.info); lay.addWidget(cancel)
        try:
            self.engine = FaceEngine()
        except Exception as e:
            self.engine = None
            self.info.setText(str(e))
            return
        self.cap = cv2.VideoCapture(0)
        if not self.cap.isOpened():
            self.engine = None
            self.info.setText("Kamera tidak tersedia")
            return
        self.verifier = Verifier(self.engine, template) if mode == "verify" else None
        self.samples, self.last_sample, self.deadline = [], 0.0, time.time() + timeout
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(30)

    def usable(self) -> bool:
        return self.engine is not None

    def _tick(self):
        ok, frame = self.cap.read()
        if not ok:
            return
        face = None
        if self.mode == "enroll":
            face = self.engine.detect(frame)
            now = time.time()
            if face is not None and face[14] > 0.9 and now - self.last_sample > 0.6:
                self.samples.append(self.engine.embed(frame, face)); self.last_sample = now
            self.info.setText(f"Hadap kamera, gerakkan kepala sedikit. Sampel {len(self.samples)}/6")
            if len(self.samples) >= 6:
                self.result_template = average_template(self.samples)
                self._finish(True)
        else:
            face, passed = self.verifier.feed(frame)
            v = self.verifier
            self.info.setText(f"Toleh kepala kiri-kanan perlahan | cocok {v.matched} | sim {v.last_sim:.2f} | "
                              f"liveness {'OK' if v.live() else '...'}")
            if passed:
                self._finish(True)
            elif time.time() > self.deadline:
                self.info.setText("Waktu habis"); self._finish(False)
        if face is not None:
            x, y, w, h = map(int, face[:4])
            cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 200, 0), 2)
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        hh, ww, _ = rgb.shape
        self.view.setPixmap(QPixmap.fromImage(QImage(rgb.data, ww, hh, ww * 3, QImage.Format.Format_RGB888).copy()))

    def _finish(self, ok):
        self.timer.stop(); self.cap.release(); self.ok = ok
        self.accept() if ok else self.reject()

    def reject(self):
        if getattr(self, "timer", None):
            self.timer.stop(); self.cap.release()
        super().reject()


class SetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SecureVault - Setup Awal")
        self.drives = usb.list_drives()
        self.combo = QComboBox()
        for d in self.drives:
            self.combo.addItem(str(d))
        self.pw = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        self.fb = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        self.face_template = None
        self.face_btn = QPushButton("Daftarkan wajah (opsional)")
        self.face_btn.clicked.connect(self._enroll)
        f = QFormLayout(self)
        f.addRow("Flashdisk", self.combo)
        f.addRow("Master password", self.pw)
        f.addRow("Password cadangan (tanpa wajah)", self.fb)
        f.addRow(self.face_btn)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept); bb.rejected.connect(self.reject)
        f.addRow(bb)

    def _enroll(self):
        dlg = FaceDialog("enroll", parent=self)
        if not dlg.usable():
            QMessageBox.warning(self, "Wajah", dlg.info.text()); return
        if dlg.exec() and dlg.result_template is not None:
            self.face_template = dlg.result_template
            self.face_btn.setText("Wajah terdaftar ✓")

    def values(self):
        d = self.drives[self.combo.currentIndex()] if self.drives else None
        return d, self.pw.text(), self.fb.text(), self.face_template


class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SecureVault - Login")
        self.pw = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        self.use_fb = QPushButton("Gunakan password cadangan")
        self.use_fb.setCheckable(True)
        f = QFormLayout(self)
        f.addRow("Password", self.pw)
        f.addRow(self.use_fb)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept); bb.rejected.connect(self.reject)
        f.addRow(bb)
