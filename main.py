import sys
from PyQt6.QtWidgets import QApplication, QMessageBox
from core import usb
from core.crypto import Keyring, CryptoError
from core.vault import VaultStore
from core.db import VaultDB
from gui.dialogs import SetupDialog, LoginDialog, FaceDialog
from gui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    store = VaultStore()

    if not store.exists():
        dlg = SetupDialog()
        if not dlg.exec():
            return 0
        drive, pw, fb, face = dlg.values()
        if drive is None:
            QMessageBox.critical(None, "Setup", "Flashdisk tidak ditemukan"); return 1
        try:
            mk = store.setup(drive, pw, fb, face)
        except (CryptoError, OSError) as e:
            QMessageBox.critical(None, "Setup", str(e)); return 1
    else:
        drive = usb.find_vault_drive()
        if drive is None:
            QMessageBox.critical(None, "Login", "Flashdisk dengan .vault_key tidak ditemukan"); return 1
        dlg = LoginDialog()
        if not dlg.exec():
            return 0
        fallback = dlg.use_fb.isChecked()
        try:
            mk = store.unlock(drive, dlg.pw.text(), fallback)
        except CryptoError as e:
            QMessageBox.critical(None, "Login", str(e)); return 1
        if not fallback and store.has_face():
            fd = FaceDialog("verify", store.face_template(mk))
            if not fd.usable():
                QMessageBox.warning(None, "Wajah", fd.info.text() + "\nGunakan password cadangan."); return 1
            if not (fd.exec() and fd.ok):
                QMessageBox.critical(None, "Wajah", "Verifikasi wajah gagal"); return 1

    k = Keyring(mk)
    db = VaultDB(store.db_path, bytes(k.db), bytes(k.chain))
    win = MainWindow(k, db, drive)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
