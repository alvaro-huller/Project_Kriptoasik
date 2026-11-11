# SecureVault

## Jalankan (venv)
Windows:
    setup_venv.bat     # buat .venv, install dependency, unduh model
    run.bat
Linux/Mac:
    ./setup_venv.sh
    ./run.sh

Manual:
    python -m venv .venv
    .venv\Scripts\activate        (Windows)  |  source .venv/bin/activate  (Linux/Mac)
    pip install -r requirements.txt
    python download_models.py
    python main.py

Setup pertama: colok flashdisk, isi password + password cadangan, daftar wajah (opsional).
`.vault_key` dibuat di flashdisk. Cabut flashdisk saat jalan = kunci dihapus + app keluar.

## Struktur
- core/crypto.py  Argon2id, HKDF, Vigenere byte-level, AES-256-GCM, ChaCha20-Poly1305 chunked
- core/db.py      SQLite: nonce acak per baris + hash chain aset
- core/stego.py   Adaptive LSB (PNG)
- core/usb.py     Serial volume + .vault_key + dead man's switch
- core/face.py    YuNet/SFace, cosine 0.363, liveness gerak kepala
- core/vault.py   Master Key wrap, template wajah terenkripsi

## Catatan keamanan
- Wajah = gate aplikasi, bukan bahan kunci. Penyerang dengan password + USB + akses file bisa bypass via password cadangan / modifikasi app.
- Liveness gerak kepala melawan foto statis, bukan video replay / deepfake.
- Wipe memori Python best-effort; GC bisa menyisakan salinan.
- Vigenere hanya lapisan akademis; keamanan nyata dari AES-256-GCM.
- Stego LSB rusak jika PNG dikompres ulang / diubah ukuran.
- Serial volume bisa dikloning; keamanan USB bertumpu pada .vault_key + password.
