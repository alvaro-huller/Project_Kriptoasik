"""Identitas fisik flashdisk: Volume Serial Number + file .vault_key tersembunyi."""
import os
import sys
import subprocess
from dataclasses import dataclass

KEYFILE = ".vault_key"


@dataclass
class Drive:
    mount: str      # "E:\\" atau "/media/user/USB"
    serial: str
    label: str = ""

    def __str__(self):
        return f"{self.mount} [{self.label or 'USB'}] serial={self.serial}"


def _win_serial(root: str) -> str:
    import ctypes
    from ctypes import wintypes
    serial = wintypes.DWORD(0)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root), None, 0, ctypes.byref(serial), None, None, None, 0)
    if not ok:
        raise OSError("GetVolumeInformationW gagal")
    return f"{serial.value:08X}"


def _win_drives():
    import ctypes
    import string
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for i, letter in enumerate(string.ascii_uppercase):
        if mask & (1 << i):
            root = f"{letter}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 2:  # DRIVE_REMOVABLE
                try:
                    yield Drive(root, _win_serial(root), letter)
                except OSError:
                    pass


def _posix_serial(device: str, mount: str) -> str:
    try:
        if sys.platform == "darwin":
            out = subprocess.check_output(["diskutil", "info", mount], text=True)
            for line in out.splitlines():
                if "Volume UUID" in line:
                    return line.split(":", 1)[1].strip()
        else:
            out = subprocess.check_output(["lsblk", "-no", "UUID", device], text=True).strip()
            if out:
                return out.splitlines()[0]
    except Exception:
        pass
    return ""


def _posix_drives():
    import psutil
    for p in psutil.disk_partitions(all=False):
        removable = ("removable" in p.opts) or p.mountpoint.startswith(("/media/", "/run/media/", "/Volumes/"))
        if removable and not p.mountpoint.startswith("/Volumes/Macintosh"):
            s = _posix_serial(p.device, p.mountpoint)
            if s:
                yield Drive(p.mountpoint, s, os.path.basename(p.mountpoint))


def list_drives():
    return list(_win_drives() if sys.platform == "win32" else _posix_drives())


def read_keyfile(drive: Drive) -> bytes | None:
    p = os.path.join(drive.mount, KEYFILE)
    if not os.path.isfile(p):
        return None
    with open(p, "rb") as f:
        return f.read()


def write_keyfile(drive: Drive) -> bytes:
    p = os.path.join(drive.mount, KEYFILE)
    data = os.urandom(32)
    if os.path.exists(p):
        raise FileExistsError(".vault_key sudah ada di USB ini")
    with open(p, "wb") as f:
        f.write(data)
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(p, 0x02 | 0x04)  # HIDDEN | SYSTEM
    return data


def find_vault_drive():
    """Cari drive yang berisi .vault_key."""
    for d in list_drives():
        if read_keyfile(d) is not None:
            return d
    return None


def still_present(drive: Drive) -> bool:
    """Untuk Dead Man's Switch: drive masih terpasang dengan serial yang sama?"""
    try:
        if sys.platform == "win32":
            return _win_serial(drive.mount) == drive.serial and os.path.isfile(os.path.join(drive.mount, KEYFILE))
        return os.path.isfile(os.path.join(drive.mount, KEYFILE)) and any(
            d.mount == drive.mount and d.serial == drive.serial for d in list_drives())
    except Exception:
        return False
