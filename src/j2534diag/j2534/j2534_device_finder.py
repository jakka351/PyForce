# j2534_device_finder.py
# Windows-only. Requires Python on Windows.

from __future__ import annotations
from dataclasses import dataclass
from typing import List
import sys

try:
    import winreg  # stdlib on Windows
except Exception:  # not Windows or missing module
    winreg = None


PASSTHRU_REGISTRY_PATH = r"Software\PassThruSupport.04.04"
PASSTHRU_REGISTRY_PATH_6432 = r"Software\Wow6432Node\PassThruSupport.04.04"


@dataclass
class J2534Device:
    Vendor: str = ""
    Name: str = ""
    FunctionLibrary: str = ""
    ConfigApplication: str = ""
    CAN: int = 0
    ISO14230: int = 0
    ISO15765: int = 0
    ISO9141: int = 0
    J1850PWM: int = 0
    J1850VPW: int = 0
    SCI_A_ENGINE: int = 0
    SCI_A_TRANS: int = 0
    SCI_B_ENGINE: int = 0
    SCI_B_TRANS: int = 0

    def __str__(self) -> str:
        return f"{self.Name} ({self.Vendor}) -> {self.FunctionLibrary}"


def _get_value(key, name: str, default):
    try:
        val, _ = winreg.QueryValueEx(key, name)
        return val
    except FileNotFoundError:
        return default


def _read_devices_from_path(hklm_path: str, wow64_flag: int) -> List[J2534Device]:
    devices: List[J2534Device] = []
    access = winreg.KEY_READ | winreg.KEY_ENUMERATE_SUB_KEYS | wow64_flag
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hklm_path, 0, access) as root:
            sub_count, _, _ = winreg.QueryInfoKey(root)
            for i in range(sub_count):
                try:
                    subname = winreg.EnumKey(root, i)
                except OSError:
                    continue
                try:
                    with winreg.OpenKey(root, subname, 0, access) as devkey:
                        dev = J2534Device()
                        dev.Vendor = _get_value(devkey, "Vendor", "")
                        dev.Name = _get_value(devkey, "Name", "")
                        dev.ConfigApplication = _get_value(devkey, "ConfigApplication", "")
                        dev.FunctionLibrary = _get_value(devkey, "FunctionLibrary", "")
                        dev.CAN = int(_get_value(devkey, "CAN", 0))
                        dev.ISO14230 = int(_get_value(devkey, "ISO14230", 0))
                        dev.ISO15765 = int(_get_value(devkey, "ISO15765", 0))
                        dev.ISO9141 = int(_get_value(devkey, "ISO9141", 0))
                        dev.J1850PWM = int(_get_value(devkey, "J1850PWM", 0))
                        dev.J1850VPW = int(_get_value(devkey, "J1850VPW", 0))
                        dev.SCI_A_ENGINE = int(_get_value(devkey, "SCI_A_ENGINE", 0))
                        dev.SCI_A_TRANS = int(_get_value(devkey, "SCI_A_TRANS", 0))
                        dev.SCI_B_ENGINE = int(_get_value(devkey, "SCI_B_ENGINE", 0))
                        dev.SCI_B_TRANS = int(_get_value(devkey, "SCI_B_TRANS", 0))
                        devices.append(dev)
                except OSError:
                    # busted subkey — skip it
                    continue
    except FileNotFoundError:
        pass
    return devices


def find_installed_j2534_dlls() -> List[J2534Device]:
    """
    Enumerate J2534 devices from HKLM\\Software\\PassThruSupport.04.04
    and the Wow6432Node mirror. Returns a list of J2534Device.
    """
    if winreg is None:
        # Non-Windows: return empty list instead of blowing up.
        return []

    # Try both registry views to be thorough.
    results: List[J2534Device] = []
    KEY32 = getattr(winreg, "KEY_WOW64_32KEY", 0)
    KEY64 = getattr(winreg, "KEY_WOW64_64KEY", 0)

    # Native view (whatever Python is), plus explicit 64/32 views where possible.
    results += _read_devices_from_path(PASSTHRU_REGISTRY_PATH, 0)
    results += _read_devices_from_path(PASSTHRU_REGISTRY_PATH, KEY64)
    results += _read_devices_from_path(PASSTHRU_REGISTRY_PATH, KEY32)
    # Explicit 32-bit node used by lots of vendors:
    results += _read_devices_from_path(PASSTHRU_REGISTRY_PATH_6432, 0)
    results += _read_devices_from_path(PASSTHRU_REGISTRY_PATH_6432, KEY64)
    results += _read_devices_from_path(PASSTHRU_REGISTRY_PATH_6432, KEY32)

    # Deduplicate by FunctionLibrary path + Name (common sense unique key).
    uniq = {}
    for d in results:
        key = (d.FunctionLibrary.lower(), d.Name.lower())
        if key not in uniq:
            uniq[key] = d
    return list(uniq.values())


# quick CLI smoke test
if __name__ == "__main__":
    devs = find_installed_j2534_dlls()
    print(f"Found {len(devs)} device(s).")
    for d in devs:
        print(" -", d)
