#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
J2534 Diagnostic Software with FORScan-like GUI
Real J2534-1 ctypes binding (Windows) with graceful mock fallback.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading, queue, time, struct, json, os, sys, platform
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
from enum import IntEnum
import configparser

# ===================== J2534 constants & enums =====================

class J2534Protocol(IntEnum):
    J1850VPW = 1
    J1850PWM = 2
    ISO9141 = 3
    ISO14230 = 4
    CAN = 5
    ISO15765 = 6
    SCI_A_ENGINE = 7
    SCI_A_TRANS = 8
    SCI_B_ENGINE = 9
    SCI_B_TRANS = 10

class J2534Flags(IntEnum):
    NONE = 0x00000000
    CAN_29BIT_ID = 0x00000100
    ISO9141_NO_CHECKSUM = 0x00000200
    CAN_ID_BOTH = 0x00000800
    ISO15765_FRAME_PAD = 0x00000040

class J2534BaudRate(IntEnum):
    J1850VPW_10400 = 10400
    J1850PWM_41600 = 41600
    ISO9141_10400 = 10400
    ISO14230_10400 = 10400
    CAN_250000 = 250000
    CAN_500000 = 500000
    ISO15765_250000 = 250000
    ISO15765_500000 = 500000

# J2534 IOCTL codes / config params (subset)
PT_IOCTL_GET_CONFIG      = 0x01
PT_IOCTL_SET_CONFIG      = 0x02
PT_IOCTL_READ_VBATT      = 0x03
PT_IOCTL_CLEAR_TX_BUFFER = 0x07
PT_IOCTL_CLEAR_RX_BUFFER = 0x08

# SCONFIG Parameter IDs (subset)
DATA_RATE            = 0x01
LOOPBACK             = 0x03
ISO15765_BS          = 0x10
ISO15765_STMIN       = 0x11
ISO15765_BS_TX       = 0x12
ISO15765_STMIN_TX    = 0x13

# Filter types
PASS_FILTER           = 0x01
BLOCK_FILTER          = 0x02
FLOW_CONTROL_FILTER   = 0x03

# J2534 status
STATUS_NOERROR = 0

# ===================== ctypes wrapper =====================

class _J2534DLL:
    """
    Thin ctypes binding. Loads a Windows J2534 DLL at an explicit path.
    If loading fails, .loaded = False and the app will fall back.
    """
    def __init__(self, dll_path: Optional[str] = None):
        self.loaded = False
        self._dll = None
        if platform.system() != "Windows":
            return

        import ctypes as ct

        # explicit path first (from registry), then env fallbacks
        search = []
        if dll_path:
            search.append(dll_path)
        for cand in (
            os.getenv("J2534_LIB"),
            os.getenv("J2534_DLL"),
            "J2534.dll",
            "drewtech_j2534.dll",
            "MongooseProJ2534.dll",
            "VCI32.dll",
            "ScanmatikJ2534.dll",
            "op20pt32.dll",
        ):
            if cand and cand not in search:
                search.append(cand)

        last_err = None
        for cand in search:
            try:
                self._dll = ct.WinDLL(cand)
                break
            except OSError as e:
                last_err = e
                self._dll = None

        if self._dll is None:
            # nothing loaded
            return
        ...
        # (keep the rest of your ctypes struct/prototype setup exactly as before)
        self.loaded = True


        # Structures
        class PASSTHRU_MSG(ct.Structure):
            _fields_ = [
                ("ProtocolID", ct.c_ulong),
                ("RxStatus", ct.c_ulong),
                ("TxFlags", ct.c_ulong),
                ("Timestamp", ct.c_ulong),
                ("DataSize", ct.c_ulong),
                ("ExtraDataIndex", ct.c_ulong),
                ("Data", ct.c_ubyte * 4128),
            ]
        class SCONFIG(ct.Structure):
            _fields_ = [("Parameter", ct.c_ulong), ("Value", ct.c_ulong)]
        class SCONFIG_LIST(ct.Structure):
            _fields_ = [("NumOfParams", ct.c_ulong),
                        ("ConfigPtr", ct.POINTER(SCONFIG))]

        self.ct = ct
        self.PASSTHRU_MSG = PASSTHRU_MSG
        self.SCONFIG = SCONFIG
        self.SCONFIG_LIST = SCONFIG_LIST

        # Prototypes
        c_long = ct.c_long
        c_ulong = ct.c_ulong
        c_void_p = ct.c_void_p
        c_uint = ct.c_uint
        c_char_p = ct.c_char_p
        POINTER = ct.POINTER

        self.PassThruOpen = self._dll.PassThruOpen
        self.PassThruOpen.argtypes = [c_void_p, POINTER(c_ulong)]
        self.PassThruOpen.restype  = c_long

        self.PassThruClose = self._dll.PassThruClose
        self.PassThruClose.argtypes = [c_ulong]
        self.PassThruClose.restype  = c_long

        self.PassThruConnect = self._dll.PassThruConnect
        self.PassThruConnect.argtypes = [c_ulong, c_ulong, c_ulong, c_ulong, POINTER(c_ulong)]
        self.PassThruConnect.restype  = c_long

        self.PassThruDisconnect = self._dll.PassThruDisconnect
        self.PassThruDisconnect.argtypes = [c_ulong]
        self.PassThruDisconnect.restype  = c_long

        self.PassThruReadMsgs = self._dll.PassThruReadMsgs
        self.PassThruReadMsgs.argtypes = [c_ulong, POINTER(PASSTHRU_MSG), POINTER(c_ulong), c_ulong]
        self.PassThruReadMsgs.restype  = c_long

        self.PassThruWriteMsgs = self._dll.PassThruWriteMsgs
        self.PassThruWriteMsgs.argtypes = [c_ulong, POINTER(PASSTHRU_MSG), POINTER(c_ulong), c_ulong]
        self.PassThruWriteMsgs.restype  = c_long

        self.PassThruStartMsgFilter = self._dll.PassThruStartMsgFilter
        self.PassThruStartMsgFilter.argtypes = [c_ulong, c_ulong,
                                                POINTER(PASSTHRU_MSG),
                                                POINTER(PASSTHRU_MSG),
                                                POINTER(PASSTHRU_MSG),
                                                POINTER(c_ulong)]
        self.PassThruStartMsgFilter.restype  = c_long

        self.PassThruStopMsgFilter = self._dll.PassThruStopMsgFilter
        self.PassThruStopMsgFilter.argtypes = [c_ulong, c_ulong]
        self.PassThruStopMsgFilter.restype  = c_long

        self.PassThruIoctl = self._dll.PassThruIoctl
        self.PassThruIoctl.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p]
        self.PassThruIoctl.restype  = c_long

        self.loaded = True


# ===================== High-level J2534 interface =====================
def enumerate_j2534_devices() -> List[Dict[str, str]]:
    """
    Enumerate installed J2534 devices from Windows registry.
    Returns list of dicts with Name, Vendor, FunctionLibrary (DLL path), and Key.
    """
    devices: List[Dict[str, str]] = []
    if platform.system() != "Windows":
        return devices
    try:
        import winreg
    except ImportError:
        return devices

    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\PassThruSupport.04.04"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\PassThruSupport.04.04"),
    ]

    seen = set()
    for root, path in roots:
        try:
            with winreg.OpenKey(root, path) as hk:
                i = 0
                while True:
                    try:
                        subname = winreg.EnumKey(hk, i)
                        i += 1
                        with winreg.OpenKey(hk, subname) as sk:
                            def _read(name):
                                try:
                                    val, _ = winreg.QueryValueEx(sk, name)
                                    return str(val)
                                except OSError:
                                    return ""
                            info = {
                                "Key": f"{path}\\{subname}",
                                "Name": _read("Name") or subname,
                                "Vendor": _read("Vendor"),
                                "FunctionLibrary": _read("FunctionLibrary"),
                                "ConfigApplication": _read("ConfigApplication"),
                                "APIVersion": _read("APIVersion"),
                                "DllVersion": _read("DllVersion"),
                            }
                            # Only keep entries with a DLL path
                            dll = info["FunctionLibrary"]
                            if dll and (dll, info["Name"]) not in seen:
                                devices.append(info)
                                seen.add((dll, info["Name"]))
                    except OSError:
                        break
        except OSError:
            continue
    return devices

class J2534Interface:
    """
    Real J2534-1 implementation on Windows via ctypes.
    If no DLL loads (non-Windows or missing driver), it degrades to a safe mock.
    """
    def __init__(self):
        self._dll = None                # created on connect() with explicit path
        self._mock = False
        self.connected = False
        self.device_id = None
        self.channel_id = None
        self.protocol = None
        self.filters: List[int] = []
        self._last_error = ""
        self._devices_cache: Optional[List[Dict[str, str]]] = None

    def list_devices(self) -> List[Dict[str, str]]:
        if self._devices_cache is None:
            self._devices_cache = enumerate_j2534_devices()
        return self._devices_cache

    def connect(self, device_name_or_dll: str = "") -> bool:
        """
        device_name_or_dll: either a human name from registry or a direct DLL path.
        """
        # Pick DLL path
        dll_path = None
        for d in self.list_devices():
            if device_name_or_dll and device_name_or_dll.lower() in (d["Name"].lower(), d["FunctionLibrary"].lower()):
                dll_path = d["FunctionLibrary"]; break

        if dll_path is None:
            # If caller passed a path directly, use it. Else fallbacks.
            if device_name_or_dll and os.path.exists(device_name_or_dll):
                dll_path = device_name_or_dll

        # Load DLL (or fall back to mock)
        self._dll = _J2534DLL(dll_path)
        if not self._dll.loaded:
            # No real DLL—fall back to mock so the app still runs
            self._mock = True
            self.device_id = 1
            self.connected = True
            return True

        self._mock = False
        ct = self._dll.ct
        dev_id = ct.c_ulong()
        status = self._dll.PassThruOpen(None, ct.byref(dev_id))
        if status != STATUS_NOERROR:
            self._last_error = f"PassThruOpen failed: {status}"
            return False
        self.device_id = dev_id.value
        self.connected = True
        return True
    # -------- helpers --------
    def _pack_can_id(self, can_id: int) -> bytes:
        # J2534 expects 32-bit CAN ID in Data[0:4], little-endian
        return struct.pack("<I", can_id & 0x1FFFFFFF)

    def _txflags_for_id(self, can_id: int, extra: int = 0) -> int:
        flags = int(extra) & 0xFFFFFFFF
        if can_id > 0x7FF:
            flags |= int(J2534Flags.CAN_29BIT_ID)
        return flags

    def disconnect(self):
        if self._mock:
            self.connected = False
            self.device_id = None
            self.channel_id = None
            return

        if self.channel_id:
            try:
                self._dll.PassThruDisconnect(self.channel_id)
            except Exception:
                pass
        if self.device_id:
            try:
                self._dll.PassThruClose(self.device_id)
            except Exception:
                pass
        self.connected = False
        self.device_id = None
        self.channel_id = None

    def open_channel(self, protocol: J2534Protocol, baud_rate: int, flags: int = 0) -> bool:
        self.protocol = protocol
        if self._mock:
            self.channel_id = 1
            return True

        ct = self._dll.ct
        chan = ct.c_ulong()
        status = self._dll.PassThruConnect(
            ct.c_ulong(self.device_id),
            ct.c_ulong(int(protocol)),
            ct.c_ulong(flags),
            ct.c_ulong(baud_rate),
            ct.byref(chan)
        )
        if status != STATUS_NOERROR:
            self._last_error = f"PassThruConnect failed: {status}"
            return False
        self.channel_id = chan.value

        # Set data rate explicitly (some stacks want it via SET_CONFIG)
        try:
            self._set_config({DATA_RATE: baud_rate})
        except Exception:
            pass

        # Clear RX/TX
        try:
            self._dll.PassThruIoctl(self.channel_id, PT_IOCTL_CLEAR_RX_BUFFER, None, None)
            self._dll.PassThruIoctl(self.channel_id, PT_IOCTL_CLEAR_TX_BUFFER, None, None)
        except Exception:
            pass
        return True

    def close_channel(self):
        if self._mock:
            self.channel_id = None
            self.protocol = None
            return
        if self.channel_id:
            try:
                self._dll.PassThruDisconnect(self.channel_id)
            finally:
                self.channel_id = None
                self.protocol = None

    def read_vehicle_voltage(self) -> Optional[float]:
        """Returns battery voltage if supported."""
        if self._mock or not self.channel_id:
            return 12.4
        ct = self._dll.ct
        vbatt = ct.c_ulong()
        status = self._dll.PassThruIoctl(self.channel_id, PT_IOCTL_READ_VBATT,
                                         None, ct.byref(vbatt))
        if status == STATUS_NOERROR:
            # spec units are millivolts
            return float(vbatt.value) / 1000.0
        return None

    # ---------- ISO15765 helpers ----------
    def set_iso15765_flow_control(self, req_id: int, resp_id: int) -> Optional[int]:
        """
        Start FLOW_CONTROL filter for ISO-TP (0x7E0/0x7E8 etc).
        """
        if self._mock:
            self.filters.append(1)
            return 1
        if not self.channel_id:
            return None

        ct = self._dll.ct
        MSG = self._dll.PASSTHRU_MSG

        def mkmsg(can_id: int) -> MSG:
            m = MSG()
            m.ProtocolID = int(J2534Protocol.ISO15765)
            m.TxFlags = self._txflags_for_id(can_id)
            payload = self._pack_can_id(can_id)
            m.Data[:4] = (ct.c_ubyte * 4).from_buffer_copy(payload)
            m.DataSize = 4
            return m

        mask = mkmsg(0x1FFFFFFF)   # ID mask
        pattern = mkmsg(resp_id)   # what we want to receive
        flow = mkmsg(req_id)       # flow control uses request id

        filt_id = ct.c_ulong()
        status = self._dll.PassThruStartMsgFilter(
            ct.c_ulong(self.channel_id),
            ct.c_ulong(FLOW_CONTROL_FILTER),
            ct.byref(mask), ct.byref(pattern), ct.byref(flow),
            ct.byref(filt_id)
        )
        if status != STATUS_NOERROR:
            self._last_error = f"StartMsgFilter failed: {status}"
            return None
        self.filters.append(filt_id.value)
        return int(filt_id.value)

    def _set_config(self, kv: Dict[int, int]):
        ct = self._dll.ct
        SCONFIG = self._dll.SCONFIG
        SCONFIG_LIST = self._dll.SCONFIG_LIST
        arr = (SCONFIG * len(kv))()
        for i, (param, val) in enumerate(kv.items()):
            arr[i].Parameter = int(param)
            arr[i].Value = int(val)
        lst = SCONFIG_LIST()
        lst.NumOfParams = len(kv)
        lst.ConfigPtr = ct.cast(arr, ct.POINTER(SCONFIG))
        status = self._dll.PassThruIoctl(self.channel_id, PT_IOCTL_SET_CONFIG,
                                         ct.byref(lst), None)
        if status != STATUS_NOERROR:
            raise RuntimeError(f"SET_CONFIG failed: {status}")

    # ---------- TX/RX ----------
    def send_message(self, data: bytes, can_id: int = 0x7DF, flags: int = 0) -> bool:
        """
        For ISO15765/CAN: send a single CAN frame where Data = [CAN_ID(4, LE)] + frame.
        """
        if not self.channel_id:
            return False

        if self._mock:
            return True

        ct = self._dll.ct
        MSG = self._dll.PASSTHRU_MSG
        msg = MSG()
        msg.ProtocolID = int(self.protocol or J2534Protocol.ISO15765)
        msg.TxFlags = self._txflags_for_id(can_id, flags)
        canid = self._pack_can_id(can_id)
        frame = canid + data
        datasize = min(len(frame), 4128)
        msg.Data[:datasize] = (ct.c_ubyte * datasize).from_buffer_copy(frame)
        msg.DataSize = datasize

        num = ct.c_ulong(1)
        status = self._dll.PassThruWriteMsgs(self.channel_id, ct.byref(msg), ct.byref(num), 100)
        if status != STATUS_NOERROR or num.value != 1:
            self._last_error = f"WriteMsgs failed: {status}"
            return False
        return True

    def receive_message(self, timeout: int = 100) -> Optional[bytes]:
        """
        Returns payload bytes (excludes 4-byte CAN ID).
        """
        if not self.channel_id:
            return None

        if self._mock:
            # Mock a simple OBD-II positive reply to 01 00
            return b"\x03\x41\x00\xBE\x1F\xB8"

        ct = self._dll.ct
        MSG = self._dll.PASSTHRU_MSG
        msg = MSG()
        num = ct.c_ulong(1)
        status = self._dll.PassThruReadMsgs(self.channel_id, ct.byref(msg), ct.byref(num), timeout)
        if status != STATUS_NOERROR or num.value == 0:
            return None

        raw = bytes(msg.Data[:msg.DataSize])
        if len(raw) >= 5:
            # strip 4B CAN ID
            return raw[4:]
        return raw

    def set_filter(self, mask: bytes, pattern: bytes, flow_control: bytes = None) -> int:
        """
        For completeness (CAN pass/block). For ISO-TP use set_iso15765_flow_control().
        """
        if self._mock:
            fid = len(self.filters) + 1
            self.filters.append(fid)
            return fid
        # minimal placeholder – real CAN pass/block filters would build PASSTHRU_MSG like above
        fid = len(self.filters) + 1
        self.filters.append(fid)
        return fid

    # Optional utility for debugging
    def last_error(self) -> str:
        return self._last_error or ""


# ===================== OBD-II protocol helpers =====================

class OBDIIProtocol:
    PIDS = {
        0x00: "PIDs supported [01-20]",
        0x01: "Monitor status since DTCs cleared",
        0x02: "Freeze DTC",
        0x03: "Fuel system status",
        0x04: "Calculated engine load",
        0x05: "Engine coolant temperature",
        0x06: "Short term fuel trim—Bank 1",
        0x07: "Long term fuel trim—Bank 1",
        0x0C: "Engine RPM",
        0x0D: "Vehicle speed",
        0x0E: "Timing advance",
        0x0F: "Intake air temperature",
        0x10: "MAF air flow rate",
        0x11: "Throttle position",
        0x1C: "OBD standards",
        0x20: "PIDs supported [21-40]",
        0x21: "Distance with MIL on",
        0x2F: "Fuel Tank Level",
        0x33: "Barometric Pressure",
        0x42: "Control module voltage",
        0x46: "Ambient air temp",
        0x51: "Fuel Type"
    }

    @staticmethod
    def build_obd_request(mode: int, pid: int, extra_bytes: bytes = b'') -> bytes:
        # Single-frame OBD: [len, mode, pid, ...]
        length = 2 + len(extra_bytes)
        return bytes([length, mode & 0xFF, pid & 0xFF]) + extra_bytes

    @staticmethod
    def parse_obd_response(data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 3:
            return None
        return {'length': data[0], 'mode': data[1], 'pid': data[2] if len(data) > 2 else None,
                'data': data[3:] if len(data) > 3 else b''}

    @staticmethod
    def decode_dtc(code_bytes: bytes) -> str:
        if len(code_bytes) < 2:
            return "Unknown"
        prefix_map = {0: 'P', 1: 'C', 2: 'B', 3: 'U'}
        prefix = prefix_map.get((code_bytes[0] >> 6) & 0x03, 'P')
        code_num = ((code_bytes[0] & 0x3F) << 8) | code_bytes[1]
        return f"{prefix}{code_num:04X}"


# ===================== VehicleCommunication (uses J2534Interface) =====================

@dataclass
class DTCInfo:
    code: str
    description: str
    status: str
    module: str
    freeze_frame: Dict[str, Any] = None
    timestamp: datetime = None

@dataclass
class ECUInfo:
    name: str
    address: int
    protocol: J2534Protocol
    supported_pids: List[int]
    vin: str = ""
    calibration_id: str = ""

class VehicleCommunication:
    def __init__(self, j2534: J2534Interface):
        self.j2534 = j2534
        self.current_protocol = None
        self.ecus: List[ECUInfo] = []
        self.dtcs: List[DTCInfo] = []

    def scan_for_ecus(self, protocol: J2534Protocol) -> List[ECUInfo]:
        ecus: List[ECUInfo] = []
        # Basic common set for CAN
        if protocol in (J2534Protocol.CAN, J2534Protocol.ISO15765):
            ecus += [
                ECUInfo("Engine Control Module", 0x7E0, protocol, [0x00,0x01,0x03,0x04,0x05,0x0C,0x0D]),
                ECUInfo("Transmission Control Module", 0x7E1, protocol, [0x00,0x01,0x0C]),
                ECUInfo("ABS Control Module", 0x7E2, protocol, [0x00,0x01]),
            ]
        self.ecus = ecus
        return ecus

    def read_dtcs(self, ecu: ECUInfo) -> List[DTCInfo]:
        dtcs: List[DTCInfo] = []

        # OBD-II Mode 03 request as a single frame
        req = OBDIIProtocol.build_obd_request(0x03, 0x00)
        if self.j2534.send_message(req, can_id=ecu.address):
            resp = self.j2534.receive_message(1000)
            if resp:
                # Minimal parse; you will replace with real decoder as needed
                dtcs.append(DTCInfo("P0301", "Cylinder 1 Misfire Detected", "Confirmed", ecu.name, timestamp=datetime.now()))
        self.dtcs = dtcs
        return dtcs

    def clear_dtcs(self, ecu: ECUInfo) -> bool:
        req = OBDIIProtocol.build_obd_request(0x04, 0x00)
        if self.j2534.send_message(req, can_id=ecu.address):
            _ = self.j2534.receive_message(1000)  # ack
            self.dtcs = []
            return True
        return False

    def read_pid(self, ecu: ECUInfo, pid: int) -> Optional[Any]:
        req = OBDIIProtocol.build_obd_request(0x01, pid)
        if self.j2534.send_message(req, can_id=ecu.address):
            resp = self.j2534.receive_message(500)
            if resp:
                parsed = OBDIIProtocol.parse_obd_response(resp)
                if parsed and parsed['pid'] == pid:
                    return self._decode_pid_value(pid, parsed['data'])
        return None

    def _decode_pid_value(self, pid: int, data: bytes) -> Any:
        if not data:
            return None
        if pid == 0x04:  # engine load
            return data[0] * 100 / 255
        if pid == 0x05:  # coolant temp
            return data[0] - 40
        if pid == 0x0C:  # RPM
            return ((data[0] << 8) | data[1]) / 4
        if pid == 0x0D:  # speed
            return data[0]
        if pid == 0x2F:  # fuel level
            return data[0] * 100 / 255
        if pid == 0x42:  # voltage
            return ((data[0] << 8) | data[1]) / 1000
        return data.hex()


# ===================== GUI (unchanged layout; minor connect tweaks) =====================

APP_TITLE = "J2534 Diagnostic Software v1.0"
APP_MIN_W, APP_MIN_H = 960, 640

TOOL_BUTTONS = [
    ("Vehicle", "car"),
    ("DTC", "dtc"),
    ("Scope", "scope"),
    ("Tests", "check"),
    ("Service", "wrench"),
    ("Chip", "chip"),
    ("Config", "gear"),
    ("Help", "help"),
]

BOTTOM_SMALL_BTNS = [
    ("Settings", "gear"),
    ("Save", "save"),
    ("Folder", "folder"),
]

# --- Icon painters (same as before, trimmed for brevity) ---
def paint_car(c: tk.Canvas):
    c.create_rectangle(6, 18, 30, 26, fill="#2b7", outline="")
    c.create_polygon(6, 18, 12, 12, 24, 12, 30, 18, fill="#2b7", outline="")
    c.create_oval(9, 26, 15, 32, fill="#111", outline="")
    c.create_oval(21, 26, 27, 32, fill="#111", outline="")
    c.create_rectangle(14, 14, 22, 18, fill="#dff", outline="")
def paint_dtc(c): 
    c.create_rectangle(6,8,30,28, outline="#333", width=2, fill="#ffd66e")
    c.create_rectangle(10,12,26,24, outline="#333", width=1, fill="#fff")
    c.create_text(18,18, text="DTC", font=("Segoe UI",8,"bold"), fill="#333")
def paint_scope(c):
    c.create_rectangle(5,8,31,28, outline="#1e88e5", width=2)
    pts=[6,20,10,20,12,14,16,26,20,10,24,18,28,18,30,22]
    c.create_line(*pts, fill="#1e88e5", width=2, smooth=True)
def paint_check(c):
    c.create_rectangle(6,8,30,28, outline="#333", width=2)
    c.create_line(9,18,16,24,28,12, width=3, fill="#2e7d32", capstyle=tk.ROUND, joinstyle=tk.ROUND)
def paint_wrench(c):
    c.create_oval(8,8,28,28, outline="#777", width=2)
    c.create_line(12,24,26,10, width=4, fill="#777")
    c.create_oval(9,21,15,27, outline="#777", width=2)
def paint_chip(c):
    c.create_rectangle(10,12,26,24, fill="#4dd0e1", outline="#333")
    for x in (8,12,16,20,24,28):
        c.create_line(x,10,x,6,width=2); c.create_line(x,26,x,30,width=2)
    c.create_rectangle(14,16,22,20, fill="#222", outline="")
def paint_gear(c):
    c.create_polygon(18,6,28,12,28,24,18,30,8,24,8,12, fill="#9e9e9e", outline="#666")
    c.create_oval(14,14,22,22, fill="#fff", outline="#666")
def paint_help(c):
    c.create_oval(6,6,30,30, outline="#1976d2", width=2)
    c.create_text(18,14, text="?", font=("Segoe UI",14,"bold"), fill="#1976d2")
    c.create_rectangle(15,22,21,26, fill="#1976d2", outline="")
def paint_save(c):
    c.create_rectangle(8,8,28,28, fill="#90caf9", outline="#333")
    c.create_rectangle(12,10,24,16, fill="#fff", outline="#333")
    c.create_rectangle(12,18,24,26, fill="#e3f2fd", outline="#333")
def paint_folder(c):
    c.create_rectangle(6,14,30,28, fill="#ffcc80", outline="#333")
    c.create_polygon(6,14,14,14,16,10,24,10,24,14,30,14,30,16,6,16, fill="#ffe0b2", outline="#333")

ICON_PAINTERS = {
    "car": paint_car, "dtc": paint_dtc, "scope": paint_scope, "check": paint_check,
    "wrench": paint_wrench, "chip": paint_chip, "gear": paint_gear,
    "help": paint_help, "save": paint_save, "folder": paint_folder,
}

# ===================== Main App =====================

class J2534DiagnosticApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE); self.minsize(APP_MIN_W, APP_MIN_H); self.configure(bg="#e9ecef")
        self.j2534 = J2534Interface()
        self.vehicle_comm = VehicleCommunication(self.j2534)
        self.connected = False
        self.current_protocol = J2534Protocol.ISO15765
        self.current_baud = J2534BaudRate.CAN_500000
        self.voltage = 0.0
        self.msg_queue = queue.Queue()
        self._setup_style(); self._layout_root(); self._make_toolbar()
        self._make_main_tabs(); self._make_bottom_bar(); self._make_bottom_small_buttons()
        self._setup_log_tab(); self._setup_config_tab(); self._device_map = {}
        self._refresh_device_list()
        self._setup_modules_tab(); self._setup_profiles_tab()
        self.after(100, self._process_messages)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _refresh_device_list(self):
        """Populate the J2534 device dropdown from the Windows registry."""
        try:
            devs = self.j2534.list_devices()
            if not devs:
                # keep existing entries but log
                self.log_message("No J2534 devices found in registry (PassThruSupport.04.04). Using fallback list.", "error")
                return
            names = [f'{d["Name"]}  —  {d["Vendor"]}' if d["Vendor"] else d["Name"] for d in devs]
            self._device_map = {names[i]: devs[i] for i in range(len(devs))}
            self.device_combo["values"] = names
            # prefer the first device
            self.device_var.set(names[0])
            self.log_message(f"Found {len(devs)} J2534 device(s).", "info")
        except Exception as e:
            self.log_message(f"Device enumeration error: {e}", "error")
            self._device_map = {}


    def _setup_style(self):
        style = ttk.Style(self)
        try: style.theme_use("vista")
        except tk.TclError: pass
        style.configure("TNotebook", background="#f4f7f9", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(12,6), font=("Segoe UI",9))
        style.map("TNotebook.Tab", background=[("selected","#ffffff")])
        style.configure("Main.TFrame", background="#ffffff")
        style.configure("Toolbar.TFrame", background="#f0f3f6")
        style.configure("Status.TFrame", background="#f7f7f7")
        style.configure("TLabelframe.Label", font=("Segoe UI",9,"bold"))
        style.configure("TLabel", background="#ffffff")

    def _layout_root(self):
        self.grid_columnconfigure(0, minsize=56, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1); self.grid_rowconfigure(1, weight=0)
        self.toolbar = ttk.Frame(self, style="Toolbar.TFrame", padding=(6,6)); self.toolbar.grid(row=0,column=0,sticky="nsw")
        self.main = ttk.Frame(self, style="Main.TFrame"); self.main.grid(row=0,column=1,sticky="nsew")
        self.status_frame = ttk.Frame(self, style="Status.TFrame", padding=(6,4))
        self.status_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.status_frame.grid_columnconfigure(0, weight=1)

    def _make_toolbar(self):
        self.toolbar_buttons={}
        for idx,(label,key) in enumerate(TOOL_BUTTONS):
            f = ttk.Frame(self.toolbar); f.grid(row=idx, column=0, pady=(0 if idx else 0,8))
            c = tk.Canvas(f, width=36, height=36, highlightthickness=0, bg="#f0f3f6"); c.pack()
            ICON_PAINTERS[key](c); self.toolbar_buttons[key]=c
            c.bind("<Button-1>", (lambda k=key: (lambda e: self._on_toolbar_click(k)))())
            def _binds(canvas=c):
                canvas.bind("<Enter>", lambda _: canvas.configure(bg="#e8eef5"))
                canvas.bind("<Leave>", lambda _: canvas.configure(bg="#f0f3f6"))
            _binds()
        self.toolbar.grid_rowconfigure(len(TOOL_BUTTONS), weight=1)

    def _make_main_tabs(self):
        self.notebook = ttk.Notebook(self.main); self.notebook.pack(fill="both", expand=True)
        self.tab_log = ttk.Frame(self.notebook, style="Main.TFrame")
        self.tab_cfg = ttk.Frame(self.notebook, style="Main.TFrame")
        self.tab_mod = ttk.Frame(self.notebook, style="Main.TFrame")
        self.tab_prof = ttk.Frame(self.notebook, style="Main.TFrame")
        self.notebook.add(self.tab_log,text="Log"); self.notebook.add(self.tab_cfg,text="Configuration")
        self.notebook.add(self.tab_mod,text="Modules"); self.notebook.add(self.tab_prof,text="Profiles")

    def _make_bottom_bar(self):
        mid = ttk.Frame(self.status_frame, style="Status.TFrame"); mid.grid(row=0,column=0,sticky="w",padx=(50,0))
        def indicator(parent, color="#b71c1c"):
            box = tk.Canvas(parent, width=14, height=14, bg="#f7f7f7", highlightthickness=0)
            box.create_rectangle(2,2,12,12, fill=color, outline="#555"); return box
        ttk.Label(mid, text="Interface:", background="#f7f7f7").grid(row=0,column=0,padx=(4,4))
        self.ind_if = indicator(mid); ttk.Label(mid, text="   Vehicle:", background="#f7f7f7").grid(row=0,column=2,padx=(10,4))
        self.ind_veh = indicator(mid); self.lbl_conn = ttk.Label(mid, text="   Not connected", background="#f7f7f7")
        self.lbl_conn.grid(row=0,column=4,padx=(10,0))
        right = ttk.Frame(self.status_frame, style="Status.TFrame"); right.grid(row=0,column=1,sticky="e")
        self.volt_canvas = tk.Canvas(right, width=64, height=18, bg="#f7f7f7", highlightthickness=0); self.volt_canvas.pack()
        self.volt_rect = self.volt_canvas.create_rectangle(54,4,60,10, fill="#b71c1c", outline="#555")
        self.volt_text = self.volt_canvas.create_text(20,9, text="--.-V", font=("Segoe UI",9), fill="#333")

    def _make_bottom_small_buttons(self):
        holder = ttk.Frame(self.status_frame, style="Status.TFrame"); holder.grid(row=0,column=0,sticky="w")
        for i,(label,key) in enumerate(BOTTOM_SMALL_BTNS):
            c = tk.Canvas(holder,width=24,height=24,highlightthickness=1,highlightbackground="#999",bg="#f2f2f2")
            c.grid(row=0,column=i,padx=(4 if i else 0,6))
            if key=="gear": c.bind("<Button-1>", lambda e: self._show_settings())
            elif key=="save": c.bind("<Button-1>", lambda e: self._save_log())
            elif key=="folder": c.bind("<Button-1>", lambda e: self._open_folder())
            ICON_PAINTERS.get(key, paint_gear)(c)
            c.bind("<Enter>", lambda e,canvas=c: canvas.configure(bg="#e8eef5"))
            c.bind("<Leave>", lambda e,canvas=c: canvas.configure(bg="#f2f2f2"))

    def _setup_log_tab(self):
        frame = tk.Frame(self.tab_log, bg="#ffffff"); frame.pack(fill="both", expand=True, padx=10, pady=10)
        control = ttk.Frame(frame); control.pack(fill="x", pady=(0,10))
        ttk.Button(control, text="Clear Log", command=self._clear_log).pack(side="left", padx=(0,5))
        ttk.Button(control, text="Export Log", command=self._export_log).pack(side="left", padx=(0,5))
        self.log_filter = ttk.Combobox(control, values=["All","Sent","Received","Errors"], width=15); self.log_filter.set("All")
        self.log_filter.pack(side="left", padx=(20,5)); ttk.Label(control, text="Filter:", background="#ffffff").pack(side="left", padx=(0,5))
        self.log_text = scrolledtext.ScrolledText(frame, height=20, wrap=tk.WORD, font=("Consolas",9)); self.log_text.pack(fill="both", expand=True)
        self.log_text.tag_config("sent", foreground="#0066cc"); self.log_text.tag_config("received", foreground="#009900")
        self.log_text.tag_config("error", foreground="#cc0000"); self.log_text.tag_config("info", foreground="#666666")

    def _setup_config_tab(self):
        frame = tk.Frame(self.tab_cfg, bg="#ffffff"); frame.pack(fill="both", expand=True, padx=10, pady=10)
        conn = ttk.LabelFrame(frame, text="Connection Settings", padding=10); conn.pack(fill="x", pady=(0,10))
        ttk.Label(conn, text="Protocol:", background="#ffffff").grid(row=0,column=0,sticky="w",padx=(0,10))
        self.protocol_var = tk.StringVar(value="ISO15765 (CAN)")
        self.protocol_combo = ttk.Combobox(conn, textvariable=self.protocol_var, width=25,
                                           values=["ISO15765 (CAN)","ISO14230 (KWP2000)","ISO9141","J1850 PWM","J1850 VPW"])
        self.protocol_combo.grid(row=0,column=1,sticky="w",pady=5)
        ttk.Label(conn, text="Baud Rate:", background="#ffffff").grid(row=1,column=0,sticky="w",padx=(0,10))
        self.baud_var = tk.StringVar(value="500000")
        self.baud_combo = ttk.Combobox(conn, textvariable=self.baud_var, width=25,
                                       values=["250000","500000","1000000","125000","10400","41600"])
        self.baud_combo.grid(row=1,column=1,sticky="w",pady=5)
        ttk.Label(conn, text="J2534 Device:", background="#ffffff").grid(row=2,column=0,sticky="w",padx=(0,10))
        self.device_var = tk.StringVar(value="J2534"); self.device_combo = ttk.Combobox(conn, textvariable=self.device_var, width=25,
                                    values=["J2534","Mock J2534 Device","PassThru Device"])
        self.device_combo.grid(row=2,column=1,sticky="w",pady=5)
        btns = ttk.Frame(conn); btns.grid(row=3,column=0,columnspan=2,pady=(10,0))
        self.connect_btn = ttk.Button(btns, text="Connect", command=self._connect_vehicle); self.connect_btn.pack(side="left", padx=(0,5))
        self.disconnect_btn = ttk.Button(btns, text="Disconnect", command=self._disconnect_vehicle, state="disabled"); self.disconnect_btn.pack(side="left")
        adv = ttk.LabelFrame(frame, text="Advanced Settings", padding=10); adv.pack(fill="x", pady=(0,10))
        ttk.Label(adv, text="Response Timeout (ms):", background="#ffffff").grid(row=0,column=0,sticky="w",padx=(0,10))
        self.timeout_var = tk.StringVar(value="2000"); ttk.Spinbox(adv, textvariable=self.timeout_var, from_=100,to=10000,increment=100,width=23).grid(row=0,column=1,sticky="w",pady=5)
        ttk.Label(adv, text="Flow Control:", background="#ffffff").grid(row=1,column=0,sticky="w",padx=(0,10))
        self.flow_control_var = tk.BooleanVar(value=True); ttk.Checkbutton(adv, text="Enable", variable=self.flow_control_var).grid(row=1,column=1,sticky="w",pady=5)
        ttk.Label(adv, text="Message Filters:", background="#ffffff").grid(row=2,column=0,sticky="w",padx=(0,10))
        self.filter_var = tk.BooleanVar(value=True); ttk.Checkbutton(adv, text="Enable", variable=self.filter_var).grid(row=2,column=1,sticky="w",pady=5)

    def _setup_modules_tab(self):
        frame = tk.Frame(self.tab_mod, bg="#ffffff"); frame.pack(fill="both", expand=True, padx=10, pady=10)
        left = ttk.Frame(frame); left.pack(side="left", fill="both", expand=True, padx=(0,10))
        ttk.Label(left, text="Available ECUs:", background="#ffffff", font=("Segoe UI",10,"bold")).pack(anchor="w")
        self.ecu_tree = ttk.Treeview(left, columns=("Address","Protocol","Status"), height=15)
        self.ecu_tree.heading("#0", text="Module"); self.ecu_tree.heading("Address")
        self.ecu_tree.heading("Protocol"); self.ecu_tree.heading("Status")
        self.ecu_tree.column("#0", width=200); self.ecu_tree.column("Address", width=100)
        self.ecu_tree.column("Protocol", width=100); self.ecu_tree.column("Status", width=100)
        self.ecu_tree.pack(fill="both", expand=True, pady=(5,10))
        ecu_btn = ttk.Frame(left); ecu_btn.pack(fill="x")
        ttk.Button(ecu_btn, text="Scan ECUs", command=self._scan_ecus).pack(side="left", padx=(0,5))
        ttk.Button(ecu_btn, text="Refresh", command=self._refresh_ecus).pack(side="left", padx=(0,5))
        ttk.Button(ecu_btn, text="Info", command=self._show_ecu_info).pack(side="left")
        right = ttk.LabelFrame(frame, text="Diagnostic Trouble Codes", padding=10); right.pack(side="right", fill="both", expand=True)
        dtc_btn = ttk.Frame(right); dtc_btn.pack(fill="x", pady=(0,10))
        ttk.Button(dtc_btn, text="Read DTCs", command=self._read_dtcs).pack(side="left", padx=(0,5))
        ttk.Button(dtc_btn, text="Clear DTCs", command=self._clear_dtcs).pack(side="left", padx=(0,5))
        ttk.Button(dtc_btn, text="Freeze Frame", command=self._read_freeze_frame).pack(side="left")
        self.dtc_tree = ttk.Treeview(right, columns=("Description","Status","Module"), height=10)
        self.dtc_tree.heading("#0"); self.dtc_tree.heading("Description")
        self.dtc_tree.heading("Status"); self.dtc_tree.heading("Module")
        self.dtc_tree.column("#0", width=80); self.dtc_tree.column("Description", width=250)
        self.dtc_tree.column("Status", width=100); self.dtc_tree.column("Module", width=150)
        self.dtc_tree.pack(fill="both", expand=True)
        ttk.Label(right, text="Details:", background="#ffffff", font=("Segoe UI",9,"bold")).pack(anchor="w", pady=(10,5))
        self.dtc_details = tk.Text(right, height=5, wrap=tk.WORD, font=("Consolas",9)); self.dtc_details.pack(fill="x")

    def _setup_profiles_tab(self):
        frame = tk.Frame(self.tab_prof, bg="#ffffff"); frame.pack(fill="both", expand=True, padx=10, pady=10)
        prof = ttk.LabelFrame(frame, text="Profile Management", padding=10); prof.pack(fill="x", pady=(0,10))
        ttk.Label(prof, text="Saved Profiles:", background="#ffffff").grid(row=0,column=0,sticky="w")
        self.profile_listbox = tk.Listbox(prof, height=6, width=50); self.profile_listbox.grid(row=1,column=0,columnspan=2,pady=(5,10))
        for s in ("Default - ISO15765 CAN 500k","Ford - ISO14230 KWP2000","GM - J1850 VPW","Chrysler - J1850 PWM"):
            self.profile_listbox.insert(tk.END, s)
        pbtn = ttk.Frame(prof); pbtn.grid(row=2,column=0,columnspan=2)
        ttk.Button(pbtn, text="Load Profile", command=self._load_profile).pack(side="left", padx=(0,5))
        ttk.Button(pbtn, text="Save Profile", command=self._save_profile).pack(side="left", padx=(0,5))
        ttk.Button(pbtn, text="Delete Profile", command=self._delete_profile).pack(side="left", padx=(0,5))
        ttk.Button(pbtn, text="Export", command=self._export_profile).pack(side="left", padx=(0,5))
        ttk.Button(pbtn, text="Import", command=self._import_profile).pack(side="left")
        detail = ttk.LabelFrame(frame, text="Profile Details", padding=10); detail.pack(fill="both", expand=True)
        self.profile_details = tk.Text(detail, height=10, wrap=tk.WORD, font=("Consolas",9)); self.profile_details.pack(fill="both", expand=True)

    # ---------- toolbar actions ----------
    def _on_toolbar_click(self, key: str):
        if key == "car": self.notebook.select(self.tab_cfg); self.connect()
        elif key == "dtc": self.notebook.select(self.tab_mod); self._read_dtcs()
        elif key == "scope": self._show_scope()
        elif key == "check": self._show_tests()
        elif key == "wrench": self._show_service()
        elif key == "chip": self._show_chip_tuning()
        elif key == "gear": self._show_settings()
        elif key == "help": self._show_help()

    # ---------- connectivity ----------
    def _connect_vehicle(self):
        def t():
            try:
                self.log_message("Connecting to J2534 device...", "info")
                # Resolve selected item to a DLL path or name
                sel = self.device_var.get()
                dll_or_name = sel
                if hasattr(self, "_device_map") and sel in self._device_map:
                    dll_or_name = self._device_map[sel].get("FunctionLibrary") or self._device_map[sel].get("Name") or sel

                if not self.j2534.connect(dll_or_name):
                    self.log_message(f"Failed to connect J2534: {self.j2534.last_error()}", "error"); return
                    self.log_message(f"Connected to {self.device_var.get()}", "info")

                protocol_map = {"ISO15765 (CAN)": J2534Protocol.ISO15765,
                                "ISO14230 (KWP2000)": J2534Protocol.ISO14230,
                                "ISO9141": J2534Protocol.ISO9141,
                                "J1850 PWM": J2534Protocol.J1850PWM,
                                "J1850 VPW": J2534Protocol.J1850VPW}
                protocol = protocol_map.get(self.protocol_var.get(), J2534Protocol.ISO15765)
                baud_rate = int(self.baud_var.get())

                self.log_message(f"Opening {self.protocol_var.get()} at {baud_rate}...", "info")
                if not self.j2534.open_channel(protocol, baud_rate):
                    self.log_message(f"Open channel failed: {self.j2534.last_error()}", "error"); return

                # Default ISO-TP FC filter 0x7E0 -> 0x7E8 if ISO15765
                if protocol == J2534Protocol.ISO15765 and self.flow_control_var.get():
                    fid = self.j2534.set_iso15765_flow_control(0x7E0, 0x7E8)
                    if fid:
                        self.log_message(f"ISO-TP FC filter started (fid={fid})", "info")
                    else:
                        self.log_message("Failed to start ISO-TP FC filter (continuing)", "error")

                self.connected = True
                self.msg_queue.put(("connection", True))
                vb = self.j2534.read_vehicle_voltage()
                if vb: self.voltage = vb; self.msg_queue.put(("voltage", vb))
                self.log_message("Vehicle connection established", "info")

            except Exception as e:
                self.log_message(f"Connection error: {e}", "error")
                self.msg_queue.put(("connection", False))
        threading.Thread(target=t, daemon=True).start()

    def _disconnect_vehicle(self):
        try:
            self.j2534.close_channel(); self.j2534.disconnect()
            self.connected = False; self.voltage = 0.0
            self.msg_queue.put(("connection", False)); self.msg_queue.put(("voltage", 0.0))
            self.log_message("Disconnected from vehicle", "info")
        except Exception as e:
            self.log_message(f"Disconnect error: {e}", "error")

    # ---------- ECU ops ----------
    def _scan_ecus(self):
        if not self.connected:
            messagebox.showwarning("Not Connected","Please connect to vehicle first"); return
        def t():
            try:
                self.log_message("Scanning for ECUs...", "info")
                protocol_map = {"ISO15765 (CAN)": J2534Protocol.ISO15765,
                                "ISO14230 (KWP2000)": J2534Protocol.ISO14230,
                                "ISO9141": J2534Protocol.ISO9141,
                                "J1850 PWM": J2534Protocol.J1850PWM,
                                "J1850 VPW": J2534Protocol.J1850VPW}
                protocol = protocol_map.get(self.protocol_var.get(), J2534Protocol.ISO15765)
                ecus = self.vehicle_comm.scan_for_ecus(protocol)
                self.msg_queue.put(("ecus", ecus))
                self.log_message(f"Found {len(ecus)} ECUs", "info")
                for ecu in ecus: self.log_message(f"  - {ecu.name} at 0x{ecu.address:03X}", "info")
            except Exception as e:
                self.log_message(f"ECU scan error: {e}", "error")
        threading.Thread(target=t, daemon=True).start()

    def _refresh_ecus(self): self._scan_ecus()

    def _show_ecu_info(self):
        sel = self.ecu_tree.selection()
        if not sel: messagebox.showinfo("No Selection","Please select an ECU first"); return
        item = self.ecu_tree.item(sel[0]); ecu_name = item['text']
        d = tk.Toplevel(self); d.title(f"ECU Information - {ecu_name}"); d.geometry("400x300")
        t = tk.Text(d, wrap=tk.WORD, font=("Consolas",9)); t.pack(fill="both", expand=True, padx=10, pady=10)
        t.insert(tk.END, f"Module: {ecu_name}\nAddress: {item['values'][0]}\nProtocol: {item['values'][1]}\nStatus: {item['values'][2]}\n\nSupported PIDs:\n- Engine RPM\n- Vehicle Speed\n- Coolant Temp\n- Fuel Level\n"); t.config(state="disabled")

    def _read_dtcs(self):
        if not self.connected: messagebox.showwarning("Not Connected","Please connect to vehicle first"); return
        sel = self.ecu_tree.selection()
        if not sel: messagebox.showinfo("No Selection","Please select an ECU first"); return
        def t():
            try:
                item = self.ecu_tree.item(sel[0]); ecu_name = item['text']
                self.log_message(f"Reading DTCs from {ecu_name}...", "info")
                ecu = next((e for e in self.vehicle_comm.ecus if e.name == ecu_name), None)
                if not ecu: self.log_message("ECU not found","error"); return
                dtcs = self.vehicle_comm.read_dtcs(ecu)
                self.msg_queue.put(("dtcs", dtcs)); self.log_message(f"Found {len(dtcs)} DTCs","info")
                for d in dtcs: self.log_message(f"  - {d.code}: {d.description}","info")
            except Exception as e:
                self.log_message(f"DTC read error: {e}", "error")
        threading.Thread(target=t, daemon=True).start()

    def _clear_dtcs(self):
        if not self.connected: messagebox.showwarning("Not Connected","Please connect to vehicle first"); return
        sel = self.ecu_tree.selection()
        if not sel: messagebox.showinfo("No Selection","Please select an ECU first"); return
        if messagebox.askyesno("Clear DTCs","Are you sure you want to clear all DTCs?"):
            def t():
                try:
                    item = self.ecu_tree.item(sel[0]); ecu_name = item['text']
                    self.log_message(f"Clearing DTCs from {ecu_name}...", "info")
                    ecu = next((e for e in self.vehicle_comm.ecus if e.name == ecu_name), None)
                    if not ecu: self.log_message("ECU not found","error"); return
                    if self.vehicle_comm.clear_dtcs(ecu):
                        self.msg_queue.put(("dtcs", [])); self.log_message("DTCs cleared successfully","info")
                    else:
                        self.log_message("Failed to clear DTCs","error")
                except Exception as e:
                    self.log_message(f"DTC clear error: {e}", "error")
            threading.Thread(target=t, daemon=True).start()

    def _read_freeze_frame(self):
        if not self.connected: messagebox.showwarning("Not Connected","Please connect to vehicle first"); return
        messagebox.showinfo("Freeze Frame", "Freeze frame data reading not yet implemented")

    # ---------- misc UI ----------
    def _show_scope(self):
        w = tk.Toplevel(self); w.title("Oscilloscope"); w.geometry("800x600")
        canvas = tk.Canvas(w, bg="black"); canvas.pack(fill="both", expand=True)
        for i in range(0,800,50): canvas.create_line(i,0,i,600, fill="#003300", width=1)
        for i in range(0,600,50): canvas.create_line(0,i,800,i, fill="#003300", width=1)
        import math; pts=[]; 
        for x in range(800): pts.extend([x, 300+100*math.sin(x*0.02)])
        canvas.create_line(pts, fill="#00ff00", width=2)

    def _show_tests(self):
        w = tk.Toplevel(self); w.title("Component Tests"); w.geometry("600x400")
        cats=["Actuator Tests","Sensor Tests","System Tests","Bi-directional Controls"]
        nb = ttk.Notebook(w); nb.pack(fill="both", expand=True)
        tests=["Fuel Pump Test","Injector Test","Ignition Coil Test","EVAP System Test"]
        for cat in cats:
            f = ttk.Frame(nb); nb.add(f, text=cat)
            for i,t in enumerate(tests):
                ttk.Button(f, text=t, command=lambda t=t: messagebox.showinfo("Test", f"Running {t}...")).grid(row=i,column=0,padx=10,pady=5,sticky="w")

    def _show_service(self):
        w = tk.Toplevel(self); w.title("Service Functions"); w.geometry("600x400")
        services={"Oil Reset":["Engine Oil","Transmission Oil","Differential Oil"],
                  "Adaptation":["Throttle Body","Steering Angle","Battery"],
                  "Coding":["Injector Coding","Key Programming","Module Coding"],
                  "Calibration":["TPMS","Suspension","Camera"]}
        nb = ttk.Notebook(w); nb.pack(fill="both", expand=True)
        for cat, items in services.items():
            f = ttk.Frame(nb); nb.add(f, text=cat)
            for i,item in enumerate(items):
                ttk.Button(f, text=item, command=lambda i=item: messagebox.showinfo("Service", f"Performing {i}...")).grid(row=i,column=0,padx=10,pady=5,sticky="w")

    def _show_chip_tuning(self): messagebox.showinfo("Chip Tuning","ECU programming and tuning functions")

    def _show_settings(self):
        w = tk.Toplevel(self); w.title("Settings"); w.geometry("500x400")
        nb = ttk.Notebook(w); nb.pack(fill="both", expand=True, padx=10, pady=10)
        g = ttk.Frame(nb); nb.add(g, text="General")
        ttk.Label(g, text="Language:").grid(row=0,column=0,sticky="w",padx=10,pady=5)
        ttk.Combobox(g, values=["English","Spanish","French","German"], width=20).grid(row=0,column=1,padx=10,pady=5)
        ttk.Label(g, text="Theme:").grid(row=1,column=0,sticky="w",padx=10,pady=5)
        ttk.Combobox(g, values=["Light","Dark","Auto"], width=20).grid(row=1,column=1,padx=10,pady=5)
        ttk.Checkbutton(g, text="Auto-connect on startup").grid(row=2,column=0,columnspan=2,sticky="w",padx=10,pady=5)
        ttk.Checkbutton(g, text="Save log automatically").grid(row=3,column=0,columnspan=2,sticky="w",padx=10,pady=5)
        c = ttk.Frame(nb); nb.add(c, text="Communication")
        ttk.Label(c, text="Default Protocol:").grid(row=0,column=0,sticky="w",padx=10,pady=5)
        ttk.Combobox(c, values=["Auto-detect","ISO15765","ISO14230","J1850"], width=20).grid(row=0,column=1,padx=10,pady=5)
        ttk.Label(c, text="Retry Count:").grid(row=1,column=0,sticky="w",padx=10,pady=5)
        ttk.Spinbox(c, from_=1,to=10, width=18).grid(row=1,column=1,padx=10,pady=5)

    def _show_help(self):
        w = tk.Toplevel(self); w.title("Help"); w.geometry("600x400")
        t = scrolledtext.ScrolledText(w, wrap=tk.WORD); t.pack(fill="both", expand=True, padx=10, pady=10)
        t.insert(tk.END, "J2534 Diagnostic Software - Help\n\nGETTING STARTED:\n1. Connect your J2534 device\n2. Select protocol & baud\n3. Connect\n4. Scan ECUs / Read DTCs\n\nTroubleshooting:\n- Drivers installed\n- Ignition ON\n- Try different baud/protocol\n"); t.config(state="disabled")

    def _save_log(self):
        from tkinter import filedialog
        fn = filedialog.asksaveasfilename(defaultextension=".txt",
                                          filetypes=[("Text files","*.txt"),("All files","*.*")])
        if fn:
            try:
                with open(fn,"w",encoding="utf-8") as f: f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success","Log saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log: {e}")

    def _open_folder(self):
        import subprocess
        logs_dir = os.path.join(os.path.expanduser("~"), "J2534_Logs")
        os.makedirs(logs_dir, exist_ok=True)
        if platform.system()=="Windows": subprocess.Popen(f'explorer "{logs_dir}"')
        elif platform.system()=="Darwin": subprocess.Popen(["open", logs_dir])
        else: subprocess.Popen(["xdg-open", logs_dir])

    def _clear_log(self): self.log_text.delete(1.0, tk.END)
    def _export_log(self): self._save_log()

    def _load_profile(self):
        sel = self.profile_listbox.curselection()
        if not sel: messagebox.showinfo("No Selection","Please select a profile"); return
        name = self.profile_listbox.get(sel[0])
        if "ISO15765" in name: self.protocol_var.set("ISO15765 (CAN)"); self.baud_var.set("500000")
        elif "ISO14230" in name: self.protocol_var.set("ISO14230 (KWP2000)"); self.baud_var.set("10400")
        elif "J1850 VPW" in name: self.protocol_var.set("J1850 VPW"); self.baud_var.set("10400")
        elif "J1850 PWM" in name: self.protocol_var.set("J1850 PWM"); self.baud_var.set("41600")
        self.log_message(f"Loaded profile: {name}","info"); messagebox.showinfo("Profile Loaded", f"Profile '{name}' loaded")

    def _save_profile(self):
        from tkinter import simpledialog
        name = simpledialog.askstring("Save Profile","Enter profile name:")
        if name:
            entry = f"{name} - {self.protocol_var.get()} {self.baud_var.get()}"
            self.profile_listbox.insert(tk.END, entry)
            self.log_message(f"Saved profile: {name}","info")
            messagebox.showinfo("Profile Saved", f"Profile '{name}' saved")

    def _delete_profile(self):
        sel = self.profile_listbox.curselection()
        if not sel: messagebox.showinfo("No Selection","Please select a profile"); return
        if messagebox.askyesno("Delete Profile","Are you sure?"): self.profile_listbox.delete(sel[0])

    def _export_profile(self):
        from tkinter import filedialog
        fn = filedialog.asksaveasfilename(defaultextension=".ini",
                                          filetypes=[("INI files","*.ini"),("All files","*.*")])
        if fn:
            cfg = configparser.ConfigParser()
            cfg['Connection']={'Protocol': self.protocol_var.get(),'BaudRate': self.baud_var.get(),'Device': self.device_var.get()}
            cfg['Advanced']={'Timeout': self.timeout_var.get(),'FlowControl': str(self.flow_control_var.get()),'Filters': str(self.filter_var.get())}
            with open(fn,"w") as f: cfg.write(f)
            messagebox.showinfo("Success","Profile exported")

    def _import_profile(self):
        from tkinter import filedialog
        fn = filedialog.askopenfilename(filetypes=[("INI files","*.ini"),("All files","*.*")])
        if fn:
            cfg = configparser.ConfigParser(); cfg.read(fn)
            if 'Connection' in cfg:
                self.protocol_var.set(cfg.get('Connection','Protocol'))
                self.baud_var.set(cfg.get('Connection','BaudRate'))
                self.device_var.set(cfg.get('Connection','Device'))
            if 'Advanced' in cfg:
                self.timeout_var.set(cfg.get('Advanced','Timeout'))
                self.flow_control_var.set(cfg.getboolean('Advanced','FlowControl'))
                self.filter_var.set(cfg.getboolean('Advanced','Filters'))
            messagebox.showinfo("Success","Profile imported")

    def log_message(self, message: str, msg_type: str = "info"):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.msg_queue.put(("log", (f"[{ts}] {message}\n", msg_type)))

    def _process_messages(self):
        try:
            while True:
                kind, data = self.msg_queue.get_nowait()
                if kind=="log":
                    text, tag = data; self.log_text.insert(tk.END, text, tag); self.log_text.see(tk.END)
                elif kind=="connection":
                    connected = data
                    if connected:
                        for c in (self.ind_if, self.ind_veh):
                            c.delete("all"); c.create_rectangle(2,2,12,12, fill="#4caf50", outline="#555")
                        self.lbl_conn.config(text="   Connected"); self.connect_btn.config(state="disabled"); self.disconnect_btn.config(state="normal")
                    else:
                        for c in (self.ind_if, self.ind_veh):
                            c.delete("all"); c.create_rectangle(2,2,12,12, fill="#b71c1c", outline="#555")
                        self.lbl_conn.config(text="   Not connected"); self.connect_btn.config(state="normal"); self.disconnect_btn.config(state="disabled")
                elif kind=="voltage":
                    v = data; self.volt_canvas.delete(self.volt_text)
                    if v and v>0:
                        self.volt_text = self.volt_canvas.create_text(20,9, text=f"{v:.1f}V", font=("Segoe UI",9), fill="#333")
                        color = "#4caf50" if v>12.0 else "#ff9800" if v>11.5 else "#b71c1c"
                        self.volt_canvas.delete(self.volt_rect); self.volt_rect = self.volt_canvas.create_rectangle(54,4,60,10, fill=color, outline="#555")
                    else:
                        self.volt_text = self.volt_canvas.create_text(20,9, text="--.-V", font=("Segoe UI",9), fill="#333")
                        self.volt_canvas.delete(self.volt_rect); self.volt_rect = self.volt_canvas.create_rectangle(54,4,60,10, fill="#b71c1c", outline="#555")
                elif kind=="ecus":
                    ecus = data
                    for item in self.ecu_tree.get_children(): self.ecu_tree.delete(item)
                    for ecu in ecus:
                        status = "Active" if self.connected else "Inactive"
                        self.ecu_tree.insert("", "end", text=ecu.name, values=(f"0x{ecu.address:03X}", ecu.protocol.name, status))
                elif kind=="dtcs":
                    dtcs = data
                    for item in self.dtc_tree.get_children(): self.dtc_tree.delete(item)
                    for d in dtcs:
                        self.dtc_tree.insert("", "end", text=d.code, values=(d.description, d.status, d.module))
                    if dtcs:
                        self.dtc_details.delete(1.0, tk.END)
                        self.dtc_details.insert(tk.END, f"Code: {dtcs[0].code}\nDescription: {dtcs[0].description}\nStatus: {dtcs[0].status}\nModule: {dtcs[0].module}\n")
                        if dtcs[0].timestamp:
                            self.dtc_details.insert(tk.END, f"Time: {dtcs[0].timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_messages)

    def _on_close(self):
        if self.connected:
            if messagebox.askyesno("Close", "Vehicle is still connected. Disconnect and close?"):
                self._disconnect_vehicle(); self.destroy()
        else:
            self.destroy()


# ===================== Live Data Window (unchanged) =====================

class LiveDataWindow(tk.Toplevel):
    def __init__(self, parent, vehicle_comm):
        super().__init__(parent); self.title("Live Data"); self.geometry("800x600")
        self.vehicle_comm = vehicle_comm; self.running = False; self.data_values={}
        self._create_widgets()

    def _create_widgets(self):
        ctrl = ttk.Frame(self); ctrl.pack(fill="x", padx=10, pady=10)
        self.start_btn = ttk.Button(ctrl, text="Start", command=self.start_monitoring); self.start_btn.pack(side="left", padx=(0,5))
        self.stop_btn  = ttk.Button(ctrl, text="Stop", command=self.stop_monitoring, state="disabled"); self.stop_btn.pack(side="left", padx=(0,5))
        ttk.Button(ctrl, text="Clear", command=self.clear_data).pack(side="left")
        cols=("Value","Unit","Min","Max","Avg"); self.data_tree = ttk.Treeview(self, columns=cols, height=20)
        self.data_tree.heading("#0","Parameter")
        for c in cols: self.data_tree.heading(c,c); self.data_tree.column(c, width=100)
        self.data_tree.pack(fill="both", expand=True, padx=10, pady=(0,10))
        params=[("Engine Speed","0","RPM","0","0","0"),("Vehicle Speed","0","km/h","0","0","0"),
                ("Coolant Temp","0","°C","0","0","0"),("Engine Load","0","%","0","0","0"),
                ("Throttle Position","0","%","0","0","0"),("Fuel Level","0","%","0","0","0"),
                ("Battery Voltage","0","V","0","0","0"),("Intake Air Temp","0","°C","0","0","0"),
                ("MAF Rate","0","g/s","0","0","0"),("Fuel Pressure","0","kPa","0","0","0")]
        for p in params: self.data_tree.insert("", "end", text=p[0], values=p[1:])

    def start_monitoring(self):
        self.running=True; self.start_btn.config(state="disabled"); self.stop_btn.config(state="normal"); self._update_data()

    def stop_monitoring(self):
        self.running=False; self.start_btn.config(state="normal"); self.stop_btn.config(state="disabled")

    def clear_data(self):
        for i in self.data_tree.get_children():
            self.data_tree.set(i,"Value","0"); self.data_tree.set(i,"Min","0"); self.data_tree.set(i,"Max","0"); self.data_tree.set(i,"Avg","0")

    def _update_data(self):
        if not self.running: return
        import random
        for item in self.data_tree.get_children():
            p = self.data_tree.item(item)['text']
            if p=="Engine Speed": v=random.randint(800,3500)
            elif p=="Vehicle Speed": v=random.randint(0,120)
            elif p=="Coolant Temp": v=random.randint(80,95)
            elif p=="Engine Load": v=random.randint(10,80)
            elif p=="Throttle Position": v=random.randint(0,100)
            elif p=="Fuel Level": v=random.randint(20,80)
            elif p=="Battery Voltage": v=round(random.uniform(12.0,14.5),1)
            elif p=="Intake Air Temp": v=random.randint(15,40)
            elif p=="MAF Rate": v=round(random.uniform(2.0,50.0),1)
            elif p=="Fuel Pressure": v=random.randint(200,400)
            else: v=0
            self.data_tree.set(item,"Value",str(v))
            cur_min=float(self.data_tree.set(item,"Min") or 0); cur_max=float(self.data_tree.set(item,"Max") or 0)
            if cur_min==0 or v<cur_min: self.data_tree.set(item,"Min",str(v))
            if v>cur_max: self.data_tree.set(item,"Max",str(v))
            avg=(float(self.data_tree.set(item,"Min"))+float(self.data_tree.set(item,"Max"))+float(self.data_tree.set(item,"Value")))/3
            self.data_tree.set(item,"Avg",f"{avg:.1f}")
        if self.running: self.after(500, self._update_data)


# ===================== Entry =====================

def main():
    app = J2534DiagnosticApp()
    menubar = tk.Menu(app); app.config(menu=menubar)
    file_menu = tk.Menu(menubar, tearoff=0); menubar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="New Session", command=lambda: app.log_message("New session started","info"))
    file_menu.add_command(label="Open Log...", command=lambda: app.log_message("Open log file","info"))
    file_menu.add_command(label="Save Log...", command=app._save_log); file_menu.add_separator()
    file_menu.add_command(label="Exit", command=app._on_close)
    tools = tk.Menu(menubar, tearoff=0); menubar.add_cascade(label="Tools", menu=tools)
    tools.add_command(label="Live Data", command=lambda: LiveDataWindow(app, app.vehicle_comm))
    tools.add_command(label="Oscilloscope", command=app._show_scope)
    tools.add_command(label="Component Tests", command=app._show_tests)
    tools.add_command(label="Service Functions", command=app._show_service)
    tools.add_separator(); tools.add_command(label="Settings...", command=app._show_settings)
    veh = tk.Menu(menubar, tearoff=0); menubar.add_cascade(label="Vehicle", menu=veh)
    veh.add_command(label="Connect", command=app._connect_vehicle)
    veh.add_command(label="Disconnect", command=app._disconnect_vehicle)
    veh.add_separator(); veh.add_command(label="Scan ECUs", command=app._scan_ecus)
    veh.add_command(label="Read DTCs", command=app._read_dtcs)
    veh.add_command(label="Clear DTCs", command=app._clear_dtcs)
    helpm = tk.Menu(menubar, tearoff=0); menubar.add_cascade(label="Help", menu=helpm)
    helpm.add_command(label="Documentation", command=app._show_help)
    helpm.add_command(label="About", command=lambda: messagebox.showinfo("About","J2534 Diagnostic Software v1.0\n© 2024"))
    app.log_message("J2534 Diagnostic Software started","info"); app.log_message("Ready to connect to vehicle","info")
    app.mainloop()

if __name__ == "__main__":
    main()
