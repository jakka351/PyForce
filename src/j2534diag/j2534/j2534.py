# j2534_full.py
# -*- coding: utf-8 -*-
"""
Full Python (ctypes) conversion of the provided C# J2534 code.
- Mirrors enums, structs, helper utilities
- Wraps a vendor J2534 DLL (stdcall) on Windows
- Provides J2534Functions and J2534FunctionsExtended classes
- Includes optional bindings for J2534-2/v5-style functions if the DLL exports them

Author: converted for Jakka (2025)
"""

from __future__ import annotations

import ctypes as ct
from ctypes import wintypes
from enum import IntEnum, IntFlag
from dataclasses import dataclass
from typing import List, Tuple, Optional

# ---------------------------- Typedefs ----------------------------

UINT32 = ct.c_uint32
UINT16 = ct.c_uint16
UINT8  = ct.c_ubyte
INT32  = ct.c_int32
INTPTR = ct.c_void_p

MAX_MSG_BYTES = 4128  # per SAE J2534

# ---------------------------- Enums ----------------------------

class ConfigParameter(IntEnum):
    DATA_RATE = 0x01
    LOOPBACK = 0x03
    NODE_ADDRESS = 0x04
    NETWORK_LINE = 0x05
    P1_MIN = 0x06
    P1_MAX = 0x07
    P2_MIN = 0x08
    P2_MAX = 0x09
    P3_MIN = 0x0A
    P3_MAX = 0x0B
    P4_MIN = 0x0C
    P4_MAX = 0x0D
    W1 = 0x0E
    W2 = 0x0F
    W3 = 0x10
    W4 = 0x11
    W5 = 0x12
    TIDLE = 0x13
    TINIL = 0x14
    TWUP = 0x15
    PARITY = 0x16
    BIT_SAMPLE_POINT = 0x17
    SYNC_JUMP_WIDTH = 0x18
    W0_MIN = 0x19
    T1_MAX = 0x1A
    T2_MAX = 0x1B
    T4_MAX = 0x1C
    T5_MAX = 0x1D
    ISO15765_BS = 0x1E
    ISO15765_STMIN = 0x1F
    DATA_BITS = 0x20
    FIVE_BAUD_MOD = 0x21
    BS_TX = 0x22
    STMIN_TX = 0x23
    T3_MAX = 0x24
    ISO15765_WFT_MAX = 0x25
    W1_MIN = 0x26
    W2_MIN = 0x27
    W3_MIN = 0x28
    W4_MAX = 0x29
    N_BR_MIN = 0x2A
    ISO15765_PAD_VALUE = 0x2B
    N_AS_MAX = 0x2C
    N_AR_MAX = 0x2D
    N_BS_MAX = 0x2E
    N_CR_MAX = 0x2F
    N_CS_MIN = 0x30
    ECHO_PHYSCIAL_CHANNEL_TX = 0x31
    # J2534-2/vendor
    CAN_MIXED_FORMAT = 0x00008000
    J1962_PINS = 0x00008001
    SW_CAN_HS_DATA_RATE = 0x00008010
    SW_CAN_SPEEDCHANGE_ENABLE = 0x00008011
    SW_CAN_RES_SWITCH = 0x00008012
    ACTIVE_CHANNELS = 0x00008020
    SAMPLE_RATE = 0x00008021
    SAMPLES_PER_READING = 0x00008022
    READINGS_PER_MSG = 0x00008023
    AVERAGING_METHOD = 0x00008024
    SAMPLE_RESOLUTION = 0x00008025
    INPUT_RANGE_LOW = 0x00008026
    INPUT_RANGE_HIGH = 0x00008027

class RxStatus(IntFlag):
    NONE = 0x00000000
    TX_MSG_TYPE = 0x00000001
    START_OF_MESSAGE = 0x00000002
    RX_BREAK = 0x00000004
    TX_INDICATION_SUCCESS = 0x00000008
    ISO15765_PADDING_ERROR = 0x00000010
    ERROR_INDICATION = 0x00000020
    BUFFER_OVERFLOW = 0x00000040
    ISO15765_ADDR_TYPE = 0x00000080
    CAN_29BIT_ID = 0x00000100
    TX_FAILED = 0x00000200
    SW_CAN_HV_TX = 0x00000400
    SW_CAN_HV_RX = 0x00010000
    SW_CAN_HS_RX = 0x00020000
    SW_CAN_NS_RX = 0x00040000

class ConnectFlag(IntFlag):
    NONE = 0x0000
    ISO9141_K_LINE_ONLY = 0x1000
    CAN_ID_BOTH = 0x0800
    ISO9141_NO_CHECKSUM = 0x0200
    CAN_29BIT_ID = 0x0100
    FULL_DUPLEX = 0x0001

class TxFlag(IntFlag):
    NONE = 0x00000000
    SCI_TX_VOLTAGE = 0x00800000
    SCI_MODE = 0x00400000
    WAIT_P3_MIN_ONLY = 0x00000200
    CAN_29BIT_ID = 0x00000100
    ISO15765_ADDR_TYPE = 0x00000080
    ISO15765_FRAME_PAD = 0x00000040
    SW_CAN_HV_TX = 0x00000400

class ProtocolID(IntEnum):
    J1850VPW = 0x01
    J1850PWM = 0x02
    ISO9141 = 0x03
    ISO14230 = 0x04
    CAN = 0x05
    ISO15765 = 0x06
    SCI_A_ENGINE = 0x07
    SCI_A_TRANS = 0x08
    SCI_B_ENGINE = 0x09
    SCI_B_TRANS = 0x0A
    ISO15765_LOGICAL = 0x200
    # J2534-2 protocols
    J1850VPW_PS = 0x8000
    J1850PWM_PS = 0x8001
    ISO9141_PS = 0x8002
    ISO14230_PS = 0x8003
    CAN_PS = 0x8004
    ISO15765_PS = 0x8005
    J2610_PS = 0x8006
    SW_ISO15765_PS = 0x8007
    SW_CAN_PS = 0x8008
    GM_UART_PS = 0x8009
    UART_ECHO_BYTE_PS = 0x800A
    HONDA_DIAGH_PS = 0x800B
    J1939_PS = 0x800C
    J1708_PS = 0x800D
    TP2_0_PS = 0x800E
    FT_CAN_PS = 0x800F
    FT_ISO15765_PS = 0x8010

class BaudRate(IntEnum):
    ISO9141_10400 = 10400
    ISO9141_10000 = 10000
    ISO14230_10400 = 10400
    ISO14230_10000 = 10000
    J1850PWM_41600 = 41600
    J1850PWM_83300 = 83300
    J1850VPW_10400 = 10400
    J1850VPW_41600 = 41600
    CAN_125000 = 125000
    CAN_250000 = 250000
    CAN_500000 = 500000
    CAN_33333 = 33333
    CAN_83333 = 83333
    ISO15765_125000 = 125000
    ISO15765_250000 = 250000
    ISO15765_500000 = 500000
    GMUART_8192 = 8192
    GMUART_160 = 160

class PinNumber(IntEnum):
    AUX = 0
    PIN_1 = 1
    PIN_3 = 3
    PIN_6 = 6
    PIN_9 = 9
    PIN_11 = 11
    PIN_12 = 12
    PIN_13 = 13
    PIN_14 = 14
    PIN_15 = 15

class PinVoltage(IntEnum):
    FEPS_VOLTAGE = 18000
    SHORT_TO_GROUND = 0xFFFFFFFE
    VOLTAGE_OFF = 0xFFFFFFFF

class FilterType(IntEnum):
    PASS_FILTER = 0x01
    BLOCK_FILTER = 0x02
    FLOW_CONTROL_FILTER = 0x03

class J2534Err(IntEnum):
    STATUS_NOERROR = 0x00
    ERR_NOT_SUPPORTED = 0x01
    ERR_INVALID_CHANNEL_ID = 0x02
    ERR_INVALID_PROTOCOL_ID = 0x03
    ERR_NULL_PARAMETER = 0x04
    ERR_INVALID_FLAGS = 0x06
    ERR_FAILED = 0x07
    ERR_DEVICE_NOT_CONNECTED = 0x08
    ERR_TIMEOUT = 0x09
    ERR_INVALID_MSG = 0x0A
    ERR_INVALID_TIME_INTERVAL = 0x0B
    ERR_EXCEEDED_LIMIT = 0x0C
    ERR_INVALID_MSG_ID = 0x0D
    ERR_DEVICE_IN_USE = 0x0E
    ERR_INVALID_IOCTL_ID = 0x0F
    ERR_BUFFER_EMPTY = 0x10
    ERR_BUFFER_FULL = 0x11
    ERR_BUFFER_OVERFLOW = 0x12
    ERR_PIN_INVALID = 0x13
    ERR_CHANNEL_IN_USE = 0x14
    ERR_MSG_PROTOCOL_ID = 0x15
    ERR_INVALID_FILTER_ID = 0x16
    ERR_NO_FLOW_CONTROL = 0x17
    ERR_NOT_UNIQUE = 0x18
    ERR_INVALID_BAUDRATE = 0x19
    ERR_DEVICE_ID_INVALID = 0x1A
    ERR_DEVICE_NOT_OPEN = 0x1B
    ERR_NULL_REQUIRED = 0x1C
    ERR_FILTER_TYPE_NOT_SUPPORTED = 0x1D
    ERR_IOCTL_PARAM_ID_NOT_SUPPORTED = 0x1E
    ERR_VOLTAGE_IN_USE = 0x1F
    ERR_PIN_IN_USE = 0x20
    ERR_INIT_FAILED = 0x21
    ERR_OPEN_FAILED = 0x22
    ERR_BUFFER_TOO_SMALL = 0x23
    ERR_LOG_CHAN_NOT_ALLOWED = 0x24
    ERR_SELECT_TYPE_NOT_SUPPORTED = 0x25
    ERR_CONCURRENT_API_CALL = 0x26

    # extra helpers
    ERR_ACCESS_VIOLATION = 0x1000
    ERR_DLL_NOT_LOADED = 0x1001
    ERR_OUT_OF_MEMORY = 0x1999
    ERR_NO_RESPONSE_FROM_MODULE = 0x5001

class Ioctl(IntEnum):
    GET_CONFIG = 0x01
    SET_CONFIG = 0x02
    READ_VBATT = 0x03
    FIVE_BAUD_INIT = 0x04
    FAST_INIT = 0x05
    CLEAR_TX_BUFFER = 0x07
    CLEAR_RX_BUFFER = 0x08
    CLEAR_PERIODIC_MSGS = 0x09
    CLEAR_MSG_FILTERS = 0x0A
    CLEAR_FUNCT_MSG_LOOKUP_TABLE = 0x0B
    ADD_TO_FUNCT_MSG_LOOKUP_TABLE = 0x0C
    DELETE_FROM_FUNCT_MSG_LOOKUP_TABLE = 0x0D
    READ_PROG_VOLTAGE = 0x0E
    BUS_ON = 0x0F
    # vendor / extended
    SW_CAN_HS = 0x8000
    SW_CAN_NS = 0x8001

class GET_DEVICE_INFO_Defines(IntEnum):
    OBDX_UniqueSerial_Part1 = 0x10000001
    OBDX_UniqueSerial_Part2 = 0x10000002
    OBDX_UniqueSerial_Part3 = 0x10000003
    OBDX_UniqueSerial_Part4 = 0x10000004
    SERIAL_NUMBER = 0x00000001
    # ... (omitted mirror list would continue – not used directly in core calls)

# ---------------------------- Structs ----------------------------

class PassThruMsg(ct.Structure):
    _fields_ = [
        ("ProtocolID", UINT32),
        ("RxStatus", UINT32),
        ("TxFlags", UINT32),
        ("Timestamp", UINT32),
        ("DataSize", UINT32),
        ("ExtraDataIndex", UINT32),
        ("Data", UINT8 * MAX_MSG_BYTES),
    ]

    @staticmethod
    def from_bytes(protocol: ProtocolID, tx_flags: TxFlag, data: bytes) -> "PassThruMsg":
        m = PassThruMsg()
        m.ProtocolID = UINT32(int(protocol))
        m.RxStatus = 0
        m.TxFlags = UINT32(int(tx_flags))
        m.Timestamp = 0
        m.ExtraDataIndex = 0
        n = min(len(data), MAX_MSG_BYTES)
        m.DataSize = n
        for i in range(n):
            m.Data[i] = data[i]
        return m

    def get_bytes(self) -> bytes:
        return bytes(self.Data[: self.DataSize])

    def to_string(self, tab: str = "    ") -> str:
        hexdata = "-".join(f"{b:02X}" for b in self.get_bytes())
        return (f"{tab}Protocol: {ProtocolID(self.ProtocolID).name}\n"
                f"{tab}RxStatus: {RxStatus(self.RxStatus)}\n"
                f"{tab}Timestamp: {int(self.Timestamp)}\n"
                f"{tab}ExtraDataIndex: {int(self.ExtraDataIndex)}\n"
                f"{tab}Data: {hexdata}")

class SByteArray(ct.Structure):
    _fields_ = [("NumOfBytes", INT32), ("BytePtr", INTPTR)]

    def __repr__(self) -> str:
        if not self.BytePtr or self.NumOfBytes <= 0:
            return "<SByteArray empty>"
        data = ct.string_at(self.BytePtr, self.NumOfBytes)
        return " ".join(f"{b:02X}" for b in data)

class SConfig(ct.Structure):
    _fields_ = [("Parameter", UINT32), ("Value", UINT16)]

class SConfigList(ct.Structure):
    _fields_ = [("Count", INT32), ("ListPtr", INTPTR)]

class SParam(ct.Structure):
    _fields_ = [("Parameter", UINT32), ("Value", UINT32), ("Supported", UINT32)]

class SParamList(ct.Structure):
    _fields_ = [("Count", INT32), ("ListPtr", INTPTR)]

class SDEVICE(ct.Structure):
    _fields_ = [
        ("DeviceName", ct.c_wchar * 80),
        ("DeviceAvailable", UINT32),
        ("DeviceDLLFWStatus", UINT32),
        ("DeviceConnectMedia", UINT32),
        ("DeviceConnectSpeed", UINT32),
        ("DeviceSignalQuality", UINT32),
        ("DeviceSignalStrength", UINT32),
    ]

class OBDX_DeviceDetails(ct.Structure):
    _fields_ = [
        ("DeviceName", INTPTR),
        ("UniqueSerial", INTPTR),
        ("HardwareVersion", INTPTR),
        ("FirmwareVersion", INTPTR),
        ("ComportNumber", UINT32),
    ]

    def _get_cstr(self, p: INTPTR) -> str:
        if not p:
            return ""
        # read until NUL
        return ct.string_at(p).decode('ascii', errors='ignore')

    def get_device_name(self) -> str:
        return self._get_cstr(self.DeviceName)

    def get_unique_serial(self) -> str:
        return self._get_cstr(self.UniqueSerial)

    def get_hardware_version(self) -> str:
        return self._get_cstr(self.HardwareVersion)

    def get_firmware_version(self) -> str:
        return self._get_cstr(self.FirmwareVersion)

class OBDX_DeviceDetailsList(ct.Structure):
    _fields_ = [("Count", INT32), ("ListPtr", INTPTR)]

    def get_list(self) -> List[OBDX_DeviceDetails]:
        if not self.ListPtr or self.Count <= 0:
            return []
        arr_t = OBDX_DeviceDetails * self.Count
        return list(ct.cast(self.ListPtr, ct.POINTER(arr_t)).contents)

# ---------------------------- Utilities ----------------------------

def hex_to_bytes(s: str) -> bytes:
    s = s.replace("0x", "").replace(" ", "").replace("-", "")
    if len(s) % 2:
        raise ValueError("hex string length must be even")
    return bytes(int(s[i:i+2], 16) for i in range(0, len(s), 2))

def bytes_to_hex(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

def as_list(ptr: INTPTR, count: int, ctype) -> List:
    if not ptr or count <= 0:
        return []
    arr_t = ctype * count
    return list(ct.cast(ptr, ct.POINTER(arr_t)).contents)

# ---------------------------- Data classes ----------------------------

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
    CAN_PS: int = 0
    FT_CAN_PS: int = 0
    FT_ISO15765_PS: int = 0
    GM_UART_PS: int = 0
    ISO14230_PS: int = 0
    ISO15765_PS: int = 0
    ISO9141_PS: int = 0
    SW_CAN_PS: int = 0
    SW_ISO15765_PS: int = 0
    J1850VPW_PS: int = 0

    def __str__(self) -> str:
        return self.Name or "J2534 Device"

# ---------------------------- DLL Wrapper ----------------------------

class J2534DllWrapper:
    """Low-level function binding for a vendor J2534 DLL."""
    def __init__(self):
        self._dll = None

    def load(self, path: str) -> bool:
        try:
            self._dll = ct.WinDLL(path)
        except Exception:
            self._dll = None
            return False

        d = self._dll
        def bind(name, restype=ct.c_int, argtypes=None, required=True):
            try:
                fn = getattr(d, name)
            except AttributeError:
                if required:
                    return None
                return None
            fn.restype = restype
            if argtypes is not None:
                fn.argtypes = argtypes
            setattr(self, name, fn)
            return fn

        # Core J2534-1
        bind("PassThruOpen", restype=ct.c_int, argtypes=[INTPTR, ct.POINTER(UINT32)])
        bind("PassThruClose", restype=ct.c_int, argtypes=[UINT32])
        bind("PassThruConnect", restype=ct.c_int, argtypes=[UINT32, UINT32, UINT32, UINT32, ct.POINTER(UINT32)])
        bind("PassThruDisconnect", restype=ct.c_int, argtypes=[ct.c_int])
        bind("PassThruReadMsgs", restype=ct.c_int, argtypes=[ct.c_int, INTPTR, ct.POINTER(ct.c_int), ct.c_int])
        bind("PassThruWriteMsgs", restype=ct.c_int, argtypes=[ct.c_int, INTPTR, ct.POINTER(ct.c_int), ct.c_int])
        bind("PassThruStartPeriodicMsg", restype=ct.c_int, argtypes=[ct.c_int, INTPTR, ct.POINTER(ct.c_int), ct.c_int])
        bind("PassThruStopPeriodicMsg", restype=ct.c_int, argtypes=[ct.c_int, ct.c_int])
        bind("PassThruStartMsgFilter", restype=ct.c_int, argtypes=[ct.c_int, ct.c_int, INTPTR, INTPTR, INTPTR, ct.POINTER(ct.c_int)])
        bind("PassThruStopMsgFilter", restype=ct.c_int, argtypes=[ct.c_int, ct.c_int])
        bind("PassThruSetProgrammingVoltage", restype=ct.c_int, argtypes=[ct.c_int, UINT32, UINT32])
        bind("PassThruReadVersion", restype=ct.c_int, argtypes=[ct.c_int, INTPTR, INTPTR, INTPTR])
        bind("PassThruGetLastError", restype=ct.c_int, argtypes=[INTPTR])
        bind("PassThruIoctl", restype=ct.c_int, argtypes=[ct.c_int, ct.c_int, INTPTR, INTPTR])

        # Optional / J2534-2 / v5
        self.PassThruScanForDevices = getattr(d, "PassThruScanForDevices", None)
        if self.PassThruScanForDevices:
            self.PassThruScanForDevices.restype = ct.c_int
            self.PassThruScanForDevices.argtypes = [ct.POINTER(ct.c_int)]

        self.PassThruGetNextDevice = getattr(d, "PassThruGetNextDevice", None)
        if self.PassThruGetNextDevice:
            self.PassThruGetNextDevice.restype = ct.c_int
            self.PassThruGetNextDevice.argtypes = [ct.POINTER(SDEVICE)]

        self.PassThruQueueMsgs = getattr(d, "PassThruQueueMsgs", None)
        if self.PassThruQueueMsgs:
            self.PassThruQueueMsgs.restype = ct.c_int
            self.PassThruQueueMsgs.argtypes = [ct.c_int, INTPTR, ct.POINTER(ct.c_int)]

        self.PassThruLogicalConnect = getattr(d, "PassThruLogicalConnect", None)
        if self.PassThruLogicalConnect:
            self.PassThruLogicalConnect.restype = ct.c_int
            self.PassThruLogicalConnect.argtypes = [ct.c_int, UINT32, UINT32, ct.POINTER(INTPTR), ct.POINTER(ct.c_int)]

        self.PassThruLogicalDisconnect = getattr(d, "PassThruLogicalDisconnect", None)
        if self.PassThruLogicalDisconnect:
            self.PassThruLogicalDisconnect.restype = ct.c_int
            self.PassThruLogicalDisconnect.argtypes = [ct.c_int]

        self.PassThruSelect = getattr(d, "PassThruSelect", None)
        if self.PassThruSelect:
            self.PassThruSelect.restype = ct.c_int
            self.PassThruSelect.argtypes = [ct.POINTER(INTPTR), UINT32, UINT32]

        return True

    def free(self) -> bool:
        # nothing to free explicitly; rely on GC
        self._dll = None
        return True

# ---------------------------- High-level classes ----------------------------

class J2534Functions:
    def __init__(self):
        self._ConnectedDevice: Optional[J2534Device] = None
        self._J2534DllWrapper: Optional[J2534DllWrapper] = None
        self._IsDLLLoaded: bool = False

    def __str__(self):
        return "Copyright Envyous Customs - J2534 API DLL - For Authorised Applications Only."

    @property
    def IsDLLLoaded(self) -> bool:
        return self._IsDLLLoaded

    @property
    def DeviceName(self) -> str:
        return self._ConnectedDevice.Name if self._ConnectedDevice else ""

    def LoadLibrary(self, device: J2534Device) -> bool:
        try:
            self._ConnectedDevice = device
            self._J2534DllWrapper = J2534DllWrapper()
            self._IsDLLLoaded = self._J2534DllWrapper.load(device.FunctionLibrary)
            return self._IsDLLLoaded
        except Exception:
            self._IsDLLLoaded = False
            return False

    def FreeLibrary(self) -> bool:
        self._IsDLLLoaded = False
        if self._J2534DllWrapper:
            return self._J2534DllWrapper.free()
        return True

    # ---- PassThru* methods (error-wrapped) ----

    def PassThruOpen(self, name: INTPTR, deviceId_ref: ct.POINTER(UINT32)) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruOpen(name, deviceId_ref)
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruClose(self, deviceId: int) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruClose(UINT32(deviceId))
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruConnect(self, deviceId: int, protocolId: ProtocolID, flags: ConnectFlag, baudRate: BaudRate, channelId_ref: ct.POINTER(UINT32)) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruConnect(UINT32(deviceId), UINT32(int(protocolId)), UINT32(int(flags)), UINT32(int(baudRate)), channelId_ref)
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruDisconnect(self, channelId: int) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruDisconnect(int(channelId))
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruReadMsgs(self, channelId: int, msgs_ptr: INTPTR, numMsgs_ref: ct.POINTER(ct.c_int), timeout_ms: int) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruReadMsgs(int(channelId), msgs_ptr, numMsgs_ref, int(timeout_ms))
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruWriteMsgs(self, channelId: int, msgs_ptr: INTPTR, numMsgs_ref: ct.POINTER(ct.c_int), timeout_ms: int) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruWriteMsgs(int(channelId), msgs_ptr, numMsgs_ref, int(timeout_ms))
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruStartPeriodicMsg(self, channelId: int, msg_ptr: INTPTR, msgId_ref: ct.POINTER(ct.c_int), interval_ms: int) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruStartPeriodicMsg(int(channelId), msg_ptr, msgId_ref, int(interval_ms))
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruStopPeriodicMsg(self, channelId: int, msgId: int) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruStopPeriodicMsg(int(channelId), int(msgId))
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruStartMsgFilter(self, channelId: int, filterType: FilterType, maskMsg_ptr: INTPTR, patternMsg_ptr: INTPTR, flowControlMsg_ptr: INTPTR, filterId_ref: ct.POINTER(ct.c_int)) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruStartMsgFilter(int(channelId), int(filterType), maskMsg_ptr, patternMsg_ptr, flowControlMsg_ptr, filterId_ref)
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruStopMsgFilter(self, channelId: int, filterId: int) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruStopMsgFilter(int(channelId), int(filterId))
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruSetProgrammingVoltage(self, deviceId: int, pinNumber: PinNumber, voltage: int) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruSetProgrammingVoltage(int(deviceId), UINT32(int(pinNumber)), UINT32(int(voltage)))
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruReadVersion(self, deviceId: int, firmware_ptr: INTPTR, dll_ptr: INTPTR, api_ptr: INTPTR) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruReadVersion(int(deviceId), firmware_ptr, dll_ptr, api_ptr)
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruGetLastError(self, errorDescription_ptr: INTPTR) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruGetLastError(errorDescription_ptr)
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruIoctl(self, channelId: int, ioctlID: Ioctl, input_ptr: INTPTR, output_ptr: INTPTR) -> J2534Err:
        try:
            if not self.IsDLLLoaded: return J2534Err.ERR_DLL_NOT_LOADED
            rc = self._J2534DllWrapper.PassThruIoctl(int(channelId), int(ioctlID), input_ptr, output_ptr)
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    # ---- Optional v5-ish ----

    def PassThruScanForDevices(self, DeviceCount_ref: ct.POINTER(ct.c_int)) -> J2534Err:
        try:
            if not self.IsDLLLoaded or not getattr(self._J2534DllWrapper, "PassThruScanForDevices", None):
                return J2534Err.ERR_NOT_SUPPORTED
            rc = self._J2534DllWrapper.PassThruScanForDevices(DeviceCount_ref)
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruGetNextDevice(self, Device_ref: ct.POINTER(SDEVICE)) -> J2534Err:
        try:
            if not self.IsDLLLoaded or not getattr(self._J2534DllWrapper, "PassThruGetNextDevice", None):
                return J2534Err.ERR_NOT_SUPPORTED
            rc = self._J2534DllWrapper.PassThruGetNextDevice(Device_ref)
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruQueueMsgs(self, channelId: int, msgs_ptr: INTPTR, numMsgs_ref: ct.POINTER(ct.c_int)) -> J2534Err:
        try:
            if not self.IsDLLLoaded or not getattr(self._J2534DllWrapper, "PassThruQueueMsgs", None):
                return J2534Err.ERR_NOT_SUPPORTED
            rc = self._J2534DllWrapper.PassThruQueueMsgs(int(channelId), msgs_ptr, numMsgs_ref)
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruLogicalConnect(self, PhysChannelId: int, protocolId: ProtocolID, flags: ConnectFlag, ChannelDescriptor_ref: ct.POINTER(INTPTR), LogicalChannelId_ref: ct.POINTER(ct.c_int)) -> J2534Err:
        try:
            if not self.IsDLLLoaded or not getattr(self._J2534DllWrapper, "PassThruLogicalConnect", None):
                return J2534Err.ERR_NOT_SUPPORTED
            rc = self._J2534DllWrapper.PassThruLogicalConnect(int(PhysChannelId), UINT32(int(protocolId)), UINT32(int(flags)), ChannelDescriptor_ref, LogicalChannelId_ref)
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruLogicalDisconnect(self, LogicalChannelId: int) -> J2534Err:
        try:
            if not self.IsDLLLoaded or not getattr(self._J2534DllWrapper, "PassThruLogicalDisconnect", None):
                return J2534Err.ERR_NOT_SUPPORTED
            rc = self._J2534DllWrapper.PassThruLogicalDisconnect(int(LogicalChannelId))
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

    def PassThruSelect(self, ChannelSetPtr_ref: ct.POINTER(INTPTR), SelectType: int, Timeout: int) -> J2534Err:
        try:
            if not self.IsDLLLoaded or not getattr(self._J2534DllWrapper, "PassThruSelect", None):
                return J2534Err.ERR_NOT_SUPPORTED
            rc = self._J2534DllWrapper.PassThruSelect(ChannelSetPtr_ref, UINT32(SelectType), UINT32(Timeout))
            return J2534Err(rc)
        except Exception:
            return J2534Err.ERR_ACCESS_VIOLATION

# Extended functions mirroring the C# class
class J2534FunctionsExtended(J2534Functions):
    def GetConfig(self, channelId: int, config: List[SConfig]) -> Tuple[J2534Err, List[SConfig]]:
        try:
            count = len(config)
            arr_t = SConfig * count
            arr = arr_t(*config)
            s = SConfigList(Count=count, ListPtr=ct.cast(ct.pointer(arr), INTPTR))
            input_ptr = ct.pointer(s)
            # Output is unused per C#
            rc = super().PassThruIoctl(channelId, Ioctl.GET_CONFIG, ct.cast(input_ptr, INTPTR), INTPTR(0))
            # After GET_CONFIG, vendors often write back updated values into the same buffer.
            got = as_list(s.ListPtr, s.Count, SConfig)
            return J2534Err(rc), got
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY, []

    def SetConfig(self, channelId: int, config: List[SConfig]) -> J2534Err:
        try:
            count = len(config)
            arr_t = SConfig * count
            arr = arr_t(*config)
            s = SConfigList(Count=count, ListPtr=ct.cast(ct.pointer(arr), INTPTR))
            input_ptr = ct.pointer(s)
            rc = super().PassThruIoctl(channelId, Ioctl.SET_CONFIG, ct.cast(input_ptr, INTPTR), INTPTR(0))
            return J2534Err(rc)
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY

    def SW_CAN_BusSpeed(self, ChannelID: int, Option: int) -> J2534Err:
        try:
            if Option == 0:
                return super().PassThruIoctl(ChannelID, Ioctl.SW_CAN_HS, INTPTR(0), INTPTR(0))
            else:
                return super().PassThruIoctl(ChannelID, Ioctl.SW_CAN_NS, INTPTR(0), INTPTR(0))
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY

    def ReadBatteryVoltage(self, deviceId: int) -> Tuple[J2534Err, Optional[int]]:
        try:
            outbuf = ct.create_string_buffer(8)
            rc = super().PassThruIoctl(deviceId, Ioctl.READ_VBATT, INTPTR(0), ct.cast(outbuf, INTPTR))
            val = ct.c_int.from_buffer(outbuf).value if rc == J2534Err.STATUS_NOERROR else None
            return J2534Err(rc), val
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY, None

    def ReadProgrammingVoltage(self, deviceId: int) -> Tuple[J2534Err, Optional[int]]:
        try:
            outbuf = ct.create_string_buffer(8)
            rc = super().PassThruIoctl(deviceId, Ioctl.READ_PROG_VOLTAGE, INTPTR(0), ct.cast(outbuf, INTPTR))
            val = ct.c_int.from_buffer(outbuf).value if rc == J2534Err.STATUS_NOERROR else None
            return J2534Err(rc), val
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY, None

    def FiveBaudInit(self, channelId: int, targetAddress: int) -> Tuple[J2534Err, Optional[int], Optional[int]]:
        """Perform 5-baud init (K-Line). Returns (err, kw1, kw2)."""
        try:
            # input: one byte target address
            in_buf = (UINT8 * 1)(targetAddress & 0xFF)
            in_arr = SByteArray(NumOfBytes=1, BytePtr=ct.cast(in_buf, INTPTR))
            out_buf = (UINT8 * 2)()
            out_arr = SByteArray(NumOfBytes=2, BytePtr=ct.cast(out_buf, INTPTR))

            rc = super().PassThruIoctl(channelId, Ioctl.FIVE_BAUD_INIT, ct.byref(in_arr), ct.byref(out_arr))
            if rc != J2534Err.STATUS_NOERROR:
                return J2534Err(rc), None, None
            return J2534Err(rc), int(out_buf[0]), int(out_buf[1])
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY, None, None

    def FastInit(self, channelId: int, txMsg: PassThruMsg) -> Tuple[J2534Err, Optional[PassThruMsg]]:
        try:
            rx = PassThruMsg()
            rc = super().PassThruIoctl(channelId, Ioctl.FAST_INIT, ct.byref(txMsg), ct.byref(rx))
            if rc != J2534Err.STATUS_NOERROR:
                return J2534Err(rc), None
            return J2534Err(rc), rx
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY, None

    def ClearTxBuffer(self, channelId: int) -> J2534Err:
        try:
            return super().PassThruIoctl(channelId, Ioctl.CLEAR_TX_BUFFER, INTPTR(0), INTPTR(0))
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY

    def ClearRxBuffer(self, channelId: int) -> J2534Err:
        try:
            return super().PassThruIoctl(channelId, Ioctl.CLEAR_RX_BUFFER, INTPTR(0), INTPTR(0))
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY

    def ClearPeriodicMsgs(self, channelId: int) -> J2534Err:
        try:
            return super().PassThruIoctl(channelId, Ioctl.CLEAR_PERIODIC_MSGS, INTPTR(0), INTPTR(0))
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY

    def ClearMsgFilters(self, channelId: int) -> J2534Err:
        try:
            return super().PassThruIoctl(channelId, Ioctl.CLEAR_MSG_FILTERS, INTPTR(0), INTPTR(0))
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY

    def ClearFunctMsgLookupTable(self, channelId: int) -> J2534Err:
        try:
            return super().PassThruIoctl(channelId, Ioctl.CLEAR_FUNCT_MSG_LOOKUP_TABLE, INTPTR(0), INTPTR(0))
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY

    def AddToFunctMsgLookupTable(self, channelId: int) -> J2534Err:
        try:
            return super().PassThruIoctl(channelId, Ioctl.ADD_TO_FUNCT_MSG_LOOKUP_TABLE, INTPTR(0), INTPTR(0))
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY

    def DeleteFromFunctMsgLookupTable(self, channelId: int) -> J2534Err:
        try:
            return super().PassThruIoctl(channelId, Ioctl.DELETE_FROM_FUNCT_MSG_LOOKUP_TABLE, INTPTR(0), INTPTR(0))
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY

    def ReadAllMessages(self, channelId: int, numMsgs: int, timeout_ms: int, readUntilTimeout: bool = True) -> Tuple[J2534Err, List[PassThruMsg]]:
        messages: List[PassThruMsg] = []
        try:
            arr_t = PassThruMsg * numMsgs
            rx_arr = arr_t()
            count = ct.c_int(numMsgs)

            status = super().PassThruReadMsgs(channelId, ct.cast(ct.pointer(rx_arr), INTPTR), ct.byref(count), timeout_ms)
            if status == J2534Err.STATUS_NOERROR:
                messages.extend(rx_arr[:max(0, count.value)])
                if not readUntilTimeout:
                    return status, messages
            else:
                messages.extend(rx_arr[:max(0, count.value)])
                return status, messages

            # keep reading until not STATUS_NOERROR
            while True:
                count = ct.c_int(numMsgs)
                status2 = super().PassThruReadMsgs(channelId, ct.cast(ct.pointer(rx_arr), INTPTR), ct.byref(count), timeout_ms)
                if status2 != J2534Err.STATUS_NOERROR:
                    break
                messages.extend(rx_arr[:max(0, count.value)])

            return J2534Err.STATUS_NOERROR, messages
        except MemoryError:
            return J2534Err.ERR_OUT_OF_MEMORY, messages

# ---------------------------- Exception ----------------------------

class J2534Exception(Exception):
    def __init__(self, error: J2534Err):
        super().__init__(str(error))
        self.Error = error

# ---------------------------- Convenience helpers ----------------------------

def build_can_msg(arb_id: int, data: bytes | str, protocol: ProtocolID = ProtocolID.CAN, extended: bool = False, tx_flags: TxFlag = TxFlag.NONE) -> PassThruMsg:
    if isinstance(data, str):
        payload = hex_to_bytes(data)
    else:
        payload = data
    header = int(arb_id).to_bytes(4, 'little', signed=False)
    frame = header + payload
    flags = tx_flags | (TxFlag.CAN_29BIT_ID if extended else TxFlag(0))
    return PassThruMsg.from_bytes(protocol, flags, frame)

# ---------------------------- Self-test ----------------------------

if __name__ == "__main__":
    import os
    dll = os.environ.get("J2534_LIB")
    if not dll:
        print("Set J2534_LIB env var to your vendor DLL to run this demo.")
        raise SystemExit(0)

    dev = J2534Device(Name="ENV Device", FunctionLibrary=dll)
    api = J2534FunctionsExtended()
    assert api.LoadLibrary(dev), "DLL load failed"

    device_id = UINT32(0)
    err = api.PassThruOpen(INTPTR(0), ct.byref(device_id))
    print("Open:", err, device_id.value)
    if err != J2534Err.STATUS_NOERROR:
        buf = ct.create_string_buffer(256)
        api.PassThruGetLastError(ct.cast(buf, INTPTR))
        print("LastError:", buf.value.decode(errors='ignore'))
        raise SystemExit(1)

    chan = UINT32(0)
    err = api.PassThruConnect(device_id.value, ProtocolID.ISO15765, ConnectFlag.NONE, BaudRate.CAN_500000, ct.byref(chan))
    print("Connect:", err, chan.value)

    if err == J2534Err.STATUS_NOERROR:
        msg = build_can_msg(0x7E0, "22 D1 00", protocol=ProtocolID.CAN)
        array_t = PassThruMsg * 1
        arr = array_t(msg)
        n = ct.c_int(1)
        err = api.PassThruWriteMsgs(chan.value, ct.cast(ct.pointer(arr), INTPTR), ct.byref(n), 50)
        print("Write:", err, "count=", n.value)

        # read
        rx_arr_t = PassThruMsg * 16
        rx_arr = rx_arr_t()
        n = ct.c_int(16)
        err = api.PassThruReadMsgs(chan.value, ct.cast(ct.pointer(rx_arr), INTPTR), ct.byref(n), 50)
        print("Read:", err, "count=", n.value)
        for i in range(max(0, n.value)):
            print(rx_arr[i].to_string("  "))

        api.PassThruDisconnect(chan.value)

    api.PassThruClose(device_id.value)
    api.FreeLibrary()
