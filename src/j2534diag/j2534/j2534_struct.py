from __future__ import annotations
import ctypes as ct
from typing import Optional, List
from ..j2534.j2534 import (
    J2534Device, J2534FunctionsExtended, J2534Err,
    ProtocolID, ConnectFlag, BaudRate, FilterType,
    PassThruMsg, TxFlag, Ioctl, INTPTR, UINT32
)
from ..j2534.j2534_device_finder import find_installed_j2534_dlls

# -----------------------------------------
# C#-style struct wrapper (Pythonized)
# -----------------------------------------

class J2534_Port:
    """
    Mirrors the spirit of your C# struct:
        class J2534_Struct { public J2534FunctionsExtended Functions; public J2534Device LoadedDevice; }
    and holds the IDs (DeviceID, ChannelID, FilterID).
    """
    def __init__(self):
        self.Functions = J2534FunctionsExtended()
        self.LoadedDevice = J2534Device()
        self.DeviceID: int = 0
        self.ChannelID: int = 0
        self.FilterID: int = -1

    # ------------ lifecycle ------------
    def load_device(self, dev: J2534Device) -> None:
        self.LoadedDevice = dev
        ok = self.Functions.LoadLibrary(dev)
        if not ok:
            raise RuntimeError(f"Failed to load DLL: {dev.FunctionLibrary}")

    def open(self) -> None:
        dev_id = UINT32(0)
        err = self.Functions.PassThruOpen(INTPTR(0), ct.byref(dev_id))
        if not status_ok(err):
            self._raise_with_last_error("PassThruOpen", err)
        self.DeviceID = int(dev_id.value)

    def connect_can(self, baud: BaudRate = BaudRate.CAN_500000, flags: ConnectFlag = ConnectFlag.NONE) -> None:
        ch = UINT32(0)
        err = self.Functions.PassThruConnect(self.DeviceID, ProtocolID.CAN, flags, baud, ct.byref(ch))
        if not status_ok(err):
            self._raise_with_last_error("PassThruConnect", err)
        self.ChannelID = int(ch.value)

    def set_pass_filter_for_7E8(self, extended: bool = False) -> None:
        """
        Only pass incoming frames from 0x7E8 (ECU response) to the application.
        Mask: 0x7FF (11-bit); Pattern: 0x7E8
        For 29-bit, supply an appropriate mask (e.g., 0x1FFFFFFF) and set TxFlag.CAN_29BIT_ID on the filter msgs.
        """
        mask = make_filter_msg_arb_id(0x7FF if not extended else 0x1FFFFFFF, extended=extended)
        patt = make_filter_msg_arb_id(0x7E8, extended=extended)

        filt_id = ct.c_int(0)
        err = self.Functions.PassThruStartMsgFilter(
            self.ChannelID,
            FilterType.PASS_FILTER,
            ct.byref(mask),
            ct.byref(patt),
            INTPTR(0),                # flowControlMsg (unused for PASS_FILTER)
            ct.byref(filt_id)
        )
        if not status_ok(err):
            self._raise_with_last_error("PassThruStartMsgFilter", err)
        self.FilterID = int(filt_id.value)

    def write(self, msg: PassThruMsg, timeout_ms: int = 50) -> int:
        arr_t = PassThruMsg * 1
        arr = arr_t(msg)
        n = ct.c_int(1)
        err = self.Functions.PassThruWriteMsgs(self.ChannelID, ct.cast(ct.pointer(arr), INTPTR), ct.byref(n), timeout_ms)
        if not status_ok(err):
            self._raise_with_last_error("PassThruWriteMsgs", err)
        return int(n.value)

    def read(self, max_msgs: int = 32, timeout_ms: int = 100) -> List[PassThruMsg]:
        arr_t = PassThruMsg * max_msgs
        arr = arr_t()
        n = ct.c_int(max_msgs)
        err = self.Functions.PassThruReadMsgs(self.ChannelID, ct.cast(ct.pointer(arr), INTPTR), ct.byref(n), timeout_ms)
        # it’s normal to get ERR_TIMEOUT with zero messages; treat that as “no data”
        if err not in (J2534Err.STATUS_NOERROR, J2534Err.ERR_TIMEOUT):
            self._raise_with_last_error("PassThruReadMsgs", err)
        return list(arr[: max(0, int(n.value))])

    def clear_filter(self) -> None:
        if self.FilterID >= 0:
            self.Functions.PassThruStopMsgFilter(self.ChannelID, self.FilterID)
            self.FilterID = -1

    def disconnect(self) -> None:
        if self.ChannelID:
            self.Functions.PassThruDisconnect(self.ChannelID)
            self.ChannelID = 0

    def close(self) -> None:
        if self.DeviceID:
            self.Functions.PassThruClose(self.DeviceID)
            self.DeviceID = 0
        self.Functions.FreeLibrary()

    # ------------ helpers ------------
    def _raise_with_last_error(self, where: str, err: J2534Err):
        buf = ct.create_string_buffer(256)
        self.Functions.PassThruGetLastError(ct.cast(buf, INTPTR))
        msg = buf.value.decode("ascii", errors="ignore")
        raise RuntimeError(f"{where} failed: {err.name} ({int(err):#x}) - {msg}")
