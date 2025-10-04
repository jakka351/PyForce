from __future__ import annotations
import ctypes as ct
from typing import Optional, List

from j2534 import (
    J2534Device, J2534FunctionsExtended, J2534Err,
    ProtocolID, ConnectFlag, BaudRate, FilterType,
    PassThruMsg, TxFlag, Ioctl, INTPTR, UINT32
)
from j2534_device_finder import find_installed_j2534_dlls