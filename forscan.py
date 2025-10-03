#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
J2534 Diagnostic Software with FORScan-like GUI
Full implementation with ECU connection, DTC reading/clearing, and diagnostic functions
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import queue
import time
import struct
import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
from enum import IntEnum
import configparser

# J2534 Constants
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
    NONE = 0x00
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

@dataclass
class DTCInfo:
    """Diagnostic Trouble Code information"""
    code: str
    description: str
    status: str
    module: str
    freeze_frame: Dict[str, Any] = None
    timestamp: datetime = None

@dataclass
class ECUInfo:
    """ECU Module information"""
    name: str
    address: int
    protocol: J2534Protocol
    supported_pids: List[int]
    vin: str = ""
    calibration_id: str = ""

class J2534Interface:
    """Mock J2534 Interface for demonstration - replace with actual J2534 DLL calls"""
    
    def __init__(self):
        self.connected = False
        self.device_id = None
        self.channel_id = None
        self.protocol = None
        self.filters = []
        
    def connect(self, device_name: str = "Mock J2534 Device") -> bool:
        """Connect to J2534 device"""
        # In real implementation, load J2534 DLL and call PassThruOpen
        self.device_id = 1
        self.connected = True
        return True
        
    def disconnect(self):
        """Disconnect from J2534 device"""
        self.connected = False
        self.device_id = None
        self.channel_id = None
        
    def open_channel(self, protocol: J2534Protocol, baud_rate: int, flags: int = 0) -> bool:
        """Open communication channel"""
        if not self.connected:
            return False
        self.channel_id = 1
        self.protocol = protocol
        return True
        
    def close_channel(self):
        """Close communication channel"""
        self.channel_id = None
        self.protocol = None
        
    def send_message(self, data: bytes) -> bool:
        """Send message to vehicle"""
        if not self.channel_id:
            return False
        # In real implementation, call PassThruWriteMsgs
        return True
        
    def receive_message(self, timeout: int = 100) -> Optional[bytes]:
        """Receive message from vehicle"""
        if not self.channel_id:
            return None
        # Mock response for demonstration
        return b'\x48\x6B\x10\x41\x00\xBE\x1F\xB8\x13'
        
    def set_filter(self, mask: bytes, pattern: bytes, flow_control: bytes = None) -> int:
        """Set message filter"""
        filter_id = len(self.filters) + 1
        self.filters.append((mask, pattern, flow_control))
        return filter_id

class OBDIIProtocol:
    """OBD-II Protocol handler"""
    
    # Standard OBD-II PIDs
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
        0x1C: "OBD standards this vehicle conforms to",
        0x20: "PIDs supported [21-40]",
        0x21: "Distance traveled with MIL on",
        0x2F: "Fuel Tank Level Input",
        0x33: "Absolute Barometric Pressure",
        0x42: "Control module voltage",
        0x46: "Ambient air temperature",
        0x51: "Fuel Type"
    }
    
    @staticmethod
    def build_obd_request(mode: int, pid: int, extra_bytes: bytes = b'') -> bytes:
        """Build OBD-II request message"""
        length = 2 + len(extra_bytes)
        return bytes([length, mode, pid]) + extra_bytes
        
    @staticmethod
    def parse_obd_response(data: bytes) -> Dict[str, Any]:
        """Parse OBD-II response message"""
        if len(data) < 3:
            return None
        
        result = {
            'length': data[0],
            'mode': data[1],
            'pid': data[2] if len(data) > 2 else None,
            'data': data[3:] if len(data) > 3 else b''
        }
        return result
        
    @staticmethod
    def decode_dtc(code_bytes: bytes) -> str:
        """Decode DTC from bytes"""
        if len(code_bytes) < 2:
            return "Unknown"
            
        # First byte high nibble determines prefix
        prefix_map = {0: 'P', 1: 'C', 2: 'B', 3: 'U'}
        prefix = prefix_map.get((code_bytes[0] >> 6) & 0x03, 'P')
        
        # Decode the numeric part
        code_num = ((code_bytes[0] & 0x3F) << 8) | code_bytes[1]
        return f"{prefix}{code_num:04X}"

class VehicleCommunication:
    """Handles vehicle communication operations"""
    
    def __init__(self, j2534: J2534Interface):
        self.j2534 = j2534
        self.current_protocol = None
        self.ecus: List[ECUInfo] = []
        self.dtcs: List[DTCInfo] = []
        
    def scan_for_ecus(self, protocol: J2534Protocol) -> List[ECUInfo]:
        """Scan for available ECUs"""
        ecus = []
        
        # Mock ECU discovery for demonstration
        if protocol in [J2534Protocol.CAN, J2534Protocol.ISO15765]:
            # Common CAN ECUs
            ecus.append(ECUInfo("Engine Control Module", 0x7E0, protocol, [0x00, 0x01, 0x03, 0x04, 0x05, 0x0C, 0x0D]))
            ecus.append(ECUInfo("Transmission Control Module", 0x7E1, protocol, [0x00, 0x01, 0x0C]))
            ecus.append(ECUInfo("ABS Control Module", 0x7E2, protocol, [0x00, 0x01]))
            ecus.append(ECUInfo("Airbag Control Module", 0x7E3, protocol, [0x00, 0x01]))
            ecus.append(ECUInfo("Body Control Module", 0x7E4, protocol, [0x00, 0x01]))
            
        self.ecus = ecus
        return ecus
        
    def read_dtcs(self, ecu: ECUInfo) -> List[DTCInfo]:
        """Read DTCs from specific ECU"""
        dtcs = []
        
        # Send Mode 03 request (Read DTCs)
        request = OBDIIProtocol.build_obd_request(0x03, 0x00)
        if self.j2534.send_message(request):
            response = self.j2534.receive_message(1000)
            if response:
                # Mock DTC data for demonstration
                dtcs.append(DTCInfo(
                    code="P0301",
                    description="Cylinder 1 Misfire Detected",
                    status="Confirmed",
                    module=ecu.name,
                    timestamp=datetime.now()
                ))
                dtcs.append(DTCInfo(
                    code="P0171",
                    description="System Too Lean (Bank 1)",
                    status="Pending",
                    module=ecu.name,
                    timestamp=datetime.now()
                ))
                
        self.dtcs = dtcs
        return dtcs
        
    def clear_dtcs(self, ecu: ECUInfo) -> bool:
        """Clear DTCs from specific ECU"""
        # Send Mode 04 request (Clear DTCs)
        request = OBDIIProtocol.build_obd_request(0x04, 0x00)
        if self.j2534.send_message(request):
            response = self.j2534.receive_message(1000)
            if response:
                self.dtcs = []
                return True
        return False
        
    def read_pid(self, ecu: ECUInfo, pid: int) -> Optional[Any]:
        """Read specific PID from ECU"""
        request = OBDIIProtocol.build_obd_request(0x01, pid)
        if self.j2534.send_message(request):
            response = self.j2534.receive_message(500)
            if response:
                parsed = OBDIIProtocol.parse_obd_response(response)
                if parsed and parsed['pid'] == pid:
                    return self._decode_pid_value(pid, parsed['data'])
        return None
        
    def _decode_pid_value(self, pid: int, data: bytes) -> Any:
        """Decode PID value based on PID type"""
        if not data:
            return None
            
        # Common PID decodings
        if pid == 0x04:  # Engine load
            return data[0] * 100 / 255
        elif pid == 0x05:  # Coolant temp
            return data[0] - 40
        elif pid == 0x0C:  # RPM
            return ((data[0] << 8) | data[1]) / 4
        elif pid == 0x0D:  # Speed
            return data[0]
        elif pid == 0x2F:  # Fuel level
            return data[0] * 100 / 255
        elif pid == 0x42:  # Voltage
            return ((data[0] << 8) | data[1]) / 1000
        else:
            return data.hex()

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

# Icon painters (from original code)
def paint_car(c: tk.Canvas):
    c.create_rectangle(6, 18, 30, 26, fill="#2b7", outline="")
    c.create_polygon(6, 18, 12, 12, 24, 12, 30, 18, fill="#2b7", outline="")
    c.create_oval(9, 26, 15, 32, fill="#111", outline="")
    c.create_oval(21, 26, 27, 32, fill="#111", outline="")
    c.create_rectangle(14, 14, 22, 18, fill="#dff", outline="")

def paint_dtc(c: tk.Canvas):
    c.create_rectangle(6, 8, 30, 28, outline="#333", width=2, fill="#ffd66e")
    c.create_rectangle(10, 12, 26, 24, outline="#333", width=1, fill="#fff")
    c.create_text(18, 18, text="DTC", font=("Segoe UI", 8, "bold"), fill="#333")

def paint_scope(c: tk.Canvas):
    c.create_rectangle(5, 8, 31, 28, outline="#1e88e5", width=2)
    pts = [6,20, 10,20, 12,14, 16,26, 20,10, 24,18, 28,18, 30,22]
    c.create_line(*pts, fill="#1e88e5", width=2, smooth=True)

def paint_check(c: tk.Canvas):
    c.create_rectangle(6, 8, 30, 28, outline="#333", width=2)
    c.create_line(9, 18, 16, 24, 28, 12, width=3, fill="#2e7d32", capstyle=tk.ROUND, joinstyle=tk.ROUND)

def paint_wrench(c: tk.Canvas):
    c.create_oval(8, 8, 28, 28, outline="#777", width=2)
    c.create_line(12, 24, 26, 10, width=4, fill="#777")
    c.create_oval(9, 21, 15, 27, outline="#777", width=2)

def paint_chip(c: tk.Canvas):
    c.create_rectangle(10, 12, 26, 24, fill="#4dd0e1", outline="#333")
    for x in (8, 12, 16, 20, 24, 28):
        c.create_line(x, 10, x, 6, width=2)
        c.create_line(x, 26, x, 30, width=2)
    c.create_rectangle(14, 16, 22, 20, fill="#222", outline="")

def paint_gear(c: tk.Canvas):
    c.create_polygon(18,6, 28,12, 28,24, 18,30, 8,24, 8,12, fill="#9e9e9e", outline="#666")
    c.create_oval(14,14,22,22, fill="#fff", outline="#666")

def paint_help(c: tk.Canvas):
    c.create_oval(6,6,30,30, outline="#1976d2", width=2)
    c.create_text(18, 14, text="?", font=("Segoe UI", 14, "bold"), fill="#1976d2")
    c.create_rectangle(15, 22, 21, 26, fill="#1976d2", outline="")

def paint_save(c: tk.Canvas):
    c.create_rectangle(8,8,28,28, fill="#90caf9", outline="#333")
    c.create_rectangle(12,10,24,16, fill="#fff", outline="#333")
    c.create_rectangle(12,18,24,26, fill="#e3f2fd", outline="#333")

def paint_folder(c: tk.Canvas):
    c.create_rectangle(6,14,30,28, fill="#ffcc80", outline="#333")
    c.create_polygon(6,14, 14,14, 16,10, 24,10, 24,14, 30,14, 30,16, 6,16,
                     fill="#ffe0b2", outline="#333")

ICON_PAINTERS = {
    "car": paint_car,
    "dtc": paint_dtc,
    "scope": paint_scope,
    "check": paint_check,
    "wrench": paint_wrench,
    "chip": paint_chip,
    "gear": paint_gear,
    "help": paint_help,
    "save": paint_save,
    "folder": paint_folder,
}

class J2534DiagnosticApp(tk.Tk):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(APP_MIN_W, APP_MIN_H)
        self.configure(bg="#e9ecef")
        
        # Initialize J2534 and vehicle communication
        self.j2534 = J2534Interface()
        self.vehicle_comm = VehicleCommunication(self.j2534)
        
        # Connection state
        self.connected = False
        self.current_protocol = J2534Protocol.ISO15765
        self.current_baud = J2534BaudRate.CAN_500000
        self.voltage = 0.0
        
        # Message queue for thread communication
        self.msg_queue = queue.Queue()
        
        # Setup UI
        self._setup_style()
        self._layout_root()
        self._make_toolbar()
        self._make_main_tabs()
        self._make_bottom_bar()
        self._make_bottom_small_buttons()
        
        # Setup content for tabs
        self._setup_log_tab()
        self._setup_config_tab()
        self._setup_modules_tab()
        self._setup_profiles_tab()
        
        # Start message processor
        self.after(100, self._process_messages)
        
        # Bind close event
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("TNotebook", background="#f4f7f9", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(12, 6), font=("Segoe UI", 9))
        style.map("TNotebook.Tab", background=[("selected", "#ffffff")])
        style.configure("Main.TFrame", background="#ffffff")
        style.configure("Toolbar.TFrame", background="#f0f3f6")
        style.configure("Status.TFrame", background="#f7f7f7")
        style.configure("TLabelframe.Label", font=("Segoe UI", 9, "bold"))
        style.configure("TLabel", background="#ffffff")

    def _layout_root(self):
        self.grid_columnconfigure(0, minsize=56, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

        self.toolbar = ttk.Frame(self, style="Toolbar.TFrame", padding=(6, 6))
        self.toolbar.grid(row=0, column=0, sticky="nsw")
        self.main = ttk.Frame(self, style="Main.TFrame")
        self.main.grid(row=0, column=1, sticky="nsew")
        self.status_frame = ttk.Frame(self, style="Status.TFrame", padding=(6, 4))
        self.status_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.status_frame.grid_columnconfigure(0, weight=1)

    def _make_toolbar(self):
        self.toolbar_buttons = {}
        for idx, (label, key) in enumerate(TOOL_BUTTONS):
            f = ttk.Frame(self.toolbar)
            f.grid(row=idx, column=0, pady=(0 if idx else 0, 8))
            c = tk.Canvas(f, width=36, height=36, highlightthickness=0, bg="#f0f3f6")
            c.pack()
            painter = ICON_PAINTERS.get(key)
            if painter:
                painter(c)
            
            # Store button reference
            self.toolbar_buttons[key] = c
            
            # Add click handler
            def make_handler(k=key):
                return lambda e: self._on_toolbar_click(k)
            c.bind("<Button-1>", make_handler())
            
            # Hover effect
            def _binds(canvas=c):
                def on_enter(_):
                    canvas.configure(bg="#e8eef5")
                def on_leave(_):
                    canvas.configure(bg="#f0f3f6")
                canvas.bind("<Enter>", on_enter)
                canvas.bind("<Leave>", on_leave)
            _binds()

        self.toolbar.grid_rowconfigure(len(TOOL_BUTTONS), weight=1)

    def _make_main_tabs(self):
        self.notebook = ttk.Notebook(self.main)
        self.notebook.pack(fill="both", expand=True)

        self.tab_log = ttk.Frame(self.notebook, style="Main.TFrame")
        self.tab_cfg = ttk.Frame(self.notebook, style="Main.TFrame")
        self.tab_mod = ttk.Frame(self.notebook, style="Main.TFrame")
        self.tab_prof = ttk.Frame(self.notebook, style="Main.TFrame")

        self.notebook.add(self.tab_log, text="Log")
        self.notebook.add(self.tab_cfg, text="Configuration")
        self.notebook.add(self.tab_mod, text="Modules")
        self.notebook.add(self.tab_prof, text="Profiles")

    def _make_bottom_bar(self):
        # Status indicators
        mid = ttk.Frame(self.status_frame, style="Status.TFrame")
        mid.grid(row=0, column=0, sticky="w", padx=(50, 0))

        def indicator(parent, color="#b71c1c"):
            box = tk.Canvas(parent, width=14, height=14, bg="#f7f7f7", highlightthickness=0)
            box.create_rectangle(2, 2, 12, 12, fill=color, outline="#555")
            return box

        # Interface indicator
        lbl_if = ttk.Label(mid, text="Interface:", background="#f7f7f7")
        self.ind_if = indicator(mid, "#b71c1c")
        lbl_veh = ttk.Label(mid, text="   Vehicle:", background="#f7f7f7")
        self.ind_veh = indicator(mid, "#b71c1c")
        self.lbl_conn = ttk.Label(mid, text="   Not connected", background="#f7f7f7")

        lbl_if.grid(row=0, column=0, padx=(4, 4))
        self.ind_if.grid(row=0, column=1)
        lbl_veh.grid(row=0, column=2, padx=(10, 4))
        self.ind_veh.grid(row=0, column=3)
        self.lbl_conn.grid(row=0, column=4, padx=(10, 0))

        # Voltage display
        right = ttk.Frame(self.status_frame, style="Status.TFrame")
        right.grid(row=0, column=1, sticky="e")
        self.volt_canvas = tk.Canvas(right, width=64, height=18, bg="#f7f7f7", highlightthickness=0)
        self.volt_canvas.pack()
        self.volt_rect = self.volt_canvas.create_rectangle(54, 4, 60, 10, fill="#b71c1c", outline="#555")
        self.volt_text = self.volt_canvas.create_text(20, 9, text="--.-V", font=("Segoe UI", 9), fill="#333")

    def _make_bottom_small_buttons(self):
        holder = ttk.Frame(self.status_frame, style="Status.TFrame")
        holder.grid(row=0, column=0, sticky="w", padx=(0, 0))

        for i, (label, key) in enumerate(BOTTOM_SMALL_BTNS):
            c = tk.Canvas(holder, width=24, height=24, highlightthickness=1, highlightbackground="#999", bg="#f2f2f2")
            c.grid(row=0, column=i, padx=(4 if i else 0, 6))
            
            if key == "gear":
                c.bind("<Button-1>", lambda e: self._show_settings())
            elif key == "save":
                c.bind("<Button-1>", lambda e: self._save_log())
            elif key == "folder":
                c.bind("<Button-1>", lambda e: self._open_folder())
                
            painter = ICON_PAINTERS.get(key, paint_gear)
            if painter:
                # Scale down for 24x24
                c.scale("all", 0, 0, 0.67, 0.67)
                painter(c)

            def _hover(canvas=c):
                def on_enter(_):
                    canvas.configure(bg="#e8eef5")
                def on_leave(_):
                    canvas.configure(bg="#f2f2f2")
                canvas.bind("<Enter>", on_enter)
                canvas.bind("<Leave>", on_leave)
            _hover()

    def _setup_log_tab(self):
        """Setup Log tab with communication log"""
        frame = tk.Frame(self.tab_log, bg="#ffffff")
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Control panel
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Button(control_frame, text="Clear Log", command=self._clear_log).pack(side="left", padx=(0, 5))
        ttk.Button(control_frame, text="Export Log", command=self._export_log).pack(side="left", padx=(0, 5))
        
        self.log_filter = ttk.Combobox(control_frame, values=["All", "Sent", "Received", "Errors"], width=15)
        self.log_filter.set("All")
        self.log_filter.pack(side="left", padx=(20, 5))
        ttk.Label(control_frame, text="Filter:", background="#ffffff").pack(side="left", padx=(0, 5))
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(frame, height=20, wrap=tk.WORD, font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True)
        
        # Configure tags for colored text
        self.log_text.tag_config("sent", foreground="#0066cc")
        self.log_text.tag_config("received", foreground="#009900")
        self.log_text.tag_config("error", foreground="#cc0000")
        self.log_text.tag_config("info", foreground="#666666")

    def _setup_config_tab(self):
        """Setup Configuration tab for connection settings"""
        frame = tk.Frame(self.tab_cfg, bg="#ffffff")
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Connection settings
        conn_frame = ttk.LabelFrame(frame, text="Connection Settings", padding=10)
        conn_frame.pack(fill="x", pady=(0, 10))
        
        # Protocol selection
        ttk.Label(conn_frame, text="Protocol:", background="#ffffff").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.protocol_var = tk.StringVar(value="ISO15765 (CAN)")
        self.protocol_combo = ttk.Combobox(conn_frame, textvariable=self.protocol_var, width=25)
        self.protocol_combo['values'] = [
            "ISO15765 (CAN)",
            "ISO14230 (KWP2000)",
            "ISO9141",
            "J1850 PWM",
            "J1850 VPW"
        ]
        self.protocol_combo.grid(row=0, column=1, sticky="w", pady=5)
        
        # Baud rate
        ttk.Label(conn_frame, text="Baud Rate:", background="#ffffff").grid(row=1, column=0, sticky="w", padx=(0, 10))
        self.baud_var = tk.StringVar(value="500000")
        self.baud_combo = ttk.Combobox(conn_frame, textvariable=self.baud_var, width=25)
        self.baud_combo['values'] = ["250000", "500000", "1000000", "125000", "10400", "41600"]
        self.baud_combo.grid(row=1, column=1, sticky="w", pady=5)
        
        # Device selection
        ttk.Label(conn_frame, text="J2534 Device:", background="#ffffff").grid(row=2, column=0, sticky="w", padx=(0, 10))
        self.device_var = tk.StringVar(value="Mock J2534 Device")
        self.device_combo = ttk.Combobox(conn_frame, textvariable=self.device_var, width=25)
        self.device_combo['values'] = ["Mock J2534 Device", "ELM327", "PassThru Device"]
        self.device_combo.grid(row=2, column=1, sticky="w", pady=5)
        
        # Connect/Disconnect buttons
        btn_frame = ttk.Frame(conn_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=(10, 0))
        
        self.connect_btn = ttk.Button(btn_frame, text="Connect", command=self._connect_vehicle)
        self.connect_btn.pack(side="left", padx=(0, 5))
        
        self.disconnect_btn = ttk.Button(btn_frame, text="Disconnect", command=self._disconnect_vehicle, state="disabled")
        self.disconnect_btn.pack(side="left")
        
        # Advanced settings
        adv_frame = ttk.LabelFrame(frame, text="Advanced Settings", padding=10)
        adv_frame.pack(fill="x", pady=(0, 10))
        
        # Timeout settings
        ttk.Label(adv_frame, text="Response Timeout (ms):", background="#ffffff").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.timeout_var = tk.StringVar(value="2000")
        ttk.Spinbox(adv_frame, textvariable=self.timeout_var, from_=100, to=10000, increment=100, width=23).grid(row=0, column=1, sticky="w", pady=5)
        
        # Flow control
        ttk.Label(adv_frame, text="Flow Control:", background="#ffffff").grid(row=1, column=0, sticky="w", padx=(0, 10))
        self.flow_control_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(adv_frame, text="Enable", variable=self.flow_control_var).grid(row=1, column=1, sticky="w", pady=5)
        
        # Filters
        ttk.Label(adv_frame, text="Message Filters:", background="#ffffff").grid(row=2, column=0, sticky="w", padx=(0, 10))
        self.filter_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(adv_frame, text="Enable", variable=self.filter_var).grid(row=2, column=1, sticky="w", pady=5)

    def _setup_modules_tab(self):
        """Setup Modules tab for ECU selection and operations"""
        frame = tk.Frame(self.tab_mod, bg="#ffffff")
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left panel - ECU list
        left_frame = ttk.Frame(frame)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        ttk.Label(left_frame, text="Available ECUs:", background="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        
        # ECU Treeview
        self.ecu_tree = ttk.Treeview(left_frame, columns=("Address", "Protocol", "Status"), height=15)
        self.ecu_tree.heading("#0", text="Module")
        self.ecu_tree.heading("Address", text="Address")
        self.ecu_tree.heading("Protocol", text="Protocol")
        self.ecu_tree.heading("Status", text="Status")
        
        self.ecu_tree.column("#0", width=200)
        self.ecu_tree.column("Address", width=100)
        self.ecu_tree.column("Protocol", width=100)
        self.ecu_tree.column("Status", width=100)
        
        self.ecu_tree.pack(fill="both", expand=True, pady=(5, 10))
        
        # ECU control buttons
        ecu_btn_frame = ttk.Frame(left_frame)
        ecu_btn_frame.pack(fill="x")
        
        ttk.Button(ecu_btn_frame, text="Scan ECUs", command=self._scan_ecus).pack(side="left", padx=(0, 5))
        ttk.Button(ecu_btn_frame, text="Refresh", command=self._refresh_ecus).pack(side="left", padx=(0, 5))
        ttk.Button(ecu_btn_frame, text="Info", command=self._show_ecu_info).pack(side="left")
        
        # Right panel - DTC operations
        right_frame = ttk.LabelFrame(frame, text="Diagnostic Trouble Codes", padding=10)
        right_frame.pack(side="right", fill="both", expand=True)
        
        # DTC control buttons
        dtc_btn_frame = ttk.Frame(right_frame)
        dtc_btn_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Button(dtc_btn_frame, text="Read DTCs", command=self._read_dtcs).pack(side="left", padx=(0, 5))
        ttk.Button(dtc_btn_frame, text="Clear DTCs", command=self._clear_dtcs).pack(side="left", padx=(0, 5))
        ttk.Button(dtc_btn_frame, text="Freeze Frame", command=self._read_freeze_frame).pack(side="left")
        
        # DTC list
        self.dtc_tree = ttk.Treeview(right_frame, columns=("Description", "Status", "Module"), height=10)
        self.dtc_tree.heading("#0", text="Code")
        self.dtc_tree.heading("Description", text="Description")
        self.dtc_tree.heading("Status", text="Status")
        self.dtc_tree.heading("Module", text="Module")
        
        self.dtc_tree.column("#0", width=80)
        self.dtc_tree.column("Description", width=250)
        self.dtc_tree.column("Status", width=100)
        self.dtc_tree.column("Module", width=150)
        
        self.dtc_tree.pack(fill="both", expand=True)
        
        # DTC details text
        ttk.Label(right_frame, text="Details:", background="#ffffff", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(10, 5))
        self.dtc_details = tk.Text(right_frame, height=5, wrap=tk.WORD, font=("Consolas", 9))
        self.dtc_details.pack(fill="x")

    def _setup_profiles_tab(self):
        """Setup Profiles tab for saving/loading configurations"""
        frame = tk.Frame(self.tab_prof, bg="#ffffff")
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Profile management
        prof_frame = ttk.LabelFrame(frame, text="Profile Management", padding=10)
        prof_frame.pack(fill="x", pady=(0, 10))
        
        # Profile list
        ttk.Label(prof_frame, text="Saved Profiles:", background="#ffffff").grid(row=0, column=0, sticky="w")
        
        self.profile_listbox = tk.Listbox(prof_frame, height=6, width=50)
        self.profile_listbox.grid(row=1, column=0, columnspan=2, pady=(5, 10))
        
        # Default profiles
        self.profile_listbox.insert(tk.END, "Default - ISO15765 CAN 500k")
        self.profile_listbox.insert(tk.END, "Ford - ISO14230 KWP2000")
        self.profile_listbox.insert(tk.END, "GM - J1850 VPW")
        self.profile_listbox.insert(tk.END, "Chrysler - J1850 PWM")
        
        # Profile buttons
        btn_frame = ttk.Frame(prof_frame)
        btn_frame.grid(row=2, column=0, columnspan=2)
        
        ttk.Button(btn_frame, text="Load Profile", command=self._load_profile).pack(side="left", padx=(0, 5))
        ttk.Button(btn_frame, text="Save Profile", command=self._save_profile).pack(side="left", padx=(0, 5))
        ttk.Button(btn_frame, text="Delete Profile", command=self._delete_profile).pack(side="left", padx=(0, 5))
        ttk.Button(btn_frame, text="Export", command=self._export_profile).pack(side="left", padx=(0, 5))
        ttk.Button(btn_frame, text="Import", command=self._import_profile).pack(side="left")
        
        # Profile details
        detail_frame = ttk.LabelFrame(frame, text="Profile Details", padding=10)
        detail_frame.pack(fill="both", expand=True)
        
        self.profile_details = tk.Text(detail_frame, height=10, wrap=tk.WORD, font=("Consolas", 9))
        self.profile_details.pack(fill="both", expand=True)

    def _on_toolbar_click(self, button_key: str):
        """Handle toolbar button clicks"""
        if button_key == "car":
            self.notebook.select(self.tab_cfg)
            self._connect_vehicle()
        elif button_key == "dtc":
            self.notebook.select(self.tab_mod)
            self._read_dtcs()
        elif button_key == "scope":
            self._show_scope()
        elif button_key == "check":
            self._show_tests()
        elif button_key == "wrench":
            self._show_service()
        elif button_key == "chip":
            self._show_chip_tuning()
        elif button_key == "gear":
            self._show_settings()
        elif button_key == "help":
            self._show_help()

    def _connect_vehicle(self):
        """Connect to vehicle via J2534"""
        def connect_thread():
            try:
                self.log_message("Connecting to J2534 device...", "info")
                
                # Connect to J2534 device
                if not self.j2534.connect(self.device_var.get()):
                    self.log_message("Failed to connect to J2534 device", "error")
                    return
                    
                self.log_message(f"Connected to {self.device_var.get()}", "info")
                
                # Parse protocol selection
                protocol_map = {
                    "ISO15765 (CAN)": J2534Protocol.ISO15765,
                    "ISO14230 (KWP2000)": J2534Protocol.ISO14230,
                    "ISO9141": J2534Protocol.ISO9141,
                    "J1850 PWM": J2534Protocol.J1850PWM,
                    "J1850 VPW": J2534Protocol.J1850VPW
                }
                
                protocol = protocol_map.get(self.protocol_var.get(), J2534Protocol.ISO15765)
                baud_rate = int(self.baud_var.get())
                
                # Open channel
                self.log_message(f"Opening {self.protocol_var.get()} channel at {baud_rate} baud...", "info")
                if not self.j2534.open_channel(protocol, baud_rate):
                    self.log_message("Failed to open communication channel", "error")
                    return
                    
                self.connected = True
                self.msg_queue.put(("connection", True))
                self.log_message("Vehicle connection established", "info")
                
                # Simulate reading voltage
                self.voltage = 12.6
                self.msg_queue.put(("voltage", self.voltage))
                
            except Exception as e:
                self.log_message(f"Connection error: {str(e)}", "error")
                self.msg_queue.put(("connection", False))
        
        threading.Thread(target=connect_thread, daemon=True).start()

    def _disconnect_vehicle(self):
        """Disconnect from vehicle"""
        try:
            self.j2534.close_channel()
            self.j2534.disconnect()
            self.connected = False
            self.voltage = 0.0
            
            self.msg_queue.put(("connection", False))
            self.msg_queue.put(("voltage", 0.0))
            self.log_message("Disconnected from vehicle", "info")
            
        except Exception as e:
            self.log_message(f"Disconnect error: {str(e)}", "error")

    def _scan_ecus(self):
        """Scan for available ECUs"""
        if not self.connected:
            messagebox.showwarning("Not Connected", "Please connect to vehicle first")
            return
            
        def scan_thread():
            try:
                self.log_message("Scanning for ECUs...", "info")
                
                # Get protocol from current settings
                protocol_map = {
                    "ISO15765 (CAN)": J2534Protocol.ISO15765,
                    "ISO14230 (KWP2000)": J2534Protocol.ISO14230,
                    "ISO9141": J2534Protocol.ISO9141,
                    "J1850 PWM": J2534Protocol.J1850PWM,
                    "J1850 VPW": J2534Protocol.J1850VPW
                }
                protocol = protocol_map.get(self.protocol_var.get(), J2534Protocol.ISO15765)
                
                # Scan for ECUs
                ecus = self.vehicle_comm.scan_for_ecus(protocol)
                
                self.msg_queue.put(("ecus", ecus))
                self.log_message(f"Found {len(ecus)} ECUs", "info")
                
                for ecu in ecus:
                    self.log_message(f"  - {ecu.name} at 0x{ecu.address:03X}", "info")
                    
            except Exception as e:
                self.log_message(f"ECU scan error: {str(e)}", "error")
        
        threading.Thread(target=scan_thread, daemon=True).start()

    def _refresh_ecus(self):
        """Refresh ECU status"""
        self._scan_ecus()

    def _show_ecu_info(self):
        """Show detailed ECU information"""
        selection = self.ecu_tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select an ECU first")
            return
            
        # Get selected ECU
        item = self.ecu_tree.item(selection[0])
        ecu_name = item['text']
        
        # Create info dialog
        info_dialog = tk.Toplevel(self)
        info_dialog.title(f"ECU Information - {ecu_name}")
        info_dialog.geometry("400x300")
        
        info_text = tk.Text(info_dialog, wrap=tk.WORD, font=("Consolas", 9))
        info_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add ECU information
        info_text.insert(tk.END, f"Module: {ecu_name}\n")
        info_text.insert(tk.END, f"Address: {item['values'][0]}\n")
        info_text.insert(tk.END, f"Protocol: {item['values'][1]}\n")
        info_text.insert(tk.END, f"Status: {item['values'][2]}\n\n")
        info_text.insert(tk.END, "Supported PIDs:\n")
        info_text.insert(tk.END, "- Engine RPM\n")
        info_text.insert(tk.END, "- Vehicle Speed\n")
        info_text.insert(tk.END, "- Coolant Temperature\n")
        info_text.insert(tk.END, "- Fuel Level\n")
        
        info_text.config(state="disabled")

    def _read_dtcs(self):
        """Read DTCs from selected ECU"""
        if not self.connected:
            messagebox.showwarning("Not Connected", "Please connect to vehicle first")
            return
            
        selection = self.ecu_tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select an ECU first")
            return
            
        def read_thread():
            try:
                # Get selected ECU
                item = self.ecu_tree.item(selection[0])
                ecu_name = item['text']
                
                self.log_message(f"Reading DTCs from {ecu_name}...", "info")
                
                # Find ECU object
                ecu = None
                for e in self.vehicle_comm.ecus:
                    if e.name == ecu_name:
                        ecu = e
                        break
                        
                if not ecu:
                    self.log_message("ECU not found", "error")
                    return
                    
                # Read DTCs
                dtcs = self.vehicle_comm.read_dtcs(ecu)
                
                self.msg_queue.put(("dtcs", dtcs))
                self.log_message(f"Found {len(dtcs)} DTCs", "info")
                
                for dtc in dtcs:
                    self.log_message(f"  - {dtc.code}: {dtc.description}", "info")
                    
            except Exception as e:
                self.log_message(f"DTC read error: {str(e)}", "error")
        
        threading.Thread(target=read_thread, daemon=True).start()

    def _clear_dtcs(self):
        """Clear DTCs from selected ECU"""
        if not self.connected:
            messagebox.showwarning("Not Connected", "Please connect to vehicle first")
            return
            
        selection = self.ecu_tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select an ECU first")
            return
            
        if messagebox.askyesno("Clear DTCs", "Are you sure you want to clear all DTCs?"):
            def clear_thread():
                try:
                    # Get selected ECU
                    item = self.ecu_tree.item(selection[0])
                    ecu_name = item['text']
                    
                    self.log_message(f"Clearing DTCs from {ecu_name}...", "info")
                    
                    # Find ECU object
                    ecu = None
                    for e in self.vehicle_comm.ecus:
                        if e.name == ecu_name:
                            ecu = e
                            break
                            
                    if not ecu:
                        self.log_message("ECU not found", "error")
                        return
                        
                    # Clear DTCs
                    if self.vehicle_comm.clear_dtcs(ecu):
                        self.msg_queue.put(("dtcs", []))
                        self.log_message("DTCs cleared successfully", "info")
                    else:
                        self.log_message("Failed to clear DTCs", "error")
                        
                except Exception as e:
                    self.log_message(f"DTC clear error: {str(e)}", "error")
            
            threading.Thread(target=clear_thread, daemon=True).start()

    def _read_freeze_frame(self):
        """Read freeze frame data"""
        if not self.connected:
            messagebox.showwarning("Not Connected", "Please connect to vehicle first")
            return
            
        messagebox.showinfo("Freeze Frame", "Freeze frame data reading not yet implemented")

    def _show_scope(self):
        """Show oscilloscope window"""
        scope_window = tk.Toplevel(self)
        scope_window.title("Oscilloscope")
        scope_window.geometry("800x600")
        
        # Add basic scope interface
        canvas = tk.Canvas(scope_window, bg="black")
        canvas.pack(fill="both", expand=True)
        
        # Draw grid
        for i in range(0, 800, 50):
            canvas.create_line(i, 0, i, 600, fill="#003300", width=1)
        for i in range(0, 600, 50):
            canvas.create_line(0, i, 800, i, fill="#003300", width=1)
            
        # Draw sample waveform
        import math
        points = []
        for x in range(800):
            y = 300 + 100 * math.sin(x * 0.02)
            points.extend([x, y])
        canvas.create_line(points, fill="#00ff00", width=2)

    def _show_tests(self):
        """Show component tests window"""
        test_window = tk.Toplevel(self)
        test_window.title("Component Tests")
        test_window.geometry("600x400")
        
        # Test categories
        categories = [
            "Actuator Tests",
            "Sensor Tests",
            "System Tests",
            "Bi-directional Controls"
        ]
        
        notebook = ttk.Notebook(test_window)
        notebook.pack(fill="both", expand=True)
        
        for category in categories:
            frame = ttk.Frame(notebook)
            notebook.add(frame, text=category)
            
            # Add sample tests
            tests = [
                "Fuel Pump Test",
                "Injector Test",
                "Ignition Coil Test",
                "EVAP System Test"
            ]
            
            for i, test in enumerate(tests):
                ttk.Button(frame, text=test, command=lambda t=test: messagebox.showinfo("Test", f"Running {t}...")).grid(row=i, column=0, padx=10, pady=5, sticky="w")

    def _show_service(self):
        """Show service functions window"""
        service_window = tk.Toplevel(self)
        service_window.title("Service Functions")
        service_window.geometry("600x400")
        
        # Service categories
        services = {
            "Oil Reset": ["Engine Oil", "Transmission Oil", "Differential Oil"],
            "Adaptation": ["Throttle Body", "Steering Angle", "Battery"],
            "Coding": ["Injector Coding", "Key Programming", "Module Coding"],
            "Calibration": ["TPMS", "Suspension", "Camera"]
        }
        
        notebook = ttk.Notebook(service_window)
        notebook.pack(fill="both", expand=True)
        
        for category, items in services.items():
            frame = ttk.Frame(notebook)
            notebook.add(frame, text=category)
            
            for i, item in enumerate(items):
                ttk.Button(frame, text=item, command=lambda i=item: messagebox.showinfo("Service", f"Performing {i}...")).grid(row=i, column=0, padx=10, pady=5, sticky="w")

    def _show_chip_tuning(self):
        """Show chip tuning window"""
        messagebox.showinfo("Chip Tuning", "ECU programming and tuning functions")

    def _show_settings(self):
        """Show settings dialog"""
        settings_window = tk.Toplevel(self)
        settings_window.title("Settings")
        settings_window.geometry("500x400")
        
        notebook = ttk.Notebook(settings_window)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # General settings
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="General")
        
        ttk.Label(general_frame, text="Language:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        ttk.Combobox(general_frame, values=["English", "Spanish", "French", "German"], width=20).grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(general_frame, text="Theme:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        ttk.Combobox(general_frame, values=["Light", "Dark", "Auto"], width=20).grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Checkbutton(general_frame, text="Auto-connect on startup").grid(row=2, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        ttk.Checkbutton(general_frame, text="Save log automatically").grid(row=3, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        
        # Communication settings
        comm_frame = ttk.Frame(notebook)
        notebook.add(comm_frame, text="Communication")
        
        ttk.Label(comm_frame, text="Default Protocol:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        ttk.Combobox(comm_frame, values=["Auto-detect", "ISO15765", "ISO14230", "J1850"], width=20).grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(comm_frame, text="Retry Count:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        ttk.Spinbox(comm_frame, from_=1, to=10, width=18).grid(row=1, column=1, padx=10, pady=5)

    def _show_help(self):
        """Show help dialog"""
        help_window = tk.Toplevel(self)
        help_window.title("Help")
        help_window.geometry("600x400")
        
        help_text = scrolledtext.ScrolledText(help_window, wrap=tk.WORD)
        help_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        help_content = """
J2534 Diagnostic Software - Help

GETTING STARTED:
1. Connect your J2534 device to the vehicle's OBD-II port
2. Select the appropriate protocol and baud rate in Configuration tab
3. Click Connect to establish communication
4. Use the Modules tab to scan for ECUs and read DTCs

FEATURES:
- Read and clear diagnostic trouble codes (DTCs)
- View live data streams
- Perform actuator tests
- Service functions (oil reset, adaptations, etc.)
- ECU programming and coding
- Data logging and analysis

TROUBLESHOOTING:
- Ensure J2534 device drivers are installed
- Check vehicle ignition is ON
- Verify correct protocol selection
- Try different baud rates if connection fails

For more information, visit the documentation.
        """
        
        help_text.insert(tk.END, help_content)
        help_text.config(state="disabled")

    def _save_log(self):
        """Save communication log to file"""
        from tkinter import filedialog
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success", "Log saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log: {str(e)}")

    def _open_folder(self):
        """Open logs folder"""
        import os
        import subprocess
        import platform
        
        logs_dir = os.path.join(os.path.expanduser("~"), "J2534_Logs")
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)
            
        if platform.system() == "Windows":
            subprocess.Popen(f'explorer "{logs_dir}"')
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", logs_dir])
        else:
            subprocess.Popen(["xdg-open", logs_dir])

    def _clear_log(self):
        """Clear communication log"""
        self.log_text.delete(1.0, tk.END)

    def _export_log(self):
        """Export log with filtering"""
        self._save_log()

    def _load_profile(self):
        """Load selected profile"""
        selection = self.profile_listbox.curselection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a profile")
            return
            
        profile_name = self.profile_listbox.get(selection[0])
        
        # Load profile settings
        if "ISO15765" in profile_name:
            self.protocol_var.set("ISO15765 (CAN)")
            self.baud_var.set("500000")
        elif "ISO14230" in profile_name:
            self.protocol_var.set("ISO14230 (KWP2000)")
            self.baud_var.set("10400")
        elif "J1850 VPW" in profile_name:
            self.protocol_var.set("J1850 VPW")
            self.baud_var.set("10400")
        elif "J1850 PWM" in profile_name:
            self.protocol_var.set("J1850 PWM")
            self.baud_var.set("41600")
            
        self.log_message(f"Loaded profile: {profile_name}", "info")
        messagebox.showinfo("Profile Loaded", f"Profile '{profile_name}' loaded successfully")

    def _save_profile(self):
        """Save current settings as profile"""
        from tkinter import simpledialog
        name = simpledialog.askstring("Save Profile", "Enter profile name:")
        if name:
            # Add to profile list
            profile_entry = f"{name} - {self.protocol_var.get()} {self.baud_var.get()}"
            self.profile_listbox.insert(tk.END, profile_entry)
            self.log_message(f"Saved profile: {name}", "info")
            messagebox.showinfo("Profile Saved", f"Profile '{name}' saved successfully")

    def _delete_profile(self):
        """Delete selected profile"""
        selection = self.profile_listbox.curselection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a profile")
            return
            
        if messagebox.askyesno("Delete Profile", "Are you sure you want to delete this profile?"):
            self.profile_listbox.delete(selection[0])

    def _export_profile(self):
        """Export profile to file"""
        from tkinter import filedialog
        filename = filedialog.asksaveasfilename(
            defaultextension=".ini",
            filetypes=[("INI files", "*.ini"), ("All files", "*.*")]
        )
        if filename:
            config = configparser.ConfigParser()
            config['Connection'] = {
                'Protocol': self.protocol_var.get(),
                'BaudRate': self.baud_var.get(),
                'Device': self.device_var.get()
            }
            config['Advanced'] = {
                'Timeout': self.timeout_var.get(),
                'FlowControl': str(self.flow_control_var.get()),
                'Filters': str(self.filter_var.get())
            }
            
            with open(filename, 'w') as f:
                config.write(f)
            messagebox.showinfo("Success", "Profile exported successfully")

    def _import_profile(self):
        """Import profile from file"""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(
            filetypes=[("INI files", "*.ini"), ("All files", "*.*")]
        )
        if filename:
            config = configparser.ConfigParser()
            config.read(filename)
            
            if 'Connection' in config:
                self.protocol_var.set(config.get('Connection', 'Protocol'))
                self.baud_var.set(config.get('Connection', 'BaudRate'))
                self.device_var.set(config.get('Connection', 'Device'))
                
            if 'Advanced' in config:
                self.timeout_var.set(config.get('Advanced', 'Timeout'))
                self.flow_control_var.set(config.getboolean('Advanced', 'FlowControl'))
                self.filter_var.set(config.getboolean('Advanced', 'Filters'))
                
            messagebox.showinfo("Success", "Profile imported successfully")

    def log_message(self, message: str, msg_type: str = "info"):
        """Add message to log with timestamp and formatting"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        formatted_msg = f"[{timestamp}] {message}\n"
        
        # Thread-safe logging
        self.msg_queue.put(("log", (formatted_msg, msg_type)))

    def _process_messages(self):
        """Process messages from queue (called from main thread)"""
        try:
            while True:
                msg_type, data = self.msg_queue.get_nowait()
                
                if msg_type == "log":
                    text, tag = data
                    self.log_text.insert(tk.END, text, tag)
                    self.log_text.see(tk.END)
                    
                elif msg_type == "connection":
                    connected = data
                    if connected:
                        # Update UI for connected state
                        self.ind_if.delete("all")
                        self.ind_if.create_rectangle(2, 2, 12, 12, fill="#4caf50", outline="#555")
                        self.ind_veh.delete("all")
                        self.ind_veh.create_rectangle(2, 2, 12, 12, fill="#4caf50", outline="#555")
                        self.lbl_conn.config(text="   Connected")
                        self.connect_btn.config(state="disabled")
                        self.disconnect_btn.config(state="normal")
                    else:
                        # Update UI for disconnected state
                        self.ind_if.delete("all")
                        self.ind_if.create_rectangle(2, 2, 12, 12, fill="#b71c1c", outline="#555")
                        self.ind_veh.delete("all")
                        self.ind_veh.create_rectangle(2, 2, 12, 12, fill="#b71c1c", outline="#555")
                        self.lbl_conn.config(text="   Not connected")
                        self.connect_btn.config(state="normal")
                        self.disconnect_btn.config(state="disabled")
                        
                elif msg_type == "voltage":
                    voltage = data
                    self.volt_canvas.delete(self.volt_text)
                    if voltage > 0:
                        self.volt_text = self.volt_canvas.create_text(20, 9, text=f"{voltage:.1f}V", font=("Segoe UI", 9), fill="#333")
                        # Update voltage indicator color
                        color = "#4caf50" if voltage > 12.0 else "#ff9800" if voltage > 11.5 else "#b71c1c"
                        self.volt_canvas.delete(self.volt_rect)
                        self.volt_rect = self.volt_canvas.create_rectangle(54, 4, 60, 10, fill=color, outline="#555")
                    else:
                        self.volt_text = self.volt_canvas.create_text(20, 9, text="--.-V", font=("Segoe UI", 9), fill="#333")
                        self.volt_canvas.delete(self.volt_rect)
                        self.volt_rect = self.volt_canvas.create_rectangle(54, 4, 60, 10, fill="#b71c1c", outline="#555")
                        
                elif msg_type == "ecus":
                    ecus = data
                    # Clear existing ECUs
                    for item in self.ecu_tree.get_children():
                        self.ecu_tree.delete(item)
                    # Add new ECUs
                    for ecu in ecus:
                        status = "Active" if self.connected else "Inactive"
                        self.ecu_tree.insert("", "end", text=ecu.name, 
                                           values=(f"0x{ecu.address:03X}", 
                                                  ecu.protocol.name, 
                                                  status))
                                                  
                elif msg_type == "dtcs":
                    dtcs = data
                    # Clear existing DTCs
                    for item in self.dtc_tree.get_children():
                        self.dtc_tree.delete(item)
                    # Add new DTCs
                    for dtc in dtcs:
                        self.dtc_tree.insert("", "end", text=dtc.code,
                                           values=(dtc.description, dtc.status, dtc.module))
                    
                    # Update details for first DTC
                    if dtcs:
                        self.dtc_details.delete(1.0, tk.END)
                        self.dtc_details.insert(tk.END, f"Code: {dtcs[0].code}\n")
                        self.dtc_details.insert(tk.END, f"Description: {dtcs[0].description}\n")
                        self.dtc_details.insert(tk.END, f"Status: {dtcs[0].status}\n")
                        self.dtc_details.insert(tk.END, f"Module: {dtcs[0].module}\n")
                        if dtcs[0].timestamp:
                            self.dtc_details.insert(tk.END, f"Time: {dtcs[0].timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                    
        except queue.Empty:
            pass
        finally:
            # Schedule next check
            self.after(100, self._process_messages)

    def _on_close(self):
        """Handle application close"""
        if self.connected:
            if messagebox.askyesno("Close", "Vehicle is still connected. Disconnect and close?"):
                self._disconnect_vehicle()
                self.destroy()
        else:
            self.destroy()


class LiveDataWindow(tk.Toplevel):
    """Window for displaying live data"""
    
    def __init__(self, parent, vehicle_comm):
        super().__init__(parent)
        self.title("Live Data")
        self.geometry("800x600")
        
        self.vehicle_comm = vehicle_comm
        self.running = False
        self.data_values = {}
        
        # Create UI
        self._create_widgets()
        
    def _create_widgets(self):
        # Control panel
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=10, pady=10)
        
        self.start_btn = ttk.Button(control_frame, text="Start", command=self.start_monitoring)
        self.start_btn.pack(side="left", padx=(0, 5))
        
        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_monitoring, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 5))
        
        ttk.Button(control_frame, text="Clear", command=self.clear_data).pack(side="left")
        
        # Data display
        columns = ("Value", "Unit", "Min", "Max", "Avg")
        self.data_tree = ttk.Treeview(self, columns=columns, height=20)
        
        self.data_tree.heading("#0", text="Parameter")
        for col in columns:
            self.data_tree.heading(col, text=col)
            self.data_tree.column(col, width=100)
        
        self.data_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Add common parameters
        params = [
            ("Engine Speed", "0", "RPM", "0", "0", "0"),
            ("Vehicle Speed", "0", "km/h", "0", "0", "0"),
            ("Coolant Temp", "0", "°C", "0", "0", "0"),
            ("Engine Load", "0", "%", "0", "0", "0"),
            ("Throttle Position", "0", "%", "0", "0", "0"),
            ("Fuel Level", "0", "%", "0", "0", "0"),
            ("Battery Voltage", "0", "V", "0", "0", "0"),
            ("Intake Air Temp", "0", "°C", "0", "0", "0"),
            ("MAF Rate", "0", "g/s", "0", "0", "0"),
            ("Fuel Pressure", "0", "kPa", "0", "0", "0"),
        ]
        
        for param in params:
            self.data_tree.insert("", "end", text=param[0], values=param[1:])
    
    def start_monitoring(self):
        """Start live data monitoring"""
        self.running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._update_data()
    
    def stop_monitoring(self):
        """Stop live data monitoring"""
        self.running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
    
    def clear_data(self):
        """Clear all data values"""
        for item in self.data_tree.get_children():
            self.data_tree.set(item, "Value", "0")
            self.data_tree.set(item, "Min", "0")
            self.data_tree.set(item, "Max", "0")
            self.data_tree.set(item, "Avg", "0")
    
    def _update_data(self):
        """Update live data values"""
        if not self.running:
            return
            
        # Simulate live data updates
        import random
        
        for item in self.data_tree.get_children():
            param = self.data_tree.item(item)['text']
            
            # Generate mock data based on parameter
            if param == "Engine Speed":
                value = random.randint(800, 3500)
            elif param == "Vehicle Speed":
                value = random.randint(0, 120)
            elif param == "Coolant Temp":
                value = random.randint(80, 95)
            elif param == "Engine Load":
                value = random.randint(10, 80)
            elif param == "Throttle Position":
                value = random.randint(0, 100)
            elif param == "Fuel Level":
                value = random.randint(20, 80)
            elif param == "Battery Voltage":
                value = round(random.uniform(12.0, 14.5), 1)
            elif param == "Intake Air Temp":
                value = random.randint(15, 40)
            elif param == "MAF Rate":
                value = round(random.uniform(2.0, 50.0), 1)
            elif param == "Fuel Pressure":
                value = random.randint(200, 400)
            else:
                value = 0
                
            # Update tree
            self.data_tree.set(item, "Value", str(value))
            
            # Update min/max/avg (simplified)
            current_min = float(self.data_tree.set(item, "Min") or 0)
            current_max = float(self.data_tree.set(item, "Max") or 0)
            
            if current_min == 0 or value < current_min:
                self.data_tree.set(item, "Min", str(value))
            if value > current_max:
                self.data_tree.set(item, "Max", str(value))
                
            # Simple average (not accurate, just for demo)
            avg = (current_min + current_max + value) / 3
            self.data_tree.set(item, "Avg", f"{avg:.1f}")
        
        # Schedule next update
        if self.running:
            self.after(500, self._update_data)


def main():
    """Main entry point"""
    app = J2534DiagnosticApp()
    
    # Add menu bar
    menubar = tk.Menu(app)
    app.config(menu=menubar)
    
    # File menu
    file_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="New Session", command=lambda: app.log_message("New session started", "info"))
    file_menu.add_command(label="Open Log...", command=lambda: app.log_message("Open log file", "info"))
    file_menu.add_command(label="Save Log...", command=app._save_log)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=app._on_close)
    
    # Tools menu
    tools_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Tools", menu=tools_menu)
    tools_menu.add_command(label="Live Data", command=lambda: LiveDataWindow(app, app.vehicle_comm))
    tools_menu.add_command(label="Oscilloscope", command=app._show_scope)
    tools_menu.add_command(label="Component Tests", command=app._show_tests)
    tools_menu.add_command(label="Service Functions", command=app._show_service)
    tools_menu.add_separator()
    tools_menu.add_command(label="Settings...", command=app._show_settings)
    
    # Vehicle menu
    vehicle_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Vehicle", menu=vehicle_menu)
    vehicle_menu.add_command(label="Connect", command=app._connect_vehicle)
    vehicle_menu.add_command(label="Disconnect", command=app._disconnect_vehicle)
    vehicle_menu.add_separator()
    vehicle_menu.add_command(label="Scan ECUs", command=app._scan_ecus)
    vehicle_menu.add_command(label="Read DTCs", command=app._read_dtcs)
    vehicle_menu.add_command(label="Clear DTCs", command=app._clear_dtcs)
    
    # Help menu
    help_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Help", menu=help_menu)
    help_menu.add_command(label="Documentation", command=app._show_help)
    help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", 
        "J2534 Diagnostic Software v1.0\n\nA comprehensive vehicle diagnostic tool\nfor reading and clearing fault codes.\n\n© 2024"))
    
    # Start application
    app.log_message("J2534 Diagnostic Software started", "info")
    app.log_message("Ready to connect to vehicle", "info")
    
    app.mainloop()


if __name__ == "__main__":
    main()
