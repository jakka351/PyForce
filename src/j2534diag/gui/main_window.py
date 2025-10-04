from __future__ import annotations
import os, sys
try:
    from PIL import Image, ImageTk  # nicer scaling
    _HAS_PIL = True
except Exception:
    _HAS_PIL = False
    # Tk 8.6 can load PNG directly via tk.PhotoImage; scaling will be basic.
    from tkinter import PhotoImage
from .icons import ICON_PAINTERS  # safe-lookup fallback used below
import ctypes as ct
import os, platform, queue, threading, configparser
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
from typing import List
from ..j2534.j2534 import *
from typing import Optional, List
from ..j2534.j2534 import (
    J2534Device, J2534FunctionsExtended, J2534Err,
    ProtocolID, ConnectFlag, BaudRate, FilterType,
    PassThruMsg, TxFlag, Ioctl, INTPTR, UINT32
)
from ..j2534.j2534_device_finder import find_installed_j2534_dlls
from ..j2534.j2534_struct import *

APP_TITLE = "PyForce J2534 Diagnostic Software v1.0.0"
APP_MIN_W, APP_MIN_H = 960, 640

# NOTE: "dtc" was causing KeyError because no painter existed.
# We keep "dtc" here, add a safe fallback in code, AND provide a painter in icons.py (see below).
TOOL_BUTTONS = [
    ("Vehicle","car"),
    ("DTC","dtc"),
    ("Scope","scope"),
    ("Tests","check"),
    ("Service","wrench"),
    ("Chip","chip"),
    ("Config","gear"),
    ("Help","help")
]

BOTTOM_SMALL_BTNS = [("Settings","gear"),("Save","save"),("Folder","folder")]

def resource_path(rel_path: str) -> str:
    """
    Return absolute path to resource, works for dev and PyInstaller onefile.
    Usage: resource_path('img/Py.png')
    """
    base = getattr(sys, "_MEIPASS", os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    return os.path.join(base, rel_path.lstrip("/\\"))


class J2534DiagnosticApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE); self.minsize(APP_MIN_W, APP_MIN_H); self.configure(bg="#e9ecef")
        self._load_branding()
        self.j2534 = port = J2534_Port()
        self.connected = False
        self.voltage = 0.0
        self.msg_queue = queue.Queue()
        self._setup_style(); self._layout_root(); self._make_toolbar()
        self._make_main_tabs(); self._make_bottom_bar(); self._make_bottom_small_buttons()
        self._setup_log_tab(); self._setup_config_tab(); self._device_map = {}
        self._refresh_device_list()
        self._setup_modules_tab(); self._setup_profiles_tab()
        self.after(100, self._process_messages)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- branding ----------
    def _load_branding(self):
        """Load logo once and create a few sizes we can reuse."""
        self._img = {}  # keep refs so Tk doesn't GC them

        logo_path = resource_path("img/Py.png")
        if not os.path.exists(logo_path):
            # fallback – app still runs
            self._img["logo_36"] = None
            self._img["logo_64"] = None
            self._img["hero_180"] = None
            self._img["icon_24"] = None
            return

        if _HAS_PIL:
            src = Image.open(logo_path).convert("RGBA")
            self._img["logo_36"] = ImageTk.PhotoImage(src.resize((160, 36), Image.LANCZOS))
            self._img["logo_64"] = ImageTk.PhotoImage(src.resize((284, 64), Image.LANCZOS))
            self._img["hero_180"] = ImageTk.PhotoImage(src.resize((800, 180), Image.LANCZOS))
            self._img["icon_24"] = ImageTk.PhotoImage(src.resize((24, 24), Image.LANCZOS))
        else:
            # no PIL – single size, reuse
            p = tk.PhotoImage(file=logo_path)
            self._img["logo_36"] = p
            self._img["logo_64"] = p
            self._img["hero_180"] = p
            self._img["icon_24"] = p


    def _refresh_device_list(self):
        try:
            devices = find_installed_j2534_dlls()
            if not devices:
                self.log_message("No J2534 devices found in the registry. Install a vendor DLL.", "error")
                return

            # Map friendly label -> device
            self._device_map = {}
            labels = []
            for d in devices:
                label = f"{d.Name} ({d.Vendor})"
                self._device_map[label] = d
                labels.append(label)

            # Update combobox
            self.device_combo.configure(values=labels)
            # Select previous or first
            if labels:
                self.device_var.set(labels[0])

            # Log for transparency
            self.log_message("Installed J2534 devices:", "info")
            for i, d in enumerate(devices):
                self.log_message(f"  [{i}] {d.Name} | {d.Vendor} | DLL: {d.FunctionLibrary}", "info")
        except Exception as e:
            self.log_message(f"Device enumeration error: {e}", "error")


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
             # --- brand banner at the very top of the left toolbar
        if self._img.get("logo_36"):
            brand_frame = ttk.Frame(self.toolbar, style="Toolbar.TFrame")
            brand_frame.grid(row=0, column=0, pady=(6, 12))
            lbl = tk.Label(
                brand_frame,
                image=self._img["logo_36"],
                bg="#f0f3f6",
                highlightthickness=0
            )
            lbl.pack()
        # shift the starting row for buttons down by 1
        start_row = 1 if self._img.get("logo_36") else 0
        for idx,(label,key) in enumerate(TOOL_BUTTONS):
            f = ttk.Frame(self.toolbar); f.grid(row=idx, column=0, pady=(0 if idx else 0,8))
            c = tk.Canvas(f, width=36, height=36, highlightthickness=0, bg="#f0f3f6"); c.pack()
            # SAFE ICON LOOKUP with fallback
            painter = ICON_PAINTERS.get(key) or ICON_PAINTERS.get("gear")
            if painter:
                painter(c)
            self.toolbar_buttons[key]=c
            c.bind("<Button-1>", (lambda k=key: (lambda e: self._on_toolbar_click(k)))())
            def _binds(canvas=c):
                canvas.bind("<Enter>", lambda _: canvas.configure(bg="#e8eef5"))
                canvas.bind("<Leave>", lambda _: canvas.configure(bg="#f0f3f6"))
            _binds()
        #_self.toolbar.grid_rowconfigure(len(TOOL_BUTTONS), weight=1)
        self.toolbar.grid_rowconfigure(start_row + len(TOOL_BUTTONS), weight=1)

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
        if self._img.get("icon_24"):
            tk.Label(right, image=self._img["icon_24"], bg="#f7f7f7").pack(side="left", padx=(0, 6))
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
            # SAFE FALLBACK (no dangling paint_gear symbol)
            painter = ICON_PAINTERS.get(key) or ICON_PAINTERS.get("gear")
            if painter:
                painter(c)
            c.bind("<Enter>", lambda e,canvas=c: canvas.configure(bg="#e8eef5"))
            c.bind("<Leave>", lambda e,canvas=c: canvas.configure(bg="#f2f2f2"))

    def _setup_log_tab(self):
        frame = tk.Frame(self.tab_log, bg="#ffffff"); frame.pack(fill="both", expand=True, padx=10, pady=10)
                # hero / brand header
        hero = tk.Frame(frame, bg="#ffffff")
        hero.pack(fill="x", pady=(0, 6))
        if self._img.get("hero_180"):
            tk.Label(hero, image=self._img["hero_180"], bg="#ffffff").pack(pady=(6, 0))
        tk.Label(
            hero,
            text="PyForce – J2534 Diagnostic Software",
            font=("Segoe UI", 16, "bold"),
            bg="#ffffff",
            fg="#333"
        ).pack(pady=(6, 4))

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
        if key == "car":
            self.notebook.select(self.tab_cfg)
            self._connect_vehicle()  # FIXED: was self.connect()
        elif key == "dtc":
            self.notebook.select(self.tab_mod); self._read_dtcs()
        elif key == "scope":
            self._show_scope()
        elif key == "check":
            self._show_tests()
        elif key == "wrench":
            self._show_service()
        elif key == "chip":
            self._show_chip_tuning()
        elif key == "gear":
            self._show_settings()
        elif key == "help":
            self._show_help()

    # -----------------------------------------
    # Helper bits
    # -----------------------------------------

    def status_ok(err: J2534Err) -> bool:
        return err == J2534Err.STATUS_NOERROR

    def id_from_msg(msg: PassThruMsg) -> int:
        # arbitration ID is encoded in first 4 bytes, little-endian
        data = bytes(msg.Data[:4])
        return int.from_bytes(data, "little", signed=False)

    def payload_from_msg(msg: PassThruMsg) -> bytes:
        sz = int(msg.DataSize)
        return bytes(msg.Data[4:sz]) if sz > 4 else b""

    def make_filter_msg_arb_id(arb_id: int, extended: bool = False) -> PassThruMsg:
        """
        Build a PassThruMsg used as Filter 'mask' or 'pattern' body for CAN.
        J2534 typically expects the ID in the first 4 bytes (little-endian).
        DataSize=4 is fine for ID-only filters.
        """
        m = PassThruMsg()
        m.ProtocolID = UINT32(int(ProtocolID.CAN))
        m.RxStatus = 0
        m.TxFlags = UINT32(int(TxFlag.CAN_29BIT_ID) if extended else 0)
        m.Timestamp = 0
        m.ExtraDataIndex = 0
        m.DataSize = 4
        raw = arb_id.to_bytes(4, "little", signed=False)
        for i in range(4):
            m.Data[i] = raw[i]
        return m

    def build_can_tx(arb_id: int, hex_bytes: str, extended: bool = False) -> PassThruMsg:
        """Create a CAN TX message to the given arbitration id with hex payload."""
        # little helper — same serialization style as in the wrapper
        from j2534_full import hex_to_bytes, PassThruMsg, TxFlag
        pld = hex_to_bytes(hex_bytes)
        header = arb_id.to_bytes(4, "little", signed=False)
        frame = header + pld
        flags = TxFlag.CAN_29BIT_ID if extended else TxFlag(0)
        return PassThruMsg.from_bytes(ProtocolID.CAN, flags, frame)


    # ---------- connectivity ----------
    def _connect_vehicle(self):
        if self.connected:
            messagebox.showinfo("Already Connected", "You are already connected.")
            return

        sel_label = self.device_var.get()
        dev = self._device_map.get(sel_label)
        if not dev:
            messagebox.showwarning("No Device", "Select a J2534 device in Configuration.")
            return

        # Resolve baud from UI; keep it simple for CAN demo
        try:
            baud_int = int(self.baud_var.get())
        except Exception:
            baud_int = 500000
        baud_enum = {
            125000: BaudRate.CAN_125000,
            250000: BaudRate.CAN_250000,
            500000: BaudRate.CAN_500000,
            33333:  BaudRate.CAN_33333,
            83333:  BaudRate.CAN_83333,
        }.get(baud_int, BaudRate.CAN_500000)

        def worker():
            try:
                self.log_message(f"Loading DLL: {dev.FunctionLibrary}", "info")
                if not self.j2534.Functions.LoadLibrary(dev):
                    raise RuntimeError("LoadLibrary failed")

                # Open
                dev_id = UINT32(0)
                err = self.j2534.Functions.PassThruOpen(INTPTR(0), ct.byref(dev_id))
                if not self._status_ok(err):
                    raise RuntimeError(f"PassThruOpen: {err.name} - {self._last_error_text()}")
                self.j2534.DeviceID = int(dev_id.value)
                self.log_message(f"Opened device -> DeviceID={self.j2534.DeviceID}", "info")

                # Connect CAN
                ch = UINT32(0)
                err = self.j2534.Functions.PassThruConnect(self.j2534.DeviceID, ProtocolID.CAN, ConnectFlag.NONE, baud_enum, ct.byref(ch))
                if not self._status_ok(err):
                    raise RuntimeError(f"PassThruConnect: {err.name} - {self._last_error_text()}")
                self.j2534.ChannelID = int(ch.value)
                self.log_message(f"Connected -> ChannelID={self.j2534.ChannelID} @ {baud_int}", "info")

                # RX clean + bus on
                self.j2534.Functions.ClearRxBuffer(self.j2534.ChannelID)
                self.j2534.Functions.PassThruIoctl(self.j2534.ChannelID, Ioctl.BUS_ON, INTPTR(0), INTPTR(0))

                # Optional: read battery voltage (if supported)
                try:
                    vb = ct.c_int(0)
                    if self._status_ok(self.j2534.Functions.ReadBatteryVoltage(self.j2534.DeviceID, ct.byref(vb))):
                        self.msg_queue.put(("voltage", vb.value / 1000.0))
                except Exception:
                    pass

                # Filter: pass only 0x7E8 (11-bit)
                mask = self._make_filter_msg_arb_id(0x7FF, extended=False)
                patt = self._make_filter_msg_arb_id(0x7E8, extended=False)
                filt_id = ct.c_int(0)
                err = self.j2534.Functions.PassThruStartMsgFilter(
                    self.j2534.ChannelID,
                    FilterType.PASS_FILTER,
                    ct.byref(mask),
                    ct.byref(patt),
                    INTPTR(0),
                    ct.byref(filt_id)
                )
                if not self._status_ok(err):
                    raise RuntimeError(f"PassThruStartMsgFilter: {err.name} - {self._last_error_text()}")
                self.j2534.FilterID = int(filt_id.value)
                self.log_message(f"Filter set -> FilterID={self.j2534.FilterID} (PASS 0x7E8)", "info")

                # Demo TX: 22 D1 00 to 0x7E0
                tx = self._build_can_tx(0x7E0, "22 D1 00", extended=False)
                arr_t = PassThruMsg * 1
                arr = arr_t(tx)
                n = ct.c_int(1)
                err = self.j2534.Functions.PassThruWriteMsgs(self.j2534.ChannelID, ct.cast(ct.pointer(arr), INTPTR), ct.byref(n), 50)
                if not self._status_ok(err):
                    raise RuntimeError(f"PassThruWriteMsgs: {err.name} - {self._last_error_text()}")
                self.log_message(f"TX wrote {n.value} message(s) -> 7E0: 22 D1 00", "sent")

                # Read replies; tolerate timeout as "no data"
                for _ in range(10):
                    max_msgs = 32
                    arr_t = PassThruMsg * max_msgs
                    rx = arr_t()
                    num = ct.c_int(max_msgs)
                    err = self.j2534.Functions.PassThruReadMsgs(self.j2534.ChannelID, ct.cast(ct.pointer(rx), INTPTR), ct.byref(num), 100)
                    if err not in (J2534Err.STATUS_NOERROR, J2534Err.ERR_TIMEOUT):
                        raise RuntimeError(f"PassThruReadMsgs: {err.name} - {self._last_error_text()}")
                    count = max(0, int(num.value))
                    if count == 0:
                        continue
                    for m in rx[:count]:
                        cid = self._id_from_msg(m)
                        pld = self._payload_from_msg(m)
                        self.log_message(f"RX id=0x{cid:03X} data={pld.hex(' ').upper()}", "received")
                    break  # got something

                self.connected = True
                self.msg_queue.put(("connection", True))

            except Exception as e:
                self.log_message(f"Connect error: {e}", "error")
                # If we partially opened things, try a clean close
                try:
                    if getattr(self.j2534, "FilterID", -1) not in (-1, None):
                        self.j2534.Functions.PassThruStopMsgFilter(self.j2534.ChannelID, self.j2534.FilterID)
                        self.j2534.FilterID = -1
                except Exception:
                    pass
                try:
                    if getattr(self.j2534, "ChannelID", 0):
                        self.j2534.Functions.PassThruDisconnect(self.j2534.ChannelID)
                        self.j2534.ChannelID = 0
                except Exception:
                    pass
                try:
                    if getattr(self.j2534, "DeviceID", 0):
                        self.j2534.Functions.PassThruClose(self.j2534.DeviceID)
                        self.j2534.DeviceID = 0
                except Exception:
                    pass
                try:
                    self.j2534.Functions.FreeLibrary()
                except Exception:
                    pass
                self.connected = False
                self.msg_queue.put(("connection", False))

        threading.Thread(target=worker, daemon=True).start()


    def _disconnect_vehicle(self):
        def worker():
            try:
                self.log_message("Disconnecting...", "info")
                try:
                    if getattr(self.j2534, "FilterID", -1) not in (-1, None):
                        self.j2534.Functions.PassThruStopMsgFilter(self.j2534.ChannelID, self.j2534.FilterID)
                        self.j2534.FilterID = -1
                except Exception:
                    pass
                try:
                    if getattr(self.j2534, "ChannelID", 0):
                        self.j2534.Functions.PassThruDisconnect(self.j2534.ChannelID)
                        self.j2534.ChannelID = 0
                except Exception:
                    pass
                try:
                    if getattr(self.j2534, "DeviceID", 0):
                        self.j2534.Functions.PassThruClose(self.j2534.DeviceID)
                        self.j2534.DeviceID = 0
                except Exception:
                    pass
                try:
                    self.j2534.Functions.FreeLibrary()
                except Exception:
                    pass

                self.connected = False
                self.msg_queue.put(("connection", False))
                self.log_message("Disconnected", "info")
            except Exception as e:
                self.log_message(f"Disconnect error: {e}", "error")

        threading.Thread(target=worker, daemon=True).start()
        

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
        import math; pts=[]
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
        top = tk.Frame(w, bg="#ffffff"); top.pack(fill="x")
        if self._img.get("logo_64"):
            tk.Label(top, image=self._img["logo_64"], bg="#ffffff").pack(pady=(8, 4))
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
        top = tk.Frame(w, bg="#ffffff"); top.pack(fill="x")
        if self._img.get("logo_64"):
            tk.Label(top, image=self._img["logo_64"], bg="#ffffff").pack(pady=(8, 4))
        tk.Label(top, text="PyForce – J2534 Diagnostic Software", bg="#ffffff", fg="#333", font=("Segoe UI", 12, "bold")).pack()
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
