import tkinter as tk
from tkinter import messagebox
from .gui.main_window import J2534DiagnosticApp
from .gui.live_data import LiveDataWindow

def main():
    app = J2534DiagnosticApp()
    menubar = tk.Menu(app); app.config(menu=menubar)

    file_menu = tk.Menu(menubar, tearoff=0); menubar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="New Session", command=lambda: app.log_message("New session started","info"))
    file_menu.add_command(label="Open Log...", command=lambda: app.log_message("Open log file","info"))
    file_menu.add_command(label="Save Log...", command=app._save_log)
    file_menu.add_separator(); file_menu.add_command(label="Exit", command=app._on_close)

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

    app.log_message("J2534 Diagnostic Software started","info")
    app.log_message("Ready to connect to vehicle","info")
    app.mainloop()

if __name__ == "__main__":
    main()
