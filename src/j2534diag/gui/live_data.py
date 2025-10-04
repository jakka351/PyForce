import tkinter as tk
from tkinter import ttk
class LiveDataWindow(tk.Toplevel):
    # paste your LiveDataWindow here unchanged
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