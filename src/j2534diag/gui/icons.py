import tkinter as tk
def paint_car(c: tk.Canvas):
    c.create_rectangle(6,18,30,26, fill="#2b7", outline="")
    c.create_polygon(6,18,12,12,24,12,30,18, fill="#2b7", outline="")
    c.create_oval(9,26,15,32, fill="#111", outline="")
    c.create_oval(21,26,27,32, fill="#111", outline="")
    c.create_rectangle(14,14,22,18, fill="#dff", outline="")
# ... include the rest: paint_dtc, paint_scope, paint_check, paint_wrench, paint_chip, paint_gear, paint_help, paint_save, paint_folder
ICON_PAINTERS = {
    "car": paint_car, # ... map all painters
}
