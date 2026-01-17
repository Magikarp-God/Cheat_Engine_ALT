import pymem
import pymem.memory
import struct
import threading
import time
import json
import tkinter as tk
from tkinter import ttk, simpledialog
from concurrent.futures import ThreadPoolExecutor

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

DTYPES = {
    "int": ("<i", 4),
    "float": ("<f", 4),
    "double": ("<d", 8),
}

# ================= ENGINE =================

class MiniEngine:
    def __init__(self):
        self.pm = None
        self.results = {}
        self.saved = {}
        self.dtype = "int"

    def attach(self, pid):
        self.pm = pymem.Pymem()
        self.pm.open_process_from_id(pid)
        self.start_worker()

    def read_val(self, addr, dtype):
        try:
            if dtype == "int":
                return self.pm.read_int(addr)
            if dtype == "float":
                return self.pm.read_float(addr)
            if dtype == "double":
                return self.pm.read_double(addr)
        except:
            return None

    def write_val(self, addr, dtype, val):
        try:
            if dtype == "int":
                self.pm.write_int(addr, int(val))
            elif dtype == "float":
                self.pm.write_float(addr, float(val))
            elif dtype == "double":
                self.pm.write_double(addr, float(val))
        except:
            pass

    # ---------- SCANNING ----------

    def scan_region(self, base, size, value, mode):
        hits = {}
        fmt, step = DTYPES[self.dtype]
        try:
            data = self.pm.read_bytes(base, size)
            for i in range(0, len(data) - step, step):
                val = struct.unpack(fmt, data[i:i+step])[0]
                if mode == "unknown" or val == value:
                    hits[base + i] = val
        except:
            pass
        return hits

    def scan(self, value=None, mode="exact"):
        self.results.clear()
        max_addr = 0x7FFFFFFFFFFF
        tasks = []

        with ThreadPoolExecutor(max_workers=4) as exe:
            addr = 0
            while addr < max_addr:
                try:
                    mbi = pymem.memory.virtual_query(self.pm.process_handle, addr)
                    if (
                        mbi.State == MEM_COMMIT and
                        not (mbi.Protect & PAGE_GUARD) and
                        not (mbi.Protect & PAGE_NOACCESS)
                    ):
                        tasks.append(
                            exe.submit(
                                self.scan_region,
                                mbi.BaseAddress,
                                mbi.RegionSize,
                                value,
                                mode
                            )
                        )
                    addr = mbi.BaseAddress + mbi.RegionSize
                except:
                    addr += 0x1000

            for t in tasks:
                self.results.update(t.result())

    def next_scan(self, value=None, mode="exact"):
        new = {}
        for addr, old in self.results.items():
            try:
                cur = self.pm.read_int(addr)
                if (
                    (mode == "exact" and cur == value) or
                    (mode == "changed" and cur != old) or
                    (mode == "unchanged" and cur == old)
                ):
                    new[addr] = cur
            except:
                pass
        self.results = new

    # ---------- BACKGROUND WORKER ----------

    def start_worker(self):
        def worker():
            while True:
                for addr, meta in list(self.saved.items()):
                    real_addr = addr

                    # Pointer resolution (manual base + offsets)
                    if meta["pointer"]:
                        base, offsets = meta["pointer"]
                        try:
                            real_addr = self.pm.read_int(base)
                            for off in offsets:
                                real_addr = self.pm.read_int(real_addr + off)
                        except:
                            continue

                    live = self.read_val(real_addr, meta["type"])
                    meta["live"] = live

                    if meta["freeze"]:
                        self.write_val(real_addr, meta["type"], meta["value"])

                time.sleep(0.15)

        threading.Thread(target=worker, daemon=True).start()

engine = MiniEngine()

# ================= GUI =================

root = tk.Tk()
root.title("Mini Memory Tool (Complete)")

pid_var = tk.StringVar()
value_var = tk.StringVar()
dtype_var = tk.StringVar(value="int")
status = tk.StringVar(value="Idle")

# ---------- TABLES ----------

scan_table = ttk.Treeview(root, columns=("addr", "val"), show="headings", height=6)
scan_table.heading("addr", text="Address")
scan_table.heading("val", text="Value")
scan_table.grid(row=6, column=0, columnspan=4, sticky="nsew")

saved_table = ttk.Treeview(
    root,
    columns=("addr", "type", "live", "set", "freeze", "label", "group"),
    show="headings",
    height=7
)
for c in ("addr", "type", "live", "set", "freeze", "label", "group"):
    saved_table.heading(c, text=c.capitalize())
saved_table.grid(row=9, column=0, columnspan=4, sticky="nsew")

# ---------- REFRESH ----------

def refresh_scan():
    scan_table.delete(*scan_table.get_children())
    for addr, val in list(engine.results.items())[:300]:
        scan_table.insert("", "end", values=(hex(addr), val))

def refresh_saved():
    saved_table.delete(*saved_table.get_children())
    for addr, m in engine.saved.items():
        saved_table.insert("", "end", values=(
            hex(addr),
            m["type"],
            m.get("live"),
            m["value"],
            m["freeze"],
            m["label"],
            m["group"]
        ))

# ---------- ACTIONS ----------

def attach():
    engine.attach(int(pid_var.get()))
    status.set("Attached")

def first_exact():
    engine.dtype = dtype_var.get()
    engine.scan(float(value_var.get()), "exact")
    refresh_scan()
    status.set(len(engine.results))

def first_unknown():
    engine.dtype = dtype_var.get()
    engine.scan(mode="unknown")
    refresh_scan()
    status.set(len(engine.results))

def next_exact():
    engine.next_scan(float(value_var.get()), "exact")
    refresh_scan()
    status.set(len(engine.results))

def next_changed():
    engine.next_scan(mode="changed")
    refresh_scan()
    status.set(len(engine.results))

def next_unchanged():
    engine.next_scan(mode="unchanged")
    refresh_scan()
    status.set(len(engine.results))

def save_selected():
    label = simpledialog.askstring("Label", "Description / label:")
    group = simpledialog.askstring("Group", "Group name:")
    for sel in scan_table.selection():
        addr = int(scan_table.item(sel)["values"][0], 16)
        engine.saved[addr] = {
            "type": dtype_var.get(),
            "value": float(value_var.get()),
            "freeze": False,
            "label": label or "",
            "group": group or "",
            "pointer": None,
            "live": None
        }
    refresh_saved()

def set_selected():
    for sel in saved_table.selection():
        addr = int(saved_table.item(sel)["values"][0], 16)
        engine.saved[addr]["value"] = float(value_var.get())
    refresh_saved()

def toggle_freeze():
    for sel in saved_table.selection():
        addr = int(saved_table.item(sel)["values"][0], 16)
        engine.saved[addr]["freeze"] = not engine.saved[addr]["freeze"]
    refresh_saved()

def freeze_group():
    g = simpledialog.askstring("Freeze Group", "Group name:")
    for m in engine.saved.values():
        if m["group"] == g:
            m["freeze"] = True
    refresh_saved()

def validate():
    dead = []
    for addr, m in engine.saved.items():
        if engine.read_val(addr, m["type"]) is None:
            dead.append(addr)
    for d in dead:
        del engine.saved[d]
    refresh_saved()
    status.set(f"Removed {len(dead)} invalid")

# ---------- UI ----------

tk.Label(root, text="PID").grid(row=0, column=0)
tk.Entry(root, textvariable=pid_var).grid(row=0, column=1)
tk.Button(root, text="Attach", command=attach).grid(row=0, column=2)

tk.Label(root, text="Value").grid(row=1, column=0)
tk.Entry(root, textvariable=value_var).grid(row=1, column=1)
tk.OptionMenu(root, dtype_var, *DTYPES.keys()).grid(row=1, column=2)

tk.Button(root, text="First Exact", command=first_exact).grid(row=2, column=0)
tk.Button(root, text="First Unknown", command=first_unknown).grid(row=2, column=1)

tk.Button(root, text="Next Exact", command=next_exact).grid(row=3, column=0)
tk.Button(root, text="Changed", command=next_changed).grid(row=3, column=1)
tk.Button(root, text="Unchanged", command=next_unchanged).grid(row=3, column=2)

tk.Button(root, text="Save → Table", command=save_selected).grid(row=7, column=0)
tk.Button(root, text="Set Value", command=set_selected).grid(row=7, column=1)
tk.Button(root, text="Freeze Selected", command=toggle_freeze).grid(row=7, column=2)
tk.Button(root, text="Freeze Group", command=freeze_group).grid(row=7, column=3)

tk.Button(root, text="Validate Addresses", command=validate)\
    .grid(row=11, column=0, columnspan=4)

tk.Label(root, textvariable=status).grid(row=12, column=0, columnspan=4)

root.mainloop()
