# main.py
# FucyFuzz DBC viewer + CaringCaribou integration

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import random
import threading
import subprocess
import time
import sys
import os
import re
import tempfile
from datetime import datetime
import json
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import can

# Import helpers
from helpers import *
from report_helpers import *

# ----------- CONFIGURATION -----------
CARING_CARIBOU_PATH = "/home/fucy-can/FUCY/caringcaribou_fresh"

# ----------- STYLES -----------
BG_COLOR = "#ffffff"
HEADER_COLOR = "#e7f0ff"
BUTTON_COLOR = "#0078d7"
TEXT_COLOR = "#000000"

root = tk.Tk()
root.title("FucyFuzz")
root.geometry("1400x900")
root.configure(bg=BG_COLOR)

style = ttk.Style()
style.theme_use("default")
style.configure("Treeview",
                background="#ffffff",
                foreground="#000000",
                rowheight=25,
                fieldbackground="#ffffff",
                font=("Segoe UI", 10))
style.configure("Treeview.Heading",
                font=("Segoe UI", 10, "bold"),
                background=HEADER_COLOR,
                foreground="#000000")
style.map("Treeview", background=[("selected", "#cce5ff")])

# ----------- GLOBAL LOG STORAGE -----------
root.all_logs = []
root.all_reports = []

# ----------- TOP BAR -----------
toolbar = tk.Frame(root, bg=HEADER_COLOR, height=50)
toolbar.pack(fill="x", padx=0, pady=5)

btn_open = tk.Button(toolbar, text="Import DBC", bg=BUTTON_COLOR, fg="white",
                     font=("Segoe UI", 10, "bold"), relief="flat", width=15, 
                     command=lambda: import_dbc(root))
btn_open.pack(side="left", padx=10, pady=5)

# Add Overall Report button
btn_overall_report = tk.Button(toolbar, text="Overall Report", bg="#28a745", fg="white",
                              font=("Segoe UI", 10, "bold"), relief="flat", width=15,
                              command=lambda: save_overall_report_dialog(root))
btn_overall_report.pack(side="left", padx=10, pady=5)

# Add Overall Logs button
btn_overall_logs = tk.Button(toolbar, text="Overall Logs", bg="#ffc107", fg="black",
                            font=("Segoe UI", 10, "bold"), relief="flat", width=15,
                            command=lambda: view_overall_logs_dialog(root))
btn_overall_logs.pack(side="left", padx=10, pady=5)

# Add Question Mark Icon in top right corner
question_icon_btn = tk.Button(toolbar, text="?", bg=HEADER_COLOR, fg=BUTTON_COLOR,
                           font=("Segoe UI", 14, "bold"), relief="flat", width=3,
                           command=lambda: run_caringcaribou_help(root))
question_icon_btn.pack(side="right", padx=10, pady=5)

# ----------- CAN MESSAGES -----------
msg_frame = tk.LabelFrame(root, text="CAN Messages", bg=BG_COLOR, fg=TEXT_COLOR,
                          font=("Segoe UI", 11, "bold"), bd=1)
msg_frame.pack(fill="x", padx=10, pady=5)

msg_scroll_y = ttk.Scrollbar(msg_frame, orient="vertical")
msg_scroll_y.pack(side="right", fill="y")

msg_table = ttk.Treeview(msg_frame, columns=("Name", "CAN_ID", "Type", "DLC", "Comment"),
                         show="headings", height=7, yscrollcommand=msg_scroll_y.set)
msg_scroll_y.config(command=msg_table.yview)

for col in ("Name", "CAN_ID", "Type", "DLC", "Comment"):
    msg_table.heading(col, text=col)
    msg_table.column(col, anchor="center", width=150)
msg_table.pack(fill="x", padx=10, pady=5)
msg_table.bind("<<TreeviewSelect>>", lambda event: on_message_select(root, msg_table, sig_table, dbc_text, bit_table_frame, bit_canvas))

# ----------- CAN SIGNALS -----------
sig_frame = tk.LabelFrame(root, text="CAN Signals", bg=BG_COLOR, fg=TEXT_COLOR,
                          font=("Segoe UI", 11, "bold"), bd=1)
sig_frame.pack(fill="x", padx=10, pady=5)

sig_scroll_y = ttk.Scrollbar(sig_frame, orient="vertical")
sig_scroll_y.pack(side="right", fill="y")

sig_table = ttk.Treeview(sig_frame, columns=("Name", "Start", "Length", "Factor", "Offset", "Min", "Max", "Unit"),
                         show="headings", height=7, yscrollcommand=sig_scroll_y.set)
sig_scroll_y.config(command=sig_table.yview)

for col in ("Name", "Start", "Length", "Factor", "Offset", "Min", "Max", "Unit"):
    sig_table.heading(col, text=col)
    sig_table.column(col, anchor="center", width=100)
sig_table.pack(fill="x", padx=10, pady=5)

# ----------- BUTTONS ABOVE DBC PREVIEW -----------
button_frame = tk.Frame(root, bg=BG_COLOR)
button_frame.pack(fill="x", padx=10, pady=(5, 0))

button_style = {
    "bg": BUTTON_COLOR,
    "fg": "white",
    "font": ("Segoe UI", 10, "bold"),
    "relief": "flat",
    "width": 15,
    "height": 1,
    "activebackground": "#005a9e"
}

btn_fuzzer = tk.Button(button_frame, text="Signal Fuzzing", **button_style)
btn_length_attack = tk.Button(button_frame, text="Length Attack", **button_style)
btn_uds_fuzz = tk.Button(button_frame, text="Replay Attack", **button_style)
btn_doip = tk.Button(button_frame, text="Scan DID's", **button_style)

btn_fuzzer.pack(side="left", padx=5, pady=5)
btn_length_attack.pack(side="left", padx=5, pady=5)
btn_uds_fuzz.pack(side="left", padx=5, pady=5)
btn_doip.pack(side="left", padx=5, pady=5)

# ----------- SPLIT (BOTTOM) -----------
bottom_split = tk.PanedWindow(root, orient="horizontal", sashrelief="raised", sashwidth=6, bg=BG_COLOR)
bottom_split.pack(fill="both", expand=True, padx=10, pady=5)

# Left side: DBC Preview
dbc_frame = tk.LabelFrame(bottom_split, text="DBC Preview", bg=BG_COLOR, fg=TEXT_COLOR,
                          font=("Segoe UI", 11, "bold"), bd=1)
dbc_text = tk.Text(dbc_frame, bg="#f5f5f5", fg="#000000", font=("Consolas", 10), wrap="word")
dbc_scroll_y = ttk.Scrollbar(dbc_frame, orient="vertical", command=dbc_text.yview)
dbc_text.configure(yscrollcommand=dbc_scroll_y.set)
dbc_scroll_y.pack(side="right", fill="y")
dbc_text.pack(fill="both", expand=True, padx=10, pady=10)
dbc_text.insert(tk.END, "Select a CAN message to view its DBC structure here...")

# Right side: Bit Mapping
bit_frame = tk.LabelFrame(bottom_split, text="Bit Mapping (0–63 bits)", bg=BG_COLOR, fg=TEXT_COLOR,
                          font=("Segoe UI", 11, "bold"), bd=1)
bit_canvas = tk.Canvas(bit_frame, bg="#ffffff")
bit_scroll_x = ttk.Scrollbar(bit_frame, orient="horizontal", command=bit_canvas.xview)
bit_scroll_y = ttk.Scrollbar(bit_frame, orient="vertical", command=bit_canvas.yview)
bit_canvas.configure(xscrollcommand=bit_scroll_x.set, yscrollcommand=bit_scroll_y.set)
bit_scroll_x.pack(side="bottom", fill="x")
bit_scroll_y.pack(side="right", fill="y")
bit_canvas.pack(fill="both", expand=True)
bit_table_frame = tk.Frame(bit_canvas, bg="#ffffff")
bit_canvas.create_window((0, 0), window=bit_table_frame, anchor="nw")

bottom_split.add(dbc_frame, stretch="always")
bottom_split.add(bit_frame, stretch="always")
root.update_idletasks()
bottom_split.sash_place(0, int(root.winfo_width() * 0.4), 0)

# ----------- APPEND: CAN + CaringCaribou Integration (DO NOT REMOVE) -----------
# Try to import python-can but keep the UI usable even if it's missing
try:
    _PYTHON_CAN_AVAILABLE = True
except Exception:
    _PYTHON_CAN_AVAILABLE = False

# --- simple CAN Log widget (non-destructive, added at bottom) ---
log_frame = tk.LabelFrame(root, text="CAN / CaringCaribou Log", bg=BG_COLOR, fg=TEXT_COLOR,
                          font=("Segoe UI", 11, "bold"), bd=1)
log_frame.pack(fill="both", padx=10, pady=(0,10), expand=False)
log_text = tk.Text(log_frame, height=8, state='disabled', bg="#111", fg="#eee", font=("Consolas", 10))
log_text.pack(fill="both", padx=8, pady=8)

# Initialize helpers
initialize_helpers(root, log_text, dbc_text, msg_table, sig_table, bit_table_frame, bit_canvas)

# Wire up buttons
try:
    btn_fuzzer.config(command=lambda: open_fuzz_popup(root))
except Exception:
    pass

try:
    btn_length_attack.config(command=lambda: open_length_attack_popup(root))
except Exception:
    pass

# Add Send Signal button
try:
    btn_send_signal = tk.Button(root, text="Send Signal", bg="#28a745", fg="white",
                                font=("Segoe UI", 10, "bold"), relief="flat", width=15,
                                command=lambda: messagebox.showinfo("Send Signal", "Use the existing Send Signal UI."))
    try:
        btn_send_signal.pack(side="left", padx=5, pady=5)
    except Exception:
        btn_send_signal.pack(padx=5, pady=5)
except Exception:
    pass

# ----------- INIT -----------
root.current_signals_dict = {}
root.frameid_to_name = {}

root.mainloop()