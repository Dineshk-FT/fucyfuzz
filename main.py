# main.py
# FucyFuzz DBC viewer + CaringCaribou integration
# Replaced cantools with a lightweight internal DBC parser (no external dependency)

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

# ----------- SIMPLE DBC PARSER (replaces cantools) -----------
# This parser handles typical Vector-style DBC message (BO_) and signal (SG_)
# lines. It's intentionally lightweight and avoids external deps.
#
# Notes:
# - Supports message ID (hex or decimal), name, dlc/length.
# - Supports signal: name, start bit, length, byte order & sign ignored for now,
#   factor/offset in parentheses (a,b), min|max in brackets, unit in quotes.
# - Parses comments on BO_ (trailing // or ; comment handling is simple).
#
# If you want full DBC feature coverage (multiplexing, complex attributes),
# consider using `canmatrix` (canmatrix.readthedocs.io) — I can switch it later.

_re_bo = re.compile(r'^\s*BO\_\s+(\d+|0x[0-9A-Fa-f]+)\s+(\w+)\s*:\s*(\d+)\s+')
# SG_ <name> : <start>|<length>@<endian><sign> (<factor>,<offset>) \[<min>|<max>\] "<unit>"
_re_sg = re.compile(
    r'^\s*SG\_\s+(\w+)\s*:\s*(\d+)\|(\d+)@([01])([+-])\s*\(\s*([0-9eE+.-]+)\s*,\s*([0-9eE+.-]+)\s*\)\s*\[\s*([0-9eE+.-]+)\s*\|\s*([0-9eE+.-]+)\s*\]\s*"([^"]*)"\s*'
)
# fallback signal regex (less strict) to capture common variants
_re_sg_loose = re.compile(
    r'^\s*SG\_\s+(\w+)\s*:\s*(\d+)\|(\d+)[^\(]*\(\s*([0-9eE+.-]+)\s*,\s*([0-9eE+.-]+)\s*\)[^\[]*\[\s*([0-9eE+.-]+)\s*\|\s*([0-9eE+.-]+)\s*\]\s*"([^"]*)"?'
)

def parse_dbc_content(content):
    """
    Parse DBC content string and return:
      - messages: list of dicts with Name, CAN_ID, FrameID, Type, DLC, Comment
      - signals_dict: { message_name: [ signals... ] }
      - frameid_to_name: { frame_id_int: message_name }
    This is a pragmatic parser that covers the common DBC layout.
    """
    messages = []
    signals_dict = {}
    frameid_to_name = {}

    lines = content.splitlines()
    current_msg = None
    current_msg_comment = ""
    for i, raw in enumerate(lines):
        line = raw.rstrip()
        # skip empty or comment-only lines
        if not line.strip():
            continue

        # Found message definition
        m = _re_bo.match(line)
        if m:
            id_text = m.group(1)
            name = m.group(2)
            dlc = int(m.group(3))
            try:
                frame_id = int(id_text, 0)
            except Exception:
                # fallback: if id is decimal string
                try:
                    frame_id = int(id_text)
                except Exception:
                    frame_id = 0
            # store previous message
            if current_msg:
                # finalize previous
                messages.append(current_msg)
            msg_type = "Standard"
            current_msg = {
                "Name": name,
                "CAN_ID": hex(frame_id),
                "FrameID": frame_id,
                "Type": msg_type,
                "DLC": dlc,
                "Comment": ""
            }
            signals_dict[name] = []
            frameid_to_name[frame_id] = name
            continue

        # Signal lines (SG_)
        if current_msg:
            ms = _re_sg.match(line)
            if ms:
                sig_name = ms.group(1)
                start = int(ms.group(2))
                length = int(ms.group(3))
                factor = float(ms.group(6)) if ms.group(6) else None
                offset = float(ms.group(7)) if ms.group(7) else None
                minv = float(ms.group(8)) if ms.group(8) else None
                maxv = float(ms.group(9)) if ms.group(9) else None
                unit = ms.group(10) or ""
                signals_dict[current_msg["Name"]].append({
                    "Name": sig_name,
                    "Start": start,
                    "Length": length,
                    "Factor": factor,
                    "Offset": offset,
                    "Min": minv,
                    "Max": maxv,
                    "Unit": unit
                })
                continue

            # try loose signal match if strict failed
            ms2 = _re_sg_loose.match(line)
            if ms2:
                sig_name = ms2.group(1)
                start = int(ms2.group(2))
                length = int(ms2.group(3))
                factor = float(ms2.group(4)) if ms2.group(4) else None
                offset = float(ms2.group(5)) if ms2.group(5) else None
                minv = float(ms2.group(6)) if ms2.group(6) else None
                maxv = float(ms2.group(7)) if ms2.group(7) else None
                unit = ms2.group(8) or ""
                signals_dict[current_msg["Name"]].append({
                    "Name": sig_name,
                    "Start": start,
                    "Length": length,
                    "Factor": factor,
                    "Offset": offset,
                    "Min": minv,
                    "Max": maxv,
                    "Unit": unit
                })
                continue

            # comments attached to BO_ lines (some DBCs put comments in lines starting with CM_ )
            if line.strip().startswith("CM_ BO_"):
                # example: CM_ BO_ 123 "some comment";
                try:
                    parts = line.split(None, 3)
                    if len(parts) >= 4:
                        # the comment may be in quotes
                        comm = parts[3].strip()
                        # remove leading message id if present
                        # Try to extract quoted text
                        q = re.search(r'\"(.+?)\"', comm)
                        if q:
                            comm_text = q.group(1)
                        else:
                            comm_text = comm.strip().rstrip(';')
                        if current_msg:
                            current_msg["Comment"] = comm_text
                except Exception:
                    pass
                continue

        # If we find a new BO_ we handled earlier; otherwise ignore unrelated tokens

    # finalize last message
    if current_msg:
        messages.append(current_msg)

    # ensure signals_dict entries exist for messages
    # (signals_dict keys already created on BO_)
    return messages, signals_dict, frameid_to_name

# ----------- IMPORT DBC FUNCTION -----------
def import_dbc():
    file_path = filedialog.askopenfilename(
        title="Select DBC File",
        filetypes=[("DBC files", "*.dbc"), ("All files", "*.*")]
    )
    if not file_path:
        return

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            dbc_content = file.read()

        messages, signals_dict, frameid_map = parse_dbc_content(dbc_content)
        root.current_signals_dict = signals_dict
        root.dbc_content = dbc_content
        root.frameid_to_name = frameid_map

        for item in msg_table.get_children():
            msg_table.delete(item)

        for m in messages:
            msg_table.insert("", "end", values=(m["Name"], m["CAN_ID"], m["Type"], m["DLC"], m["Comment"]))

        messagebox.showinfo("Success", f"Loaded {len(messages)} messages from DBC file.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to import DBC file:\n{str(e)}")

# ----------- MESSAGE SELECTION HANDLER -----------
def on_message_select(event=None):
    selection = msg_table.selection()
    if not selection:
        return
    item = selection[0]
    msg_name = msg_table.item(item, "values")[0]

    for i in sig_table.get_children():
        sig_table.delete(i)

    if msg_name in root.current_signals_dict:
        signals = root.current_signals_dict[msg_name]
        for s in signals:
            sig_table.insert("", "end", values=(s["Name"], s["Start"], s["Length"], s["Factor"],
                                                s["Offset"], s["Min"], s["Max"], s["Unit"]))
        update_dbc_preview(msg_name)
        update_bit_mapping(signals)

# ----------- DBC PREVIEW UPDATE -----------
def update_dbc_preview(msg_name):
    dbc_text.delete(1.0, tk.END)
    dbc_text.insert(tk.END, f"BO_ {msg_name}:\n")
    for s in root.current_signals_dict.get(msg_name, []):
        dbc_text.insert(
            tk.END,
            f" SG_ {s['Name']} : {s['Start']}|{s['Length']} "
            f"({s['Factor']},{s['Offset']}) [{s['Min']}|{s['Max']}] "
            f"\"{s['Unit']}\"\n"
        )

# ----------- BIT MAPPING VISUALIZATION -----------
def update_bit_mapping(signals):
    for widget in bit_table_frame.winfo_children():
        widget.destroy()

    header_font = ("Segoe UI", 10, "bold")
    cell_font = ("Segoe UI", 9)

    tk.Label(bit_table_frame, text="Signal Name", font=header_font, bg="#e0e0e0",
             fg="#000000", width=14, relief="ridge").grid(row=0, column=0, sticky="nsew")

    for i in range(64):
        tk.Label(bit_table_frame, text=f"{i}", font=header_font, bg="#e0e0e0",
                 fg="#000000", width=3, relief="ridge").grid(row=0, column=i + 1, sticky="nsew")

    colors = ["#add8e6", "#90ee90", "#f4a261", "#ffcccb", "#b19cd9", "#87cefa", "#ffb347"]
    row_idx = 1

    for sig in signals:
        try:
            start = int(sig["Start"])
            length = int(sig["Length"])
        except Exception:
            continue

        color = random.choice(colors)
        tk.Label(bit_table_frame, text=sig["Name"], bg="#fafafa", fg="#000000",
                 font=cell_font, width=14, relief="ridge").grid(row=row_idx, column=0, sticky="nsew")

        for bit in range(64):
            bg_color = color if start <= bit < start + length else "#ffffff"
            tk.Label(bit_table_frame, text="", bg=bg_color, width=3, height=1,
                     relief="ridge").grid(row=row_idx, column=bit + 1, sticky="nsew")
        row_idx += 1

    bit_table_frame.update_idletasks()
    bit_canvas.config(scrollregion=bit_canvas.bbox("all"))

# ----------- TOP BAR -----------
toolbar = tk.Frame(root, bg=HEADER_COLOR, height=50)
toolbar.pack(fill="x", padx=0, pady=5)

btn_open = tk.Button(toolbar, text="Import DBC", bg=BUTTON_COLOR, fg="white",
                     font=("Segoe UI", 10, "bold"), relief="flat", width=15, command=import_dbc)
btn_open.pack(side="left", padx=10, pady=5)

# Add Question Mark Icon in top right corner
question_icon_btn = tk.Button(toolbar, text="?", bg=HEADER_COLOR, fg=BUTTON_COLOR,
                           font=("Segoe UI", 14, "bold"), relief="flat", width=3,
                           command=lambda: run_caringcaribou_help())
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
msg_table.bind("<<TreeviewSelect>>", on_message_select)

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

btn_length_attack = tk.Button(button_frame, text="Length Attack", **button_style)
btn_fuzzer = tk.Button(button_frame, text="Signal Fuzzing", **button_style)
btn_uds_fuzz = tk.Button(button_frame, text="Replay Attack", **button_style)
btn_doip = tk.Button(button_frame, text="Scan DID's", **button_style)

btn_length_attack.pack(side="left", padx=5, pady=5)
btn_fuzzer.pack(side="left", padx=5, pady=5)
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
    import can
    _PYTHON_CAN_AVAILABLE = True
except Exception:
    _PYTHON_CAN_AVAILABLE = False

# --- simple CAN Log widget (non-destructive, added at bottom) ---
log_frame = tk.LabelFrame(root, text="CAN / CaringCaribou Log", bg=BG_COLOR, fg=TEXT_COLOR,
                          font=("Segoe UI", 11, "bold"), bd=1)
log_frame.pack(fill="both", padx=10, pady=(0,10), expand=False)
log_text = tk.Text(log_frame, height=8, state='disabled', bg="#111", fg="#eee", font=("Consolas", 10))
log_text.pack(fill="both", padx=8, pady=8)

def append_log(text):
    """Append timestamped line to the log widget (thread-safe)."""
    def _append():
        log_text.config(state='normal')
        if isinstance(text, str):
            txt = text.rstrip("\n")
        else:
            txt = str(text)
        log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {txt}\n")
        log_text.see(tk.END)
        log_text.config(state='disabled')
    root.after(0, _append)

# --- CAN helpers (uses python-can if available) ---
def create_can_bus(interface_name):
    if not _PYTHON_CAN_AVAILABLE:
        raise ImportError("python-can is not installed.")
    try:
        bus = can.interface.Bus(channel=interface_name, bustype='socketcan')
        return bus
    except Exception as e:
        try:
            bus = can.interface.Bus(interface_name)
            return bus
        except Exception:
            raise RuntimeError(f"Failed to open CAN bus ({interface_name}): {e}")

def send_can_message(arbitration_id, data_bytes, is_extended_id=False, interface="vcan0"):
    def _send():
        try:
            if not _PYTHON_CAN_AVAILABLE:
                append_log("python-can not installed: cannot send frame.")
                messagebox.showerror("python-can missing", "python-can is not installed. Install it to send frames.")
                return
            bus = create_can_bus(interface)
            msg = can.Message(arbitration_id=arbitration_id, data=data_bytes, is_extended_id=is_extended_id)
            bus.send(msg)
            try:
                bus.shutdown()
            except Exception:
                pass
            append_log(f"Sent CAN ID=0x{arbitration_id:x} DATA={' '.join(f'{b:02X}' for b in data_bytes)} on {interface}")
        except Exception as exc:
            append_log(f"Send failed: {exc}")
            def show_err():
                messagebox.showerror("CAN Send Error", f"Failed to send CAN message:\n{exc}")
            root.after(0, show_err)
    threading.Thread(target=_send, daemon=True).start()

# --- Parse caringcaribou lenattack output (keeps original logic) ---
def parse_and_update_from_lenattack(output_text, original_dbc_content):
    try:
        discovered_messages = []
        lines = output_text.split('\n')
        patterns = [
            r'Found message with ID\s+(0x[0-9a-fA-F]+|\d+).*?DLC\s+(\d+)',
            r'Message\s+(0x[0-9a-fA-F]+|\d+).*?length\s*[:=]\s*(\d+)',
            r'ID\s*(0x[0-9a-fA-F]+|\d+).*?DLC\s*[:=]\s*(\d+)',
            r'(0x[0-9a-fA-F]+|\d+)\s+.*?(\d+)\s+bytes?'
        ]
        import re
        for line in lines:
            line = line.strip()
            append_log(f"🔍 Parsing line: {line}")
            for pattern in patterns:
                matches = re.findall(pattern, line, re.IGNORECASE)
                for match in matches:
                    if len(match) >= 2:
                        try:
                            can_id = int(match[0], 0)
                            dlc = int(match[1])
                            discovered_messages.append({
                                'id': can_id,
                                'dlc': dlc,
                                'line': line
                            })
                            append_log(f"✅ Found message: ID=0x{can_id:x}, DLC={dlc}")
                        except ValueError:
                            continue

        if discovered_messages:
            summary = "=== LENGTH ATTACK RESULTS ===\n\n"
            summary += f"Discovered {len(discovered_messages)} potential messages:\n\n"
            for msg in discovered_messages:
                summary += f"ID: 0x{msg['id']:x} | DLC: {msg['dlc']}\n"
                summary += f"Raw: {msg['line']}\n\n"
            return summary
        else:
            return "Length attack completed. No new messages discovered in the output.\n\nRaw output was:\n" + output_text[-1000:]
    except Exception as e:
        return f"Error parsing lenattack results: {str(e)}\n\nRaw output:\n{output_text[-1000:]}"

# --- CaringCaribou integration / runner (keeps original behavior) ---
def run_caringcaribou_help():
    def _run_help():
        try:
            args = ["/usr/bin/python", "-m", "caringcaribou.caringcaribou", "--help"]
            working_dir = CARING_CARIBOU_PATH
            append_log(f"🔍 Running Help Command: {' '.join(args)}")
            append_log(f"📁 Working directory: {os.getcwd()}")
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                cwd=working_dir,
                env={"PYTHONPATH": working_dir, **os.environ}
            )
            stdout, stderr = proc.communicate(timeout=15)
            def update_preview():
                dbc_text.delete(1.0, tk.END)
                dbc_text.insert(tk.END, "=== CARING CARIBOU HELP ===\n\n")
                if stdout:
                    dbc_text.insert(tk.END, stdout)
                    append_log("✅ Help command completed successfully")
                    if "lenattack" in stdout:
                        append_log("✓ lenattack module is available")
                    else:
                        append_log("⚠ lenattack module NOT found")
                if stderr:
                    dbc_text.insert(tk.END, "\n=== ERRORS ===\n")
                    dbc_text.insert(tk.END, stderr)
                    append_log(f"❌ Help command errors: {stderr}")
            root.after(0, update_preview)
        except subprocess.TimeoutExpired:
            append_log("❌ Help command timed out after 15 seconds")
            root.after(0, lambda: messagebox.showerror("Timeout", "Help command timed out"))
        except FileNotFoundError:
            error_msg = "❌ CaringCaribou not found at /usr/bin/python -m caringcaribou.caringcaribou"
            append_log(error_msg)
            root.after(0, lambda: messagebox.showerror("Not Found", error_msg))
        except Exception as e:
            append_log(f"💥 Error running help command: {e}")
            root.after(0, lambda: messagebox.showerror("Error", f"Failed to run help: {e}"))
    threading.Thread(target=_run_help, daemon=True).start()

def check_caringcaribou_installation():
    try:
        result = subprocess.run(["/usr/bin/python", "-m", "caringcaribou.caringcaribou", "--version"],
                                capture_output=True, text=True, timeout=10,
                                cwd=CARING_CARIBOU_PATH,
                                env={"PYTHONPATH": CARING_CARIBOU_PATH, **os.environ})
        if result.returncode == 0:
            append_log(f"CaringCaribou found: {result.stdout.strip()}")
            return True
        else:
            append_log(f"CaringCaribou check failed: {result.stderr}")
            return False
    except Exception as e:
        append_log(f"CaringCaribou not accessible: {e}")
        return False

check_caringcaribou_installation()

def run_caringcaribou_cmd(args_list, is_lenattack=False, is_fuzzer=False):
    def _run():
        try:
            if args_list[0] == sys.executable and "-m" in args_list and "caringcaribou" in args_list:
                args_list[0] = "/usr/bin/python"
            working_dir = CARING_CARIBOU_PATH
            env = {"PYTHONPATH": CARING_CARIBOU_PATH, **os.environ}
            full_command = " ".join(args_list)
            append_log(f"🚀 Launching: {full_command}")
            append_log(f"📁 Working directory: {working_dir}")
            append_log(f"🐍 Python executable: {args_list[0]}")
            def show_command():
                dbc_text.delete(1.0, tk.END)
                dbc_text.insert(tk.END, "=== FUZZING COMMAND ===\n\n")
                dbc_text.insert(tk.END, f"Command: {full_command}\n")
                dbc_text.insert(tk.END, f"Working Directory: {working_dir}\n")
                dbc_text.insert(tk.END, f"PYTHONPATH: {working_dir}\n")
                dbc_text.insert(tk.END, "\n" + "="*50 + "\n\n")
                dbc_text.insert(tk.END, "=== FUZZING OUTPUT (Live) ===\n\n")
                dbc_text.see(tk.END)
            if is_fuzzer:
                root.after(0, show_command)
            proc = subprocess.Popen(args_list,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  text=True,
                                  bufsize=1,
                                  universal_newlines=True,
                                  cwd=working_dir,
                                  env=env)
            full_output = ""
            while proc.poll() is None:
                while True:
                    line = proc.stdout.readline()
                    if line:
                        line = line.rstrip()
                        append_log(f"📤 {line}")
                        full_output += line + "\n"
                        if is_fuzzer and line:
                            def update_fuzz_output():
                                dbc_text.insert(tk.END, f"{line}\n")
                                dbc_text.see(tk.END)
                            root.after(0, update_fuzz_output)
                    else:
                        break
                while True:
                    line = proc.stderr.readline()
                    if line:
                        line = line.rstrip()
                        append_log(f"❌ {line}")
                        full_output += line + "\n"
                        if is_fuzzer and line:
                            def update_fuzz_error():
                                dbc_text.insert(tk.END, f"ERROR: {line}\n")
                                dbc_text.see(tk.END)
                            root.after(0, update_fuzz_error)
                    else:
                        break
                time.sleep(0.1)
            remaining_stdout, remaining_stderr = proc.communicate()
            if remaining_stdout:
                append_log(f"📤 [FINAL] {remaining_stdout}")
                full_output += remaining_stdout
                if is_fuzzer:
                    def update_final_output():
                        dbc_text.insert(tk.END, f"\n=== FINAL OUTPUT ===\n{remaining_stdout}\n")
                        dbc_text.see(tk.END)
                    root.after(0, update_final_output)
            if remaining_stderr:
                append_log(f"❌ [FINAL] {remaining_stderr}")
                full_output += remaining_stderr
                if is_fuzzer:
                    def update_final_error():
                        dbc_text.insert(tk.END, f"\n=== FINAL ERRORS ===\n{remaining_stderr}\n")
                        dbc_text.see(tk.END)
                    root.after(0, update_final_error)
            append_log(f"✅ Process exited with code {proc.returncode}")
            if is_lenattack and full_output:
                result_summary = parse_and_update_from_lenattack(full_output, getattr(root, "dbc_content", ""))
                def show_lenattack_results():
                    popup = tk.Toplevel(root)
                    popup.title("Length Attack Results")
                    popup.geometry("800x600")
                    result_text = scrolledtext.ScrolledText(popup, wrap=tk.WORD, font=("Consolas", 10))
                    result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                    result_text.insert(tk.END, "=== LENGTH ATTACK COMMAND ===\n")
                    result_text.insert(tk.END, f"Command: {full_command}\n")
                    result_text.insert(tk.END, f"Working Directory: {working_dir}\n")
                    result_text.insert(tk.END, f"PYTHONPATH: {working_dir}\n")
                    result_text.insert(tk.END, "\n" + "="*50 + "\n\n")
                    result_text.insert(tk.END, "=== LENGTH ATTACK RESULTS ===\n\n")
                    result_text.insert(tk.END, result_summary)
                    result_text.config(state=tk.DISABLED)
                    dbc_text.delete(1.0, tk.END)
                    dbc_text.insert(tk.END, "=== LENGTH ATTACK RESULTS ===\n\n")
                    dbc_text.insert(tk.END, f"Command: {full_command}\n\n")
                    dbc_text.insert(tk.END, result_summary)
                    tk.Button(popup, text="Close", bg=BUTTON_COLOR, fg="white",
                             command=popup.destroy).pack(pady=10)
                root.after(0, show_lenattack_results)
            if is_fuzzer and full_output:
                def show_fuzzer_results():
                    popup = tk.Toplevel(root)
                    popup.title("Fuzzing Results")
                    popup.geometry("800x600")
                    result_text = scrolledtext.ScrolledText(popup, wrap=tk.WORD, font=("Consolas", 10))
                    result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                    result_text.insert(tk.END, "=== FUZZING COMMAND ===\n")
                    result_text.insert(tk.END, f"Command: {full_command}\n")
                    result_text.insert(tk.END, f"Working Directory: {working_dir}\n")
                    result_text.insert(tk.END, f"PYTHONPATH: {working_dir}\n")
                    result_text.insert(tk.END, f"Exit Code: {proc.returncode}\n")
                    result_text.insert(tk.END, "\n" + "="*50 + "\n\n")
                    result_text.insert(tk.END, "=== COMPLETE FUZZING OUTPUT ===\n\n")
                    result_text.insert(tk.END, full_output)
                    result_text.config(state=tk.DISABLED)
                    tk.Button(popup, text="Close", bg=BUTTON_COLOR, fg="white",
                             command=popup.destroy).pack(pady=10)
                root.after(0, show_fuzzer_results)
        except FileNotFoundError:
            error_msg = "❌ CaringCaribou not found. Please install it with: pip install caringcaribou"
            append_log(error_msg)
            root.after(0, lambda: messagebox.showerror("Not Found", error_msg))
        except Exception as e:
            append_log(f"💥 Error launching process: {e}")
            root.after(0, lambda: messagebox.showerror("Launch Error", f"Error: {e}"))
    threading.Thread(target=_run, daemon=True).start()

# --- Updated Fuzzer Popup with proper command structure ---
def open_fuzz_popup():
    if not hasattr(root, "dbc_content") or not root.current_signals_dict:
        messagebox.showwarning("No DBC", "Please import a DBC first.")
        return

    pop = tk.Toplevel(root)
    pop.title("Signal Fuzzer Configuration")
    pop.geometry("500x350")

    tk.Label(pop, text="Fuzzer Type:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=8, pady=(8,0))
    fuzzer_types = ["random", "brute", "mutate", "replay", "identify"]
    fuzzer_type_var = tk.StringVar(value="brute")
    fuzzer_combo = ttk.Combobox(pop, values=fuzzer_types, textvariable=fuzzer_type_var, state="readonly")
    fuzzer_combo.pack(fill="x", padx=8, pady=(0,8))

    tk.Label(pop, text="Select message (optional):").pack(anchor="w", padx=8, pady=(8,0))
    msg_names = list(root.current_signals_dict.keys())
    sel_msg_var = tk.StringVar(value=msg_names[0] if msg_names else "")
    msg_combo = ttk.Combobox(pop, values=msg_names, textvariable=sel_msg_var, state="readonly")
    msg_combo.pack(fill="x", padx=8, pady=(0,8))

    tk.Label(pop, text="Or enter Arbitration ID (hex or int):").pack(anchor="w", padx=8)
    id_var = tk.StringVar(value="0x123")
    id_entry = tk.Entry(pop, textvariable=id_var)
    id_entry.pack(fill="x", padx=8, pady=(0,8))

    tk.Label(pop, text="Data Pattern (e.g., 12ab..78):").pack(anchor="w", padx=8)
    data_var = tk.StringVar(value="12ab..78")
    data_entry = tk.Entry(pop, textvariable=data_var)
    data_entry.pack(fill="x", padx=8, pady=(0,8))

    tk.Label(pop, text="Extra args (optional):").pack(anchor="w", padx=8)
    extra_var = tk.StringVar(value="")
    extra_entry = tk.Entry(pop, textvariable=extra_var)
    extra_entry.pack(fill="x", padx=8, pady=(0,8))

    def start_fuzz():
        fuzzer_type = fuzzer_type_var.get().strip()
        selected_message = sel_msg_var.get().strip()
        entered_id = id_var.get().strip()
        data_pattern = data_var.get().strip()
        extras = extra_var.get().strip().split() if extra_var.get().strip() else []

        use_id = None
        if selected_message:
            try:
                for name, sigs in root.current_signals_dict.items():
                    if name == selected_message:
                        # try to find frame ID via frameid_to_name
                        for fid, nm in getattr(root, "frameid_to_name", {}).items():
                            if nm == name:
                                use_id = fid
                                break
                        break
            except Exception:
                pass

        if use_id is None and entered_id:
            try:
                use_id = int(entered_id, 0)
            except ValueError:
                messagebox.showerror("Invalid ID", "Could not parse the entered ID.")
                return

        if use_id is None:
            messagebox.showerror("No ID", "No valid message ID supplied.")
            return

        hexid = hex(use_id) if isinstance(use_id, int) else str(use_id)
        args = ["/usr/bin/python", "-m", "caringcaribou.caringcaribou", "fuzzer", fuzzer_type, hexid, data_pattern]
        args.extend(extras)
        full_command = " ".join(args)
        if messagebox.askyesno("Start Fuzzing",
                              f"Start {fuzzer_type} fuzzing with this command?\n\n{full_command}\n\n"
                              f"Message: {selected_message or 'Manual ID'}\n"
                              f"ID: {hexid}\n"
                              f"Data Pattern: {data_pattern}"):
            run_caringcaribou_cmd(args, is_fuzzer=True)
            pop.destroy()

    tk.Button(pop, text="Start Fuzzing", bg=BUTTON_COLOR, fg="white",
              font=("Segoe UI", 10, "bold"), command=start_fuzz).pack(padx=8, pady=12)

try:
    btn_fuzzer.config(command=open_fuzz_popup)
except Exception:
    pass

# Add Send Signal button (kept from original)
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

# ----------- LENGTH ATTACK POPUP & WIRING -----------
def open_length_attack_popup():
    if not hasattr(root, "dbc_content") or not getattr(root, "current_signals_dict", None):
        if not messagebox.askyesno("No DBC", "No DBC loaded. Continue to run lenattack without a DBC?"):
            return

    pop = tk.Toplevel(root)
    pop.title("Length Attack Launcher")
    pop.geometry("520x320")

    tk.Label(pop, text="Select message (optional):").pack(anchor="w", padx=8, pady=(8,0))
    msg_names = list(getattr(root, "current_signals_dict", {}).keys())
    sel_msg_var = tk.StringVar(value=msg_names[0] if msg_names else "")
    msg_combo = ttk.Combobox(pop, values=msg_names, textvariable=sel_msg_var, state="readonly")
    msg_combo.pack(fill="x", padx=8, pady=(0,8))

    tk.Label(pop, text="Or enter Arbitration ID (hex or int):").pack(anchor="w", padx=8)
    id_var = tk.StringVar(value="0x123")
    id_entry = tk.Entry(pop, textvariable=id_var)
    id_entry.pack(fill="x", padx=8, pady=(0,8))

    tk.Label(pop, text="CAN Interface (socketcan):").pack(anchor="w", padx=8)
    iface_var = tk.StringVar(value="vcan0")
    iface_entry = tk.Entry(pop, textvariable=iface_var)
    iface_entry.pack(fill="x", padx=8, pady=(0,8))

    tk.Label(pop, text="Extra args (optional):").pack(anchor="w", padx=8)
    extra_var = tk.StringVar(value="")
    extra_entry = tk.Entry(pop, textvariable=extra_var)
    extra_entry.pack(fill="x", padx=8, pady=(0,8))

    def start_lenattack():
        selected_message = sel_msg_var.get().strip()
        entered_id = id_var.get().strip()
        use_id = None
        if selected_message:
            try:
                for fid, nm in getattr(root, "frameid_to_name", {}).items():
                    if nm == selected_message:
                        use_id = fid
                        break
                if use_id is None and entered_id:
                    use_id = int(entered_id, 0)
            except Exception:
                try:
                    use_id = int(entered_id, 0) if entered_id else None
                except Exception:
                    use_id = None
        else:
            try:
                use_id = int(entered_id, 0) if entered_id else None
            except Exception:
                messagebox.showerror("Invalid ID", "Could not parse the entered ID.")
                return

        if use_id is None:
            messagebox.showerror("No ID", "No valid message ID supplied.")
            return

        hexid = hex(use_id) if isinstance(use_id, int) else str(use_id)
        extras = extra_var.get().strip().split() if extra_var.get().strip() else []
        args = ["/usr/bin/python", "-m", "caringcaribou.caringcaribou", "lenattack", hexid] + extras
        full_command = " ".join(args)
        if messagebox.askyesno("Start Length Attack",
                              f"Start length attack with this command?\n\n{full_command}\n\n"
                              f"Target ID: {hexid}\n"
                              f"Extra args: {extras}"):
            try:
                if hasattr(root, "frameid_to_name") and use_id in getattr(root, "frameid_to_name", {}):
                    name = root.frameid_to_name[use_id]
                    for iid in msg_table.get_children():
                        vals = msg_table.item(iid, "values")
                        if vals and vals[0] == name:
                            msg_table.selection_set(iid)
                            msg_table.see(iid)
                            on_message_select()
                            append_log(f"Auto-selected message '{name}' (ID={hexid}) in DBC view.")
                            break
            except Exception as e:
                append_log(f"Auto-select failed: {e}")

            run_caringcaribou_cmd(args, is_lenattack=True)
            pop.destroy()
    tk.Button(pop, text="Start Length Attack", bg=BUTTON_COLOR, fg="white", command=start_lenattack).pack(padx=8, pady=(8,12))

try:
    btn_length_attack.config(command=open_length_attack_popup)
except Exception:
    pass

# ----------- INIT -----------
root.current_signals_dict = {}
root.frameid_to_name = {}

root.mainloop()
