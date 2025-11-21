# helpers.py
# Helper functions for FucyFuzz

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
from report_helpers import *

# ----------- DBC PARSER -----------
_re_bo = re.compile(r'^\s*BO\_\s+(\d+|0x[0-9A-Fa-f]+)\s+(\w+)\s*:\s*(\d+)\s+')
_re_sg = re.compile(
    r'^\s*SG\_\s+(\w+)\s*:\s*(\d+)\|(\d+)@([01])([+-])\s*\(\s*([0-9eE+.-]+)\s*,\s*([0-9eE+.-]+)\s*\)\s*\[\s*([0-9eE+.-]+)\s*\|\s*([0-9eE+.-]+)\s*\]\s*"([^"]*)"\s*'
)
_re_sg_loose = re.compile(
    r'^\s*SG\_\s+(\w+)\s*:\s*(\d+)\|(\d+)[^\(]*\(\s*([0-9eE+.-]+)\s*,\s*([0-9eE+.-]+)\s*\)[^\[]*\[\s*([0-9eE+.-]+)\s*\|\s*([0-9eE+.-]+)\s*\]\s*"([^"]*)"?'
)

def parse_dbc_content(content):
    messages = []
    signals_dict = {}
    frameid_to_name = {}

    lines = content.splitlines()
    current_msg = None
    current_msg_comment = ""
    for i, raw in enumerate(lines):
        line = raw.rstrip()
        if not line.strip():
            continue

        m = _re_bo.match(line)
        if m:
            id_text = m.group(1)
            name = m.group(2)
            dlc = int(m.group(3))
            try:
                frame_id = int(id_text, 0)
            except Exception:
                try:
                    frame_id = int(id_text)
                except Exception:
                    frame_id = 0
            if current_msg:
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

            if line.strip().startswith("CM_ BO_"):
                try:
                    parts = line.split(None, 3)
                    if len(parts) >= 4:
                        comm = parts[3].strip()
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

    if current_msg:
        messages.append(current_msg)

    return messages, signals_dict, frameid_to_name

# ----------- UI HELPERS -----------
def initialize_helpers(root, log_text, dbc_text, msg_table, sig_table, bit_table_frame, bit_canvas):
    root.log_text = log_text
    root.dbc_text = dbc_text
    root.msg_table = msg_table
    root.sig_table = sig_table
    root.bit_table_frame = bit_table_frame
    root.bit_canvas = bit_canvas

def append_log(root, text):
    def _append():
        root.log_text.config(state='normal')
        if isinstance(text, str):
            txt = text.rstrip("\n")
        else:
            txt = str(text)
        timestamped_log = f"{time.strftime('%H:%M:%S')} - {txt}"
        root.log_text.insert(tk.END, f"{timestamped_log}\n")
        root.log_text.see(tk.END)
        root.log_text.config(state='disabled')
        
        root.all_logs.append(timestamped_log)
    root.after(0, _append)

def import_dbc(root):
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

        for item in root.msg_table.get_children():
            root.msg_table.delete(item)

        for m in messages:
            root.msg_table.insert("", "end", values=(m["Name"], m["CAN_ID"], m["Type"], m["DLC"], m["Comment"]))

        messagebox.showinfo("Success", f"Loaded {len(messages)} messages from DBC file.")
        append_log(root, f"📁 Imported DBC file: {file_path} ({len(messages)} messages)")
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to import DBC file:\n{str(e)}")
        append_log(root, f"❌ DBC import failed: {str(e)}")

def on_message_select(root, msg_table, sig_table, dbc_text, bit_table_frame, bit_canvas):
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
        update_dbc_preview(root, msg_name)
        update_bit_mapping(root, signals, bit_table_frame, bit_canvas)

def update_dbc_preview(root, msg_name):
    root.dbc_text.delete(1.0, tk.END)
    root.dbc_text.insert(tk.END, f"BO_ {msg_name}:\n")
    for s in root.current_signals_dict.get(msg_name, []):
        root.dbc_text.insert(
            tk.END,
            f" SG_ {s['Name']} : {s['Start']}|{s['Length']} "
            f"({s['Factor']},{s['Offset']}) [{s['Min']}|{s['Max']}] "
            f"\"{s['Unit']}\"\n"
        )

def update_bit_mapping(root, signals, bit_table_frame, bit_canvas):
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

# ----------- CARING CARIBOU HELPERS -----------
def run_caringcaribou_help(root):
    def _run_help():
        try:
            args = ["/usr/bin/python", "-m", "caringcaribou.caringcaribou", "--help"]
            working_dir = "/home/fucy-can/FUCY/caringcaribou_fresh"
            append_log(root, f"🔍 Running Help Command: {' '.join(args)}")
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
                root.dbc_text.delete(1.0, tk.END)
                root.dbc_text.insert(tk.END, "=== CARING CARIBOU HELP ===\n\n")
                if stdout:
                    root.dbc_text.insert(tk.END, stdout)
                    append_log(root, "✅ Help command completed successfully")
                if stderr:
                    root.dbc_text.insert(tk.END, "\n=== ERRORS ===\n")
                    root.dbc_text.insert(tk.END, stderr)
                    append_log(root, f"❌ Help command errors: {stderr}")
            root.after(0, update_preview)
        except Exception as e:
            append_log(root, f"💥 Error running help command: {e}")
            root.after(0, lambda: messagebox.showerror("Error", f"Failed to run help: {e}"))
    threading.Thread(target=_run_help, daemon=True).start()

def open_fuzz_popup(root):
    if not hasattr(root, "dbc_content") or not root.current_signals_dict:
        messagebox.showwarning("No DBC", "Please import a DBC first.")
        return

    pop = tk.Toplevel(root)
    pop.title("Signal Fuzzer Configuration")
    pop.geometry("500x450")
    pop.configure(bg="#ffffff")

    # Store process reference for stopping
    pop.current_process = None

    tk.Label(pop, text="Fuzzer Type:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=8, pady=(8,0))
    fuzzer_types = ["random", "brute", "mutate", "replay", "identify"]
    fuzzer_type_var = tk.StringVar(value="brute")
    fuzzer_combo = ttk.Combobox(pop, values=fuzzer_types, textvariable=fuzzer_type_var, state="readonly")
    fuzzer_combo.pack(fill="x", padx=8, pady=(0,8))

    # Message selection frame
    msg_frame = tk.Frame(pop, bg="#ffffff")
    msg_frame.pack(fill="x", padx=8, pady=(8,0))
    tk.Label(msg_frame, text="Select message (optional):", bg="#ffffff").pack(anchor="w")
    msg_names = list(root.current_signals_dict.keys())
    sel_msg_var = tk.StringVar(value=msg_names[0] if msg_names else "")
    msg_combo = ttk.Combobox(msg_frame, values=msg_names, textvariable=sel_msg_var, state="readonly")
    msg_combo.pack(fill="x", pady=(0,8))

    # ID entry frame
    id_frame = tk.Frame(pop, bg="#ffffff")
    id_frame.pack(fill="x", padx=8, pady=(8,0))
    tk.Label(id_frame, text="Or enter Arbitration ID (hex or int):", bg="#ffffff").pack(anchor="w")
    id_var = tk.StringVar(value="0x123")
    id_entry = tk.Entry(id_frame, textvariable=id_var)
    id_entry.pack(fill="x", pady=(0,8))

    # Data pattern frame (initially hidden for random)
    data_frame = tk.Frame(pop, bg="#ffffff")
    data_frame.pack(fill="x", padx=8, pady=(8,0))
    tk.Label(data_frame, text="Data Pattern (e.g., 12ab..78):", bg="#ffffff").pack(anchor="w")
    data_var = tk.StringVar(value="12ab..78")
    data_entry = tk.Entry(data_frame, textvariable=data_var)
    data_entry.pack(fill="x", pady=(0,8))

    # File frame (for replay and identify)
    file_frame = tk.Frame(pop, bg="#ffffff")
    file_frame.pack(fill="x", padx=8, pady=(8,0))
    tk.Label(file_frame, text="Input File:", bg="#ffffff").pack(anchor="w")
    file_var = tk.StringVar(value="log.txt")
    file_entry = tk.Entry(file_frame, textvariable=file_var)
    file_entry.pack(fill="x", side="left", pady=(0,8), expand=True)
    tk.Button(file_frame, text="Browse", bg="#0078d7", fg="white", font=("Segoe UI", 8),
              command=lambda: browse_file(file_var)).pack(side="right", padx=(5,0), pady=(0,8))

    # Extra args frame
    extra_frame = tk.Frame(pop, bg="#ffffff")
    extra_frame.pack(fill="x", padx=8, pady=(8,0))
    tk.Label(extra_frame, text="Extra args (optional):", bg="#ffffff").pack(anchor="w")
    extra_var = tk.StringVar(value="")
    extra_entry = tk.Entry(extra_frame, textvariable=extra_var)
    extra_entry.pack(fill="x", pady=(0,8))

    # Status label
    status_label = tk.Label(pop, text="", bg="#ffffff", fg="#0078d7", font=("Segoe UI", 9))
    status_label.pack(fill="x", padx=8, pady=(5,0))

    def browse_file(file_var):
        filename = filedialog.askopenfilename(
            title="Select input file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            file_var.set(filename)

    def update_fields(*args):
        fuzzer_type = fuzzer_type_var.get()
        
        # Show/hide fields based on fuzzer type
        if fuzzer_type == "random":
            data_frame.pack_forget()
            file_frame.pack_forget()
            extra_frame.pack(fill="x", padx=8, pady=(8,0))
            status_label.config(text="Random fuzzer: Uses only extra args field")
            
        elif fuzzer_type == "brute":
            data_frame.pack(fill="x", padx=8, pady=(8,0))
            file_frame.pack_forget()
            extra_frame.pack(fill="x", padx=8, pady=(8,0))
            status_label.config(text="Brute force fuzzer: Requires data pattern")
            
        elif fuzzer_type == "mutate":
            data_frame.pack(fill="x", padx=8, pady=(8,0))
            file_frame.pack_forget()
            extra_frame.pack(fill="x", padx=8, pady=(8,0))
            status_label.config(text="Mutation fuzzer: Requires data pattern")
            
        elif fuzzer_type == "replay":
            data_frame.pack_forget()
            file_frame.pack(fill="x", padx=8, pady=(8,0))
            extra_frame.pack(fill="x", padx=8, pady=(8,0))
            status_label.config(text="Replay fuzzer: Requires input file")
            
        elif fuzzer_type == "identify":
            data_frame.pack_forget()
            file_frame.pack(fill="x", padx=8, pady=(8,0))
            extra_frame.pack(fill="x", padx=8, pady=(8,0))
            status_label.config(text="Identify fuzzer: Requires input file")

    # Initial field setup
    update_fields()
    
    # Bind combobox change event
    fuzzer_type_var.trace('w', update_fields)

    def stop_fuzzing():
        if pop.current_process:
            try:
                pop.current_process.terminate()
                append_log(root, "🛑 Fuzzing stopped by user")
                status_label.config(text="Fuzzing stopped", fg="#dc3545")
                stop_btn.config(state="disabled")
                start_btn.config(state="normal")
            except Exception as e:
                append_log(root, f"❌ Error stopping fuzzing: {e}")

    def start_fuzz():
        fuzzer_type = fuzzer_type_var.get().strip()
        selected_message = sel_msg_var.get().strip()
        entered_id = id_var.get().strip()
        data_pattern = data_var.get().strip()
        input_file = file_var.get().strip()
        extras = extra_var.get().strip().split() if extra_var.get().strip() else []

        use_id = None
        if selected_message:
            try:
                for name, sigs in root.current_signals_dict.items():
                    if name == selected_message:
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
        
        # Build command based on fuzzer type
        args = ["/usr/bin/python", "-m", "caringcaribou.caringcaribou", "fuzzer", fuzzer_type, hexid]
        
        if fuzzer_type == "brute" or fuzzer_type == "mutate":
            if not data_pattern:
                messagebox.showerror("Missing Data", f"{fuzzer_type} fuzzer requires a data pattern.")
                return
            args.append(data_pattern)
        elif fuzzer_type == "replay" or fuzzer_type == "identify":
            if not input_file:
                messagebox.showerror("Missing File", f"{fuzzer_type} fuzzer requires an input file.")
                return
            args.append(input_file)
        # For random, no additional required parameters beyond ID
        
        args.extend(extras)
        full_command = " ".join(args)
        
        if messagebox.askyesno("Start Fuzzing",
                              f"Start {fuzzer_type} fuzzing with this command?\n\n{full_command}\n\n"
                              f"Message: {selected_message or 'Manual ID'}\n"
                              f"ID: {hexid}\n"
                              f"Data Pattern: {data_pattern if fuzzer_type in ['brute', 'mutate'] else 'N/A'}\n"
                              f"Input File: {input_file if fuzzer_type in ['replay', 'identify'] else 'N/A'}\n"
                              f"Extra Args: {extras if extras else 'None'}"):
            
            # Update UI for running state
            status_label.config(text="Fuzzing started...", fg="#28a745")
            start_btn.config(state="disabled")
            stop_btn.config(state="normal")
            
            # Store the process reference in the popup
            def run_with_stop():
                process = run_caringcaribou_cmd_with_stop(root, args, pop, is_fuzzer=True)
                pop.current_process = process
            
            threading.Thread(target=run_with_stop, daemon=True).start()

    # Button frame
    button_frame = tk.Frame(pop, bg="#ffffff")
    button_frame.pack(fill="x", padx=8, pady=12)

    start_btn = tk.Button(button_frame, text="Start Fuzzing", bg="#28a745", fg="white",
                         font=("Segoe UI", 10, "bold"), command=start_fuzz)
    start_btn.pack(side="left", padx=5)

    stop_btn = tk.Button(button_frame, text="Stop Fuzzing", bg="#dc3545", fg="white",
                        font=("Segoe UI", 10, "bold"), command=stop_fuzzing, state="disabled")
    stop_btn.pack(side="left", padx=5)

    tk.Button(button_frame, text="Close", bg="#6c757d", fg="white",
             font=("Segoe UI", 10), command=pop.destroy).pack(side="right", padx=5)

def run_caringcaribou_cmd_with_stop(root, args_list, popup_window, is_lenattack=False, is_fuzzer=False):
    """Run CaringCaribou command with ability to stop the process"""
    from report_helpers import parse_and_update_from_lenattack
    
    def _run():
        report_data = {
            'tool': 'Length Attack' if is_lenattack else 'Signal Fuzzer' if is_fuzzer else 'CaringCaribou',
            'command': '',
            'working_dir': '',
            'target_id': '',
            'exit_code': -1,
            'results_summary': '',
            'full_output': '',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            if args_list[0] == sys.executable and "-m" in args_list and "caringcaribou" in args_list:
                args_list[0] = "/usr/bin/python"
            working_dir = "/home/fucy-can/FUCY/caringcaribou_fresh"
            env = {"PYTHONPATH": working_dir, **os.environ}
            full_command = " ".join(args_list)
            
            for arg in args_list:
                if arg.startswith('0x') or (arg.isdigit() and len(arg) > 1):
                    report_data['target_id'] = arg
                    break
            
            report_data['command'] = full_command
            report_data['working_dir'] = working_dir
            
            append_log(root, f"🚀 Launching: {full_command}")
            
            def show_command():
                root.dbc_text.delete(1.0, tk.END)
                root.dbc_text.insert(tk.END, "=== CARING CARIBOU COMMAND ===\n\n")
                root.dbc_text.insert(tk.END, f"Command: {full_command}\n")
                if is_lenattack:
                    root.dbc_text.insert(tk.END, "=== LENGTH ATTACK OUTPUT (Live) ===\n\n")
                elif is_fuzzer:
                    root.dbc_text.insert(tk.END, "=== FUZZING OUTPUT (Live) ===\n\n")
                else:
                    root.dbc_text.insert(tk.END, "=== OUTPUT (Live) ===\n\n")
                root.dbc_text.see(tk.END)
            
            root.after(0, show_command)
            
            proc = subprocess.Popen(args_list,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  text=True,
                                  bufsize=1,
                                  universal_newlines=True,
                                  cwd=working_dir,
                                  env=env)
            
            # Store process reference in popup for stopping
            popup_window.current_process = proc
            
            full_output = ""
            
            while proc.poll() is None:
                while True:
                    line = proc.stdout.readline()
                    if line:
                        line = line.rstrip()
                        append_log(root, f"📤 {line}")
                        full_output += line + "\n"
                        def update_output():
                            root.dbc_text.insert(tk.END, f"{line}\n")
                            root.dbc_text.see(tk.END)
                        root.after(0, update_output)
                    else:
                        break
                
                while True:
                    line = proc.stderr.readline()
                    if line:
                        line = line.rstrip()
                        append_log(root, f"❌ {line}")
                        full_output += line + "\n"
                        def update_error():
                            root.dbc_text.insert(tk.END, f"ERROR: {line}\n")
                            root.dbc_text.see(tk.END)
                        root.after(0, update_error)
                    else:
                        break
                
                time.sleep(0.1)
            
            # Clear process reference
            popup_window.current_process = None
            
            remaining_stdout, remaining_stderr = proc.communicate()
            
            if remaining_stdout:
                append_log(root, f"📤 [FINAL] {remaining_stdout}")
                full_output += remaining_stdout
                def update_final_output():
                    root.dbc_text.insert(tk.END, f"\n{remaining_stdout}")
                    root.dbc_text.see(tk.END)
                root.after(0, update_final_output)
            
            if remaining_stderr:
                append_log(root, f"❌ [FINAL] {remaining_stderr}")
                full_output += remaining_stderr
                def update_final_error():
                    root.dbc_text.insert(tk.END, f"\nERROR: {remaining_stderr}")
                    root.dbc_text.see(tk.END)
                root.after(0, update_final_error)
            
            report_data['exit_code'] = proc.returncode
            report_data['full_output'] = full_output
            
            # Determine success status
            success = proc.returncode == 0
            status_message = "✅ Process completed successfully" if success else "❌ Process failed"
            append_log(root, f"{status_message} with code {proc.returncode}")
            
            # Reset UI state
            def reset_ui():
                if hasattr(popup_window, 'status_label'):
                    if proc.returncode == 0:
                        popup_window.status_label.config(text="Fuzzing completed successfully", fg="#28a745")
                    else:
                        popup_window.status_label.config(text="Fuzzing completed with errors", fg="#dc3545")
                
                if hasattr(popup_window, 'start_btn'):
                    popup_window.start_btn.config(state="normal")
                if hasattr(popup_window, 'stop_btn'):
                    popup_window.stop_btn.config(state="disabled")
            
            root.after(0, reset_ui)
            
            root.all_reports.append(report_data.copy())
            
            if is_lenattack and full_output:
                result_summary = parse_and_update_from_lenattack(root, full_output, getattr(root, "dbc_content", ""))
                report_data['results_summary'] = result_summary
                
                def show_lenattack_results():
                    from report_helpers import show_lenattack_results_dialog
                    show_lenattack_results_dialog(root, report_data, full_command, working_dir, result_summary, success)
                
                root.after(0, show_lenattack_results)
            
            elif is_fuzzer and full_output:
                lines = full_output.split('\n')
                error_count = sum(1 for line in lines if 'error' in line.lower() or 'fail' in line.lower())
                success_count = sum(1 for line in lines if 'success' in line.lower() or 'found' in line.lower())
                
                report_data['results_summary'] = f"Fuzzing completed with exit code {proc.returncode}\n"
                report_data['results_summary'] += f"Lines processed: {len(lines)}\n"
                report_data['results_summary'] += f"Potential errors: {error_count}\n"
                report_data['results_summary'] += f"Potential successes: {success_count}\n\n"
                report_data['results_summary'] += "See full output for detailed results."
                
                def show_fuzzer_results():
                    from report_helpers import show_fuzzer_results_dialog
                    show_fuzzer_results_dialog(root, report_data, full_command, working_dir, full_output, success)
                
                root.after(0, show_fuzzer_results)
            
            else:
                report_data['results_summary'] = f"Process completed with exit code {proc.returncode}\n\nOutput length: {len(full_output)} characters"
                root.after(0, lambda: show_report_dialog(root, report_data, report_data['tool'], success))
                
        except Exception as e:
            append_log(root, f"💥 Error launching process: {e}")
            report_data['results_summary'] = f"Error: {str(e)}"
            
            # Reset UI on error
            def reset_ui_on_error():
                if hasattr(popup_window, 'status_label'):
                    popup_window.status_label.config(text=f"Error: {str(e)}", fg="#dc3545")
                if hasattr(popup_window, 'start_btn'):
                    popup_window.start_btn.config(state="normal")
                if hasattr(popup_window, 'stop_btn'):
                    popup_window.stop_btn.config(state="disabled")
                popup_window.current_process = None
            
            root.after(0, reset_ui_on_error)
            root.after(0, lambda: (messagebox.showerror("Launch Error", f"Error: {e}"),
                                  show_report_dialog(root, report_data, report_data['tool'], False)))
        
        return proc
    
    # Start the process in a thread and return the process reference
    import threading
    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    
    # Return a dummy process object that can be used to check if running
    class DummyProcess:
        def __init__(self):
            self.returncode = None
        
        def terminate(self):
            if hasattr(popup_window, 'current_process') and popup_window.current_process:
                popup_window.current_process.terminate()
    
    return DummyProcess()

# Keep the original run_caringcaribou_cmd for other uses
def run_caringcaribou_cmd(root, args_list, is_lenattack=False, is_fuzzer=False):
    """Original function for backward compatibility"""
    return run_caringcaribou_cmd_with_stop(root, args_list, tk.Toplevel(), is_lenattack, is_fuzzer)

def open_length_attack_popup(root):
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
                    for iid in root.msg_table.get_children():
                        vals = root.msg_table.item(iid, "values")
                        if vals and vals[0] == name:
                            root.msg_table.selection_set(iid)
                            root.msg_table.see(iid)
                            on_message_select(root, root.msg_table, root.sig_table, root.dbc_text, root.bit_table_frame, root.bit_canvas)
                            append_log(root, f"Auto-selected message '{name}' (ID={hexid}) in DBC view.")
                            break
            except Exception as e:
                append_log(root, f"Auto-select failed: {e}")

            run_caringcaribou_cmd(root, args, is_lenattack=True)
            pop.destroy()
    tk.Button(pop, text="Start Length Attack", bg="#0078d7", fg="white", command=start_lenattack).pack(padx=8, pady=(8,12))