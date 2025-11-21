import customtkinter as ctk
from tkinter import filedialog, messagebox
import subprocess
import threading
import os
import signal
import sys
import time
import random
import json
from datetime import datetime

# --- OPTIONAL IMPORTS ---
try:
    import cantools
except ImportError:
    cantools = None

# PDF Generation Import
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
    from reportlab.lib.styles import getSampleStyleSheet
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# --- CONFIGURATION ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# ==============================================================================
#   MAIN APP
# ==============================================================================

class CaribouApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("FUCYTECH // CARING CARIBOU CTK INTERFACE")
        self.geometry("1400x950")

        # --- INITIALIZE WORKING DIRECTORY ---
        # Default path attempt, fallback to current dir
        default_path = "/home/fucy-can/FUCY/caringcaribou_fresh"
        if os.path.exists(default_path):
            self.working_dir = default_path
        else:
            self.working_dir = os.getcwd()

        # Data Management
        self.current_process = None
        self.session_history = []
        self.full_log_buffer = []
        
        # GLOBAL DBC STORE
        self.dbc_db = None
        self.dbc_messages = {} 

        # Layout
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ===========================
        # 1) TABVIEW
        # ===========================
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        tab_names = [
            "Configuration", "Recon", "Fuzzer", "Length Attack",
            "UDS", "Advanced", "Send", "Monitor"
        ]
        for name in tab_names:
            self.tabs.add(name)

        # ===========================
        # 2) TAB FRAMES
        # ===========================
        self.frames = {}
        self.frames["config"] = ConfigFrame(self.tabs.tab("Configuration"), self)
        self.frames["recon"] = ReconFrame(self.tabs.tab("Recon"), self)
        self.frames["fuzzer"] = FuzzerFrame(self.tabs.tab("Fuzzer"), self)
        self.frames["lenattack"] = LengthAttackFrame(self.tabs.tab("Length Attack"), self)
        self.frames["uds"] = UDSFrame(self.tabs.tab("UDS"), self)
        self.frames["advanced"] = AdvancedFrame(self.tabs.tab("Advanced"), self)
        self.frames["send"] = SendFrame(self.tabs.tab("Send"), self)
        self.frames["monitor"] = MonitorFrame(self.tabs.tab("Monitor"), self)

        for frm in self.frames.values():
            frm.pack(fill="both", expand=True, padx=15, pady=15)

        # ===========================
        # 3) CONSOLE
        # ===========================
        self.console_frame = ctk.CTkFrame(self, height=250, fg_color="#111")
        self.console_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))

        header = ctk.CTkFrame(self.console_frame, fg_color="transparent")
        header.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(header, text="SYSTEM OUTPUT", font=("Arial", 12, "bold")).pack(side="left", padx=5)

        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.pack(side="right")

        # Global Buttons
        ctk.CTkButton(btn_frame, text="📂 Import DBC (Global)", width=140, fg_color="#8e44ad",
                      command=self.load_global_dbc).pack(side="left", padx=5)

        ctk.CTkButton(btn_frame, text="📄 Overall PDF Report", width=140, fg_color="#2980b9",
                      command=self.save_overall_report).pack(side="left", padx=5)
        
        ctk.CTkButton(btn_frame, text="📜 Save Logs", width=100, fg_color="#7f8c8d",
                      command=self.save_full_logs).pack(side="left", padx=5)

        ctk.CTkButton(btn_frame, text="⛔ STOP", fg_color="#c0392b", width=100,
                      command=self.stop_process).pack(side="left", padx=5)

        self.console = ctk.CTkTextbox(self.console_frame, font=("Consolas", 12), text_color="#00ff00", fg_color="#000")
        self.console.pack(fill="both", expand=True, padx=5, pady=5)

    # =======================================
    # GLOBAL DBC LOGIC
    # =======================================
    def load_global_dbc(self):
        if not cantools:
            messagebox.showerror("Error", "Python 'cantools' library missing.\nRun: pip install cantools")
            return

        fp = filedialog.askopenfilename(filetypes=[("DBC files", "*.dbc"), ("All", "*.*")])
        if not fp: return

        try:
            self.dbc_db = cantools.database.load_file(fp)
            self.dbc_messages = {msg.name: msg.frame_id for msg in self.dbc_db.messages}
            
            msg_count = len(self.dbc_messages)
            self._console_write(f"[INFO] Loaded DBC: {os.path.basename(fp)} ({msg_count} messages)\n")
            self.refresh_tab_dropdowns()

        except Exception as e:
            self._console_write(f"[ERROR] Failed to load DBC: {e}\n")

    def refresh_tab_dropdowns(self):
        msg_names = sorted(list(self.dbc_messages.keys()))
        if not msg_names: return
        
        for tab_name in ["fuzzer", "lenattack", "send", "uds"]:
            if hasattr(self.frames[tab_name], "update_msg_list"):
                self.frames[tab_name].update_msg_list(msg_names)

    def get_id_by_name(self, name):
        if name in self.dbc_messages:
            return hex(self.dbc_messages[name])
        return ""

    # =======================================
    # HELP MODAL LOGIC
    # =======================================
    def show_module_help(self, module_names):
        if isinstance(module_names, str):
            module_names = [module_names]

        full_output = ""
        # Use Dynamic Working Directory
        env = os.environ.copy()
        env["PYTHONPATH"] = self.working_dir + os.pathsep + env.get("PYTHONPATH", "")

        for mod in module_names:
            cmd = [sys.executable, "-m", "caringcaribou.caringcaribou", mod, "--help"]
            full_output += f"=== HELP: {mod.upper()} ===\nCommand: {' '.join(cmd)}\n\n"
            
            try:
                # Use Dynamic Working Directory
                output = subprocess.check_output(
                    cmd, env=env, stderr=subprocess.STDOUT, cwd=self.working_dir, text=True
                )
                full_output += output
            except subprocess.CalledProcessError as e:
                full_output += f"Error retrieving help: {e.output}"
            except Exception as e:
                full_output += f"Execution error: {str(e)}"
            
            full_output += "\n" + "-"*60 + "\n\n"

        # Create Modal Window
        top = ctk.CTkToplevel(self)
        top.title("Module Help")
        top.geometry("900x700")
        top.attributes("-topmost", True) 
        
        ctk.CTkLabel(top, text="Module Documentation", font=("Arial", 20, "bold")).pack(pady=10)
        
        textbox = ctk.CTkTextbox(top, font=("Consolas", 12))
        textbox.pack(fill="both", expand=True, padx=15, pady=10)
        textbox.insert("0.0", full_output)
        textbox.configure(state="disabled") # Read-only

        ctk.CTkButton(top, text="Close", command=top.destroy, fg_color="#c0392b").pack(pady=10)

    # =======================================
    # PROCESS EXECUTION
    # =======================================
    def run_command(self, args_list, module_name="General"):
        if self.current_process:
            messagebox.showwarning("Busy", "Process running. Stop first.")
            return

        cmd = [sys.executable, "-m", "caringcaribou.caringcaribou"] + [str(a) for a in args_list]
        
        # Use Dynamic Working Directory
        env = os.environ.copy()
        env["PYTHONPATH"] = self.working_dir + os.pathsep + env.get("PYTHONPATH", "")

        self._console_write(f"\n>>> [{module_name}] START: {' '.join(cmd)}\n")
        self._console_write(f">>> CWD: {self.working_dir}\n")
        
        current_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "module": module_name,
            "command": " ".join(cmd),
            "output": "", "status": "Running"
        }

        def target():
            out_buf = []
            try:
                cflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
                self.current_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1, cwd=self.working_dir, env=env,
                    creationflags=cflags, universal_newlines=True
                )

                while True:
                    line = self.current_process.stdout.readline()
                    if not line and self.current_process.poll() is not None: break
                    if line:
                        self._console_write(line)
                        out_buf.append(line)

                rc = self.current_process.poll()
                self._console_write(f"\n<<< FINISHED (Code: {rc})\n")
                
                current_entry["output"] = "".join(out_buf)
                current_entry["status"] = "Success" if rc == 0 else f"Failed ({rc})"
                self.session_history.append(current_entry)

            except Exception as e:
                self._console_write(f"\nERROR: {e}\n")
                current_entry["output"] = "".join(out_buf) + f"\nError: {e}"
                current_entry["status"] = "Error"
                self.session_history.append(current_entry)
            finally:
                self.current_process = None

        threading.Thread(target=target, daemon=True).start()

    def stop_process(self):
        if self.current_process:
            try:
                if os.name == 'nt':
                    subprocess.call(['taskkill', '/F', '/T', '/PID', str(self.current_process.pid)])
                else:
                    os.kill(self.current_process.pid, signal.SIGTERM)
            except: pass
            self.current_process = None
            self._console_write("\n[Process Stopped by User]\n")

    def _console_write(self, text):
        self.full_log_buffer.append(text)
        self.console.after(0, lambda: (self.console.insert("end", text), self.console.see("end")))

    # =======================================
    # REPORTING
    # =======================================
    def generate_pdf(self, filename, title, entries):
        if not REPORTLAB_AVAILABLE:
            messagebox.showerror("Error", "ReportLab not installed. Saving as .txt instead.")
            return self.save_txt_report(filename.replace(".pdf", ".txt"), title, entries)

        try:
            doc = SimpleDocTemplate(filename, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            story.append(Paragraph(title, styles['Title']))
            story.append(Spacer(1, 12))
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Spacer(1, 24))

            for idx, e in enumerate(entries):
                story.append(Paragraph(f"Action #{idx+1}: {e['module']}", styles['Heading2']))
                story.append(Paragraph(f"<b>Time:</b> {e['timestamp']}", styles['Normal']))
                story.append(Paragraph(f"<b>Command:</b> {e['command']}", styles['Normal']))
                status_color = "green" if "Success" in e['status'] else "red"
                story.append(Paragraph(f"<b>Status:</b> <font color={status_color}>{e['status']}</font>", styles['Normal']))
                story.append(Spacer(1, 6))
                out_text = e['output']
                if len(out_text) > 5000: out_text = out_text[:5000] + "\n... [TRUNCATED IN PDF] ..."
                style_code = styles['Code']
                style_code.fontSize = 8
                story.append(Preformatted(out_text, style_code))
                story.append(Spacer(1, 24))

            doc.build(story)
            messagebox.showinfo("Success", f"PDF Report Saved:\n{filename}")
        except Exception as e:
            messagebox.showerror("PDF Error", str(e))

    def save_txt_report(self, filename, title, entries):
        try:
            with open(filename, "w") as f:
                f.write(f"{title}\nGenerated: {datetime.now()}\n{'='*60}\n\n")
                for e in entries:
                    f.write(f"MODULE: {e['module']}\nTIME: {e['timestamp']}\nCMD: {e['command']}\nSTATUS: {e['status']}\nOUTPUT:\n{e['output']}\n{'-'*60}\n\n")
            messagebox.showinfo("Success", f"Text Report Saved:\n{filename}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def save_overall_report(self):
        if not self.session_history: return messagebox.showinfo("Info", "No history to report.")
        ext = ".pdf" if REPORTLAB_AVAILABLE else ".txt"
        ftypes = [("PDF Document", "*.pdf")] if REPORTLAB_AVAILABLE else [("Text File", "*.txt")]
        fn = filedialog.asksaveasfilename(defaultextension=ext, filetypes=ftypes)
        if fn: self.generate_pdf(fn, "FucyFuzz Overall Security Report", self.session_history)

    def save_module_report(self, mod):
        entries = [e for e in self.session_history if e['module'] == mod]
        if not entries: return messagebox.showinfo("Info", f"No history for {mod}.")
        ext = ".pdf" if REPORTLAB_AVAILABLE else ".txt"
        ftypes = [("PDF Document", "*.pdf")] if REPORTLAB_AVAILABLE else [("Text File", "*.txt")]
        fn = filedialog.asksaveasfilename(initialfile=f"{mod}_Report{ext}", defaultextension=ext, filetypes=ftypes)
        if fn: self.generate_pdf(fn, f"{mod} Module Report", entries)

    def save_full_logs(self):
        fn = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log File", "*.log")])
        if fn:
            with open(fn, "w") as f: f.writelines(self.full_log_buffer)
            messagebox.showinfo("Success", "Logs saved.")


# ==============================================================================
#  FRAMES
# ==============================================================================

class ConfigFrame(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        ctk.CTkLabel(self, text="System Configuration", font=("Arial", 24, "bold")).pack(anchor="w")
        
        # Grid for options
        grid = ctk.CTkFrame(self)
        grid.pack(fill="x", pady=20)
        
        # Working Directory Section
        ctk.CTkLabel(grid, text="Caring Caribou Path:").grid(row=0, column=0, padx=20, pady=20)
        
        self.wd_entry = ctk.CTkEntry(grid, placeholder_text="/path/to/caringcaribou")
        self.wd_entry.grid(row=0, column=1, padx=(20, 5), pady=20, sticky="ew")
        self.wd_entry.insert(0, app.working_dir)
        
        ctk.CTkButton(grid, text="Browse", width=80, command=self.browse_wd).grid(row=0, column=2, padx=20, pady=20)

        # Interface Section
        ctk.CTkLabel(grid, text="Interface:").grid(row=1, column=0, padx=20, pady=20)
        self.driver = ctk.CTkOptionMenu(grid, values=["socketcan", "vector", "pcan"])
        self.driver.grid(row=1, column=1, padx=20, pady=20, sticky="ew")

        ctk.CTkLabel(grid, text="Channel:").grid(row=2, column=0, padx=20, pady=20)
        self.channel = ctk.CTkEntry(grid, placeholder_text="vcan0")
        self.channel.grid(row=2, column=1, padx=20, pady=20, sticky="ew")

        grid.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(self, text="Save Config", command=self.save).pack(pady=20)

    def browse_wd(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.wd_entry.delete(0, "end")
            self.wd_entry.insert(0, dir_path)

    def save(self):
        # Update App Working Directory
        new_wd = self.wd_entry.get().strip()
        if os.path.exists(new_wd):
            self.app.working_dir = new_wd
            self.app._console_write(f"[CONFIG] Working Directory updated to: {new_wd}\n")
        else:
            messagebox.showwarning("Warning", "Path does not exist. Working directory not updated.")

        try:
            with open(os.path.expanduser("~/.canrc"), "w") as f:
                f.write(f"[default]\ninterface={self.driver.get()}\nchannel={self.channel.get()}\n")
            self.app._console_write("[CONFIG] ~/.canrc Config Saved.\n")
        except Exception as e: messagebox.showerror("Error", str(e))

class ReconFrame(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x")
        ctk.CTkLabel(head, text="Reconnaissance", font=("Arial", 24, "bold")).pack(side="left")
        
        # Buttons
        ctk.CTkButton(head, text="❓", width=40, fg_color="#f39c12", text_color="white", 
                      command=lambda: app.show_module_help("listener")).pack(side="right", padx=5)
        ctk.CTkButton(head, text="📥 Report (PDF)", width=100, 
                      command=lambda: app.save_module_report("Recon")).pack(side="right", padx=5)
        
        ctk.CTkButton(self, text="▶ Start Listener", height=50, command=lambda: app.run_command(["listener"], "Recon")).pack(expand=True)

class FuzzerFrame(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app

        # Header
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x")
        ctk.CTkLabel(head, text="Signal Fuzzer", font=("Arial", 24, "bold")).pack(side="left")
        
        # Buttons
        ctk.CTkButton(head, text="❓", width=40, fg_color="#f39c12", text_color="white",
                      command=lambda: app.show_module_help("fuzzer")).pack(side="right", padx=5)
        ctk.CTkButton(head, text="📥 Report (PDF)", width=100, 
                      command=lambda: app.save_module_report("Fuzzer")).pack(side="right", padx=5)

        tabs = ctk.CTkTabview(self)
        tabs.pack(fill="both", expand=True, pady=10)

        # Targeted Fuzz
        smart = tabs.add("Targeted")
        
        ctk.CTkLabel(smart, text="Select Message (Optional):").pack(pady=(10, 0))
        self.msg_select = ctk.CTkOptionMenu(smart, values=["No DBC Loaded"], command=self.on_msg_select)
        self.msg_select.pack(pady=5)
        
        self.tid = ctk.CTkEntry(smart, placeholder_text="Target ID (e.g., 0x123)")
        self.tid.pack(pady=5)
        self.data = ctk.CTkEntry(smart, placeholder_text="Data Pattern (e.g., 1122..44)")
        self.data.pack(pady=5)
        self.mode = ctk.CTkOptionMenu(smart, values=["brute", "mutate"])
        self.mode.pack(pady=10)
        
        ctk.CTkButton(smart, text="Launch Fuzzer", fg_color="#e67e22", command=self.run_smart).pack(pady=20)

        # Random
        rnd = tabs.add("Random")
        ctk.CTkButton(rnd, text="Start Random Noise", fg_color="#c0392b", command=lambda: app.run_command(["fuzzer", "random"], "Fuzzer")).pack(pady=20)

    def update_msg_list(self, names):
        self.msg_select.configure(values=names)
        self.msg_select.set("Select Message")

    def on_msg_select(self, selection):
        hex_id = self.app.get_id_by_name(selection)
        if hex_id:
            self.tid.delete(0, "end")
            self.tid.insert(0, hex_id)

    def run_smart(self):
        if not self.tid.get() or not self.data.get(): return messagebox.showerror("Error", "Missing ID/Data")
        self.app.run_command(["fuzzer", self.mode.get(), self.tid.get(), self.data.get()], "Fuzzer")


class LengthAttackFrame(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x")
        ctk.CTkLabel(head, text="Length Attack", font=("Arial", 24, "bold")).pack(side="left")
        
        # Buttons
        ctk.CTkButton(head, text="❓", width=40, fg_color="#f39c12", text_color="white",
                      command=lambda: app.show_module_help("lenattack")).pack(side="right", padx=5)
        ctk.CTkButton(head, text="📥 Report (PDF)", width=100, 
                      command=lambda: app.save_module_report("LengthAttack")).pack(side="right", padx=5)

        card = ctk.CTkFrame(self)
        card.pack(fill="x", padx=20, pady=20)

        # Row 0: DBC Select
        ctk.CTkLabel(card, text="DBC Message:").grid(row=0, column=0, padx=10, pady=10)
        self.msg_select = ctk.CTkOptionMenu(card, values=["No DBC Loaded"], command=self.on_msg_select)
        self.msg_select.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        # Row 1: Target ID
        ctk.CTkLabel(card, text="Target ID (Hex):").grid(row=1, column=0, padx=10, pady=10)
        self.lid = ctk.CTkEntry(card, placeholder_text="0x123")
        self.lid.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        # Row 2: Extra Args
        ctk.CTkLabel(card, text="Extra Args:").grid(row=2, column=0, padx=10, pady=10)
        self.largs = ctk.CTkEntry(card, placeholder_text="Optional (e.g. -v)")
        self.largs.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(self, text="START ATTACK", height=40, fg_color="#8e44ad", command=self.run_attack).pack(fill="x", padx=50, pady=20)

    def update_msg_list(self, names):
        self.msg_select.configure(values=names)
        self.msg_select.set("Select Message")

    def on_msg_select(self, selection):
        hex_id = self.app.get_id_by_name(selection)
        if hex_id:
            self.lid.delete(0, "end")
            self.lid.insert(0, hex_id)

    def run_attack(self):
        tid = self.lid.get().strip()
        if not tid: return messagebox.showerror("Error", "Enter ID")
        if not tid.startswith("0x") and not tid.isdigit(): tid = "0x" + tid
        
        cmd = ["lenattack", tid]
        if self.largs.get().strip():
            cmd.extend(self.largs.get().strip().split())
            
        self.app.run_command(cmd, "LengthAttack")

class UDSFrame(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x")
        ctk.CTkLabel(head, text="UDS Diagnostics", font=("Arial", 24, "bold")).pack(side="left")
        
        # Buttons
        ctk.CTkButton(head, text="❓", width=40, fg_color="#f39c12", text_color="white",
                      command=lambda: app.show_module_help("uds")).pack(side="right", padx=5)
        ctk.CTkButton(head, text="📥 Report (PDF)", width=100, 
                      command=lambda: app.save_module_report("UDS")).pack(side="right", padx=5)

        self.act = ctk.CTkOptionMenu(self, values=["discovery", "services", "subservices", "dump_dids", "read_mem", "security_seed"])
        self.act.pack(pady=10)

        # ADDED DBC SELECTION
        ctk.CTkLabel(self, text="DBC Message (Optional):").pack(pady=(10, 0))
        self.msg_select = ctk.CTkOptionMenu(self, values=["No DBC Loaded"], command=self.on_msg_select)
        self.msg_select.pack(pady=5)

        # ==========================================================
        #  FIXED LAYOUT: Checkbox above Entry for Perfect Alignment
        # ==========================================================
        
        # 1. Checkbox acts as label
        self.use_id_var = ctk.BooleanVar(value=True)
        self.id_chk = ctk.CTkCheckBox(self, text="Use Target ID:", variable=self.use_id_var, 
                                      command=self.toggle_id_entry)
        self.id_chk.pack(pady=(10, 5), anchor="w", padx=5)

        # 2. Entry uses fill="x" to match other fields exactly
        self.tid = ctk.CTkEntry(self, placeholder_text="Target ID (0x7E0)")
        self.tid.pack(fill="x", pady=5)

        self.args = ctk.CTkEntry(self, placeholder_text="Extra Args")
        self.args.pack(fill="x", pady=5) # Matches width of tid above
        
        ctk.CTkButton(self, text="Execute UDS", command=self.run).pack(pady=20)

    def toggle_id_entry(self):
        # Gray out the entry if checkbox is unchecked
        state = "normal" if self.use_id_var.get() else "disabled"
        self.tid.configure(state=state)

    def update_msg_list(self, names):
        self.msg_select.configure(values=names)
        self.msg_select.set("Select Message")

    def on_msg_select(self, selection):
        hex_id = self.app.get_id_by_name(selection)
        if hex_id:
            self.use_id_var.set(True) # Auto-enable
            self.toggle_id_entry()
            self.tid.delete(0, "end")
            self.tid.insert(0, hex_id)

    def run(self):
        cmd = ["uds", self.act.get()]
        
        # Only add ID if checkbox is True AND entry is not empty
        if self.use_id_var.get():
            val = self.tid.get().strip()
            if val:
                cmd.append(val)
                
        if self.args.get(): cmd.extend(self.args.get().split())
        self.app.run_command(cmd, "UDS")

class AdvancedFrame(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x")
        ctk.CTkLabel(head, text="Advanced", font=("Arial", 24, "bold")).pack(side="left")
        
        # Buttons (Show help for both advanced modules)
        ctk.CTkButton(head, text="❓", width=40, fg_color="#f39c12", text_color="white",
                      command=lambda: app.show_module_help(["doip", "xcp"])).pack(side="right", padx=5)
        ctk.CTkButton(head, text="📥 Report (PDF)", width=100, 
                      command=lambda: app.save_module_report("Advanced")).pack(side="right", padx=5)
        
        ctk.CTkButton(self, text="DoIP Discovery", command=lambda: app.run_command(["doip", "discovery"], "Advanced")).pack(fill="x", pady=10)
        self.xcp_id = ctk.CTkEntry(self, placeholder_text="XCP ID")
        self.xcp_id.pack(pady=5)
        ctk.CTkButton(self, text="XCP Info", command=lambda: app.run_command(["xcp", "info", self.xcp_id.get()], "Advanced")).pack(pady=5)

class SendFrame(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x")
        ctk.CTkLabel(head, text="Send & Replay", font=("Arial", 24, "bold")).pack(side="left")
        
        # Buttons
        ctk.CTkButton(head, text="❓", width=40, fg_color="#f39c12", text_color="white",
                      command=lambda: app.show_module_help("send")).pack(side="right", padx=5)
        ctk.CTkButton(head, text="📥 Report (PDF)", width=100, 
                      command=lambda: app.save_module_report("SendReplay")).pack(side="right", padx=5)

        man = ctk.CTkFrame(self)
        man.pack(fill="x", pady=10)
        
        ctk.CTkLabel(man, text="DBC Message:").pack()
        self.msg_select = ctk.CTkOptionMenu(man, values=["No DBC Loaded"], command=self.on_msg_select)
        self.msg_select.pack(pady=5)

        self.sid = ctk.CTkEntry(man, placeholder_text="ID (Hex)")
        self.sid.pack(pady=5)
        self.sdat = ctk.CTkEntry(man, placeholder_text="Data (Hex Bytes)")
        self.sdat.pack(pady=5)
        ctk.CTkButton(man, text="Send Frame", command=lambda: app.run_command(["send", self.sid.get(), self.sdat.get()], "SendReplay")).pack(pady=10)
        ctk.CTkButton(self, text="Replay File", command=self.replay).pack(pady=10)

    def update_msg_list(self, names):
        self.msg_select.configure(values=names)
        self.msg_select.set("Select Message")

    def on_msg_select(self, selection):
        hex_id = self.app.get_id_by_name(selection)
        if hex_id:
            self.sid.delete(0, "end")
            self.sid.insert(0, hex_id)

    def replay(self):
        fn = filedialog.askopenfilename()
        if fn: self.app.run_command(["fuzzer", "replay", fn], "SendReplay")

class MonitorFrame(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.is_monitoring = False

        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x", pady=10)
        ctk.CTkLabel(head, text="Traffic Monitor", font=("Arial", 24, "bold")).pack(side="left")
        ctk.CTkButton(head, text="📥 Save CSV", command=self.save_monitor).pack(side="right")

        ctl = ctk.CTkFrame(self)
        ctl.pack(fill="x", pady=5)
        
        ctk.CTkButton(ctl, text="▶ Simulate", command=self.toggle_sim, width=100, fg_color="#27ae60").pack(side="left", padx=5)
        ctk.CTkButton(ctl, text="🗑 Clear", command=self.clear, width=60, fg_color="gray30").pack(side="right")

        self.cols = ["Time", "ID", "Name", "Signals", "Raw"]
        self.header = ctk.CTkFrame(self, height=30, fg_color="#111")
        self.header.pack(fill="x")
        for i, c in enumerate(self.cols):
            lbl = ctk.CTkLabel(self.header, text=c, font=("Arial", 11, "bold"))
            lbl.grid(row=0, column=i, sticky="ew", padx=2)
            self.header.grid_columnconfigure(i, weight=1)

        self.scroll = ctk.CTkScrollableFrame(self, fg_color="#1a1a1a")
        self.scroll.pack(fill="both", expand=True)

    def add_row(self, aid, data):
        if len(self.scroll.winfo_children()) > 60: self.scroll.winfo_children()[0].destroy()
        vals = [time.strftime("%H:%M:%S"), hex(aid), "Unknown", "---", " ".join(f"{b:02X}" for b in data)]
        
        if self.app.dbc_db:
            try:
                m = self.app.dbc_db.get_message_by_frame_id(aid)
                if m:
                    vals[2] = m.name
                    vals[3] = str(m.decode(data))
            except: pass
            
        row = ctk.CTkFrame(self.scroll, height=25, fg_color=("gray20", "gray15"))
        row.pack(fill="x", pady=1)
        for i, v in enumerate(vals):
            ctk.CTkLabel(row, text=v, font=("Consolas", 10), anchor="w").grid(row=0, column=i, sticky="ew", padx=2)
            row.grid_columnconfigure(i, weight=1)

    def save_monitor(self):
        fn = filedialog.asksaveasfilename(defaultextension=".csv")
        if fn:
            with open(fn, "w") as f:
                f.write("Time,ID,Name,Signals,Raw\n")
                for row in self.scroll.winfo_children():
                    cols = [w.cget("text") for w in row.winfo_children() if isinstance(w, ctk.CTkLabel)]
                    f.write(",".join(cols) + "\n")
    
    def clear(self):
        for w in self.scroll.winfo_children(): w.destroy()

    def toggle_sim(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            threading.Thread(target=self._sim, daemon=True).start()
        else: self.is_monitoring = False

    def _sim(self):
        while self.is_monitoring:
            if self.app.dbc_db and self.app.dbc_db.messages:
                m = random.choice(self.app.dbc_db.messages)
                b = bytes([random.getrandbits(8) for _ in range(m.length)])
                self.after(0, lambda i=m.frame_id, d=b: self.add_row(i, d))
            else:
                b = bytes([random.getrandbits(8) for _ in range(8)])
                self.after(0, lambda i=random.randint(0x100, 0x500), d=b: self.add_row(i, d))
            time.sleep(0.2)

if __name__ == "__main__":
    app = CaribouApp()
    app.mainloop()