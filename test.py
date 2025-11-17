#!/usr/bin/env python3
"""
Enhanced CaringCaribou + Tkinter example
- Configurable command to start CaringCaribou
- Start / Stop controls for subprocess per run.
- Safe threading: reader thread → queue → root.after poll to update GUI.
- Parses lenattack-like output for discovered CAN IDs and adds them to a Treeview.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import queue
import sys
import shutil
import re
import os

# ---------- Configuration ----------
DEFAULT_CAN_INTERFACE = "vcan0"  # change to can0 or vcan0 as appropriate
# Use current Python executable by default to ensure local modules are used
DEFAULT_CARING_CARIBOU_COMMAND = [sys.executable, "-m", "caringcaribou.caringcaribou"]
POLL_INTERVAL_MS = 120

# ---------- Runner class ----------
class CaringCaribouRunner:
    def __init__(self, output_queue, command, directory=None):
        self.proc = None
        self.thread = None
        self.output_queue = output_queue
        self._stop_event = threading.Event()
        self.command = command
        self.directory = directory

    def start(self, args_list, auto_add_interface=True):
        if self.proc is not None:
            raise RuntimeError("Process already running")
        cmd = self.command + args_list
        # Only add interface if requested and not already provided
        if auto_add_interface and "-i" not in args_list and "--interface" not in args_list:
            # insert -i after base command
            cmd = self.command + ["-i", DEFAULT_CAN_INTERFACE] + args_list
        
        # Set up environment for the process
        env = os.environ.copy()
        working_dir = self.directory
        
        # If using the fresh caringcaribou, set PYTHONPATH and working directory
        if working_dir:
            env["PYTHONPATH"] = working_dir
        
        # start subprocess
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                env=env,
                cwd=working_dir
            )
        except FileNotFoundError as e:
            raise
        # reader thread
        self._stop_event.clear()
        self.thread = threading.Thread(target=self._reader, daemon=True)
        self.thread.start()

    def _reader(self):
        try:
            # iterate lines until EOF
            for line in iter(self.proc.stdout.readline, ""):
                if line == '' and self.proc.poll() is not None:
                    break
                # push raw line
                self.output_queue.put(line)
                if self._stop_event.is_set():
                    break
            # collect any remaining text
            remaining = self.proc.stdout.read()
            if remaining:
                self.output_queue.put(remaining)
        except Exception as e:
            self.output_queue.put(f"[Runner error] {e}\n")
        finally:
            self.output_queue.put("__PROCESS_ENDED__")

    def stop(self):
        # signal stop and terminate process
        if self.proc is None:
            return
        self._stop_event.set()
        try:
            self.proc.terminate()
        except Exception:
            pass
        # attempt graceful wait, then kill
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                self.proc.kill()
            except Exception:
                pass

    def is_running(self):
        return self.proc is not None and self.proc.poll() is None

# ---------- GUI ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CaringCaribou - Tkinter Integration")
        self.geometry("1000x700")

        # Configuration
        self.caring_caribou_command = DEFAULT_CARING_CARIBOU_COMMAND.copy()
        self.caring_caribou_directory = "/home/fucy-can/FUCY/caringcaribou_fresh"  # Set your directory here

        # top frame: controls
        ctrl_frame = ttk.Frame(self)
        ctrl_frame.pack(fill=tk.X, padx=8, pady=6)

        ttk.Label(ctrl_frame, text="CAN Interface:").pack(side=tk.LEFT)
        self.iface_var = tk.StringVar(value=DEFAULT_CAN_INTERFACE)
        iface_entry = ttk.Entry(ctrl_frame, textvariable=self.iface_var, width=12)
        iface_entry.pack(side=tk.LEFT, padx=(4, 16))

        self.start_btn = ttk.Button(ctrl_frame, text="Start LenAttack", command=self.open_lenattack_popup)
        self.start_btn.pack(side=tk.LEFT)

        self.stop_btn = ttk.Button(ctrl_frame, text="Stop Running", command=self.stop_running, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=6)

        self.test_btn = ttk.Button(ctrl_frame, text="Test CaringCaribou", command=self.test_caringcaribou)
        self.test_btn.pack(side=tk.LEFT, padx=6)

        self.config_btn = ttk.Button(ctrl_frame, text="Configure Command", command=self.configure_command)
        self.config_btn.pack(side=tk.LEFT, padx=6)

        self.help_btn = ttk.Button(ctrl_frame, text="Help", command=self.show_help)
        self.help_btn.pack(side=tk.LEFT, padx=6)

        # center frames: left -> discovered IDs, right -> log
        center = ttk.Frame(self)
        center.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Left: discovered messages / results
        left = ttk.Frame(center)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=False)
        ttk.Label(left, text="Discovered / Parsed IDs").pack(anchor=tk.W)
        self.tree = ttk.Treeview(left, columns=("id_hex", "info"), show="headings", height=20)
        self.tree.heading("id_hex", text="ID")
        self.tree.heading("info", text="Info")
        self.tree.column("id_hex", width=100, anchor=tk.CENTER)
        self.tree.column("info", width=240)
        self.tree.pack(fill=tk.Y, expand=True)

        # Right: logs
        right = ttk.Frame(center)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Label(right, text="CAN / CaringCaribou Log").pack(anchor=tk.W)
        self.log_text = scrolledtext.ScrolledText(right, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # bottom status
        status = ttk.Frame(self)
        status.pack(fill=tk.X, padx=8, pady=4)
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(status, textvariable=self.status_var).pack(anchor=tk.W)

        # command status
        self.command_status_var = tk.StringVar(value=f"Command: {' '.join(self.caring_caribou_command)}")
        ttk.Label(status, textvariable=self.command_status_var, foreground="blue").pack(anchor=tk.W)

        # directory status
        self.directory_status_var = tk.StringVar(value=f"Directory: {self.caring_caribou_directory}")
        ttk.Label(status, textvariable=self.directory_status_var, foreground="green").pack(anchor=tk.W)

        # runner and queue
        self.q = queue.Queue()
        self.runner = CaringCaribouRunner(self.q, self.caring_caribou_command, self.caring_caribou_directory)

        # poll queue
        self.after(POLL_INTERVAL_MS, self._poll_queue)

        # graceful cleanup on close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # regex to capture discovered ids (heuristic)
        self._discover_regex = re.compile(r"\b(0x[0-9A-Fa-f]{1,3}|[0-9]{1,5})\b")

        # Show initial configuration
        self.log_text.insert(tk.END, f"Initial configuration:\n")
        self.log_text.insert(tk.END, f"  Command: {' '.join(self.caring_caribou_command)}\n")
        self.log_text.insert(tk.END, f"  Directory: {self.caring_caribou_directory}\n")
        self.log_text.insert(tk.END, f"  Python: {sys.executable}\n")
        self.log_text.see(tk.END)

    def open_lenattack_popup(self):
        """Open popup to configure and start lenattack"""
        popup = tk.Toplevel(self)
        popup.title("Length Attack")
        popup.transient(self)

        ttk.Label(popup, text="Message ID (hex, e.g. 0x123):").grid(row=0, column=0, sticky=tk.W, padx=6, pady=6)
        msgid_var = tk.StringVar(value="0x123")
        ttk.Entry(popup, textvariable=msgid_var, width=16).grid(row=0, column=1, padx=6, pady=6)

        ttk.Label(popup, text="Interface (optional):").grid(row=1, column=0, sticky=tk.W, padx=6, pady=6)
        i_var = tk.StringVar(value="")  # Empty by default for lenattack
        ttk.Entry(popup, textvariable=i_var, width=12).grid(row=1, column=1, padx=6, pady=6)

        def start_lenattack():
            mid = msgid_var.get().strip()
            if not mid:
                messagebox.showerror("Input error", "Please enter a message ID")
                return
            # build args for lenattack - NO automatic interface
            args = ["lenattack", mid]
            # Only include interface if user provided one
            interface = i_var.get().strip()
            if interface:
                args += ["-i", interface]
            
            # Show the exact command that will be executed
            full_cmd = self.caring_caribou_command + args
            self.log_text.insert(tk.END, f"\n=== Starting LenAttack ===\n")
            self.log_text.insert(tk.END, f"Full command: {' '.join(full_cmd)}\n")
            self.log_text.insert(tk.END, f"Working directory: {self.caring_caribou_directory}\n")
            self.log_text.insert(tk.END, f"PYTHONPATH: {self.caring_caribou_directory}\n")
            self.log_text.insert(tk.END, "=" * 50 + "\n")
            self.log_text.see(tk.END)
            
            try:
                # Don't auto-add interface for lenattack
                self._start_process_with_args(args, auto_add_interface=False)
                popup.destroy()
            except FileNotFoundError as e:
                messagebox.showerror("Start error", f"Failed to start CaringCaribou: {e}")

        ttk.Button(popup, text="Start", command=start_lenattack).grid(row=3, column=0, padx=6, pady=8)
        ttk.Button(popup, text="Cancel", command=popup.destroy).grid(row=3, column=1, padx=6, pady=8)

    def _start_process_with_args(self, args_list, auto_add_interface=True):
        """Start the CaringCaribou process with given arguments"""
        # ensure no other process running
        if self.runner.is_running():
            messagebox.showwarning("Already Running", "A CaringCaribou process is already running. Stop it first.")
            return
        # set interface default for runner
        global DEFAULT_CAN_INTERFACE
        DEFAULT_CAN_INTERFACE = self.iface_var.get()
        
        # start using the runner's start method which handles environment
        try:
            self.runner.start(args_list, auto_add_interface=auto_add_interface)
        except FileNotFoundError as e:
            raise
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start process: {e}")
            return
        self.status_var.set("Running")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

    def stop_running(self):
        """Stop the currently running process"""
        if not self.runner.is_running():
            return
        self.log_text.insert(tk.END, "Stopping process...\n")
        self.log_text.see(tk.END)
        self.runner.stop()

    def test_caringcaribou(self):
        """Test if CaringCaribou is working"""
        # Use the same approach as the help command
        self.show_help()

    def show_help(self):
        """Show CaringCaribou help in the log area using the configured command"""
        # Use the EXACT same approach as the runner
        help_command = self.caring_caribou_command + ["--help"]
        
        self.log_text.insert(tk.END, f"\n=== Running Help Command ===\n")
        self.log_text.insert(tk.END, f"Command: {' '.join(help_command)}\n")
        self.log_text.insert(tk.END, f"Working directory: {self.caring_caribou_directory}\n")
        self.log_text.insert(tk.END, f"PYTHONPATH: {self.caring_caribou_directory}\n")
        self.log_text.insert(tk.END, "=" * 50 + "\n")
        self.log_text.see(tk.END)
        
        try:
            # Use Popen EXACTLY like the runner does, but capture output
            proc = subprocess.Popen(
                help_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                env={"PYTHONPATH": self.caring_caribou_directory, **os.environ},
                cwd=self.caring_caribou_directory
            )
            
            # Read output like the runner does
            stdout, stderr = proc.communicate(timeout=10)
            
            if stdout:
                self.log_text.insert(tk.END, stdout + "\n")
                # Check if lenattack is in the output
                if "lenattack" in stdout:
                    self.log_text.insert(tk.END, "✓ lenattack module found!\n")
                else:
                    self.log_text.insert(tk.END, "⚠ lenattack module NOT found in available modules\n")
            if stderr:
                self.log_text.insert(tk.END, "STDERR:\n" + stderr + "\n")
            if not stdout and not stderr:
                self.log_text.insert(tk.END, "No output received\n")
                
            self.log_text.insert(tk.END, f"Help command completed with return code: {proc.returncode}\n")
            
        except subprocess.TimeoutExpired:
            self.log_text.insert(tk.END, "Help command timed out after 10 seconds\n")
        except FileNotFoundError:
            self.log_text.insert(tk.END, f"Error: Could not find CaringCaribou\n")
            self.log_text.insert(tk.END, f"Current command: {' '.join(self.caring_caribou_command)}\n")
            self.log_text.insert(tk.END, f"Make sure 'caringcaribou' is installed and available\n")
        except Exception as e:
            self.log_text.insert(tk.END, f"Error running help command: {e}\n")
        
        self.log_text.insert(tk.END, "=" * 50 + "\n")
        self.log_text.see(tk.END)

    def configure_command(self):
        """Open a dialog to configure the CaringCaribou command"""
        popup = tk.Toplevel(self)
        popup.title("Configure CaringCaribou Command")
        popup.geometry("700x400")
        popup.transient(self)
        
        ttk.Label(popup, text="CaringCaribou Command:").pack(anchor=tk.W, padx=10, pady=(10, 0))
        
        # Create a frame for the command entry and browse button
        cmd_frame = ttk.Frame(popup)
        cmd_frame.pack(fill=tk.X, padx=10, pady=5)
        
        cmd_var = tk.StringVar(value=" ".join(self.caring_caribou_command))
        cmd_entry = ttk.Entry(cmd_frame, textvariable=cmd_var, width=80)
        cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        def update_command():
            new_cmd = cmd_var.get().strip()
            if not new_cmd:
                messagebox.showerror("Error", "Command cannot be empty")
                return
            
            # Split the command into parts
            new_cmd_parts = new_cmd.split()
            self.caring_caribou_command = new_cmd_parts
            self.runner.command = new_cmd_parts
            self.command_status_var.set(f"Command: {' '.join(new_cmd_parts)}")
            self.log_text.insert(tk.END, f"Updated command to: {' '.join(new_cmd_parts)}\n")
            self.log_text.see(tk.END)
            popup.destroy()
        
        def reset_to_default():
            self.caring_caribou_command = DEFAULT_CARING_CARIBOU_COMMAND.copy()
            self.runner.command = self.caring_caribou_command
            self.command_status_var.set(f"Command: {' '.join(self.caring_caribou_command)}")
            cmd_var.set(" ".join(self.caring_caribou_command))
            self.log_text.insert(tk.END, f"Reset command to default: {' '.join(self.caring_caribou_command)}\n")
            self.log_text.see(tk.END)

        def test_command():
            """Test the current command in the entry field"""
            test_cmd = cmd_var.get().strip().split()
            if not test_cmd:
                messagebox.showerror("Error", "Command cannot be empty")
                return
            
            # Create a temporary runner to test the command
            temp_runner = CaringCaribouRunner(queue.Queue(), test_cmd, self.caring_caribou_directory)
            try:
                # Use the runner's start method which handles environment
                temp_runner.start(["--help"])
                
                # Wait for process to complete
                temp_runner.proc.wait(timeout=8)
                
                # Check output
                output = ""
                while True:
                    try:
                        line = temp_runner.output_queue.get_nowait()
                        if line == "__PROCESS_ENDED__":
                            break
                        output += line
                    except queue.Empty:
                        break
                
                if "lenattack" in output:
                    messagebox.showinfo("Command Test", 
                                      "Command test successful! ✓\nThe command works correctly and lenattack module is available.")
                else:
                    messagebox.showwarning("Command Test", 
                                         "Command works but lenattack module NOT found.\nAvailable modules may be different than expected.")
                    
            except Exception as e:
                messagebox.showerror("Command Test", f"Command test failed: {e}")
            finally:
                if temp_runner.is_running():
                    temp_runner.stop()
        
        def browse_directory():
            """Browse for the caringcaribou directory"""
            directory = filedialog.askdirectory(
                title="Select CaringCaribou directory",
                initialdir="/home/fucy-can/FUCY"
            )
            if directory:
                # Use module format with the selected directory
                cmd_var.set(f"{sys.executable} -m caringcaribou.caringcaribou")
                # Store the directory path for environment setup
                self.caring_caribou_directory = directory
                self.directory_status_var.set(f"Directory: {directory}")
                self.runner.directory = directory
                self.log_text.insert(tk.END, f"Selected CaringCaribou directory: {directory}\n")
        
        # Buttons frame
        btn_frame = ttk.Frame(popup)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(btn_frame, text="Browse Directory", command=browse_directory).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Test Command", command=test_command).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Update Command", command=update_command).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Reset to Default", command=reset_to_default).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Cancel", command=popup.destroy).pack(side=tk.LEFT)
        
        # Help text
        help_text = (
            f"Current Python: {sys.executable}\n"
            f"Current Directory: {self.caring_caribou_directory}\n\n"
            "IMPORTANT: Use module format for CaringCaribou:\n"
            "- python -m caringcaribou.caringcaribou\n\n"
            "If using your local copy:\n"
            "1. Click 'Browse Directory' and select the directory\n"
            "2. Click 'Test Command' to verify\n"
            "3. Click 'Update Command' to apply\n"
        )
        
        help_label = ttk.Label(popup, text=help_text, foreground="gray", justify=tk.LEFT)
        help_label.pack(anchor=tk.W, padx=10, pady=(10, 0))

    def _poll_queue(self):
        """Poll the queue for process output"""
        try:
            while True:
                line = self.q.get_nowait()
                if line == "__PROCESS_ENDED__":
                    self._on_process_end()
                    continue
                self._handle_process_line(line)
        except queue.Empty:
            pass
        finally:
            self.after(POLL_INTERVAL_MS, self._poll_queue)

    def _handle_process_line(self, line):
        """Handle a line of output from the process"""
        # append to log
        self.log_text.insert(tk.END, line)
        self.log_text.see(tk.END)
        # quick parsing: look for hex IDs in the line and add to tree
        for m in self._discover_regex.finditer(line):
            token = m.group(1)
            # simple filter: prefer 0x... hex tokens
            if token.lower().startswith("0x"):
                hex_id = token.lower()
                # ensure not already present
                if not self._tree_has_id(hex_id):
                    self.tree.insert("", tk.END, values=(hex_id, "discovered"))

    def _tree_has_id(self, hex_id):
        """Check if tree already has this ID"""
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            if vals and vals[0] == hex_id:
                return True
        return False

    def _on_process_end(self):
        """Handle process termination"""
        self.status_var.set("Idle")
        self.log_text.insert(tk.END, "\n[Process finished]\n")
        self.log_text.see(tk.END)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def _on_close(self):
        """Handle window close event"""
        if self.runner.is_running():
            if not messagebox.askyesno("Quit", "A process is running. Stop and quit?"):
                return
            self.runner.stop()
        self.destroy()

# ---------- Run app ----------
if __name__ == '__main__':
    app = App()
    app.mainloop()