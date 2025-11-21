# report_helpers.py
# Report generation and dialog helpers for FucyFuzz

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import re
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

# ----------- REPORT GENERATION -----------
def generate_pdf_report(report_data, filename=None):
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fucyfuzz_report_{timestamp}.pdf"
    
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=30,
        textColor=colors.HexColor("#0078d7")
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=12,
        spaceAfter=12,
        textColor=colors.HexColor("#0078d7")
    )
    
    normal_style = styles['Normal']
    
    story = []
    
    story.append(Paragraph("FucyFuzz Security Assessment Report", title_style))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    story.append(Paragraph(f"Tool: {report_data.get('tool', 'Unknown')}", normal_style))
    story.append(Paragraph(f"Target ID: {report_data.get('target_id', 'N/A')}", normal_style))
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("Execution Details", heading_style))
    story.append(Paragraph(f"Command: {report_data.get('command', 'N/A')}", normal_style))
    story.append(Paragraph(f"Working Directory: {report_data.get('working_dir', 'N/A')}", normal_style))
    story.append(Paragraph(f"Exit Code: {report_data.get('exit_code', 'N/A')}", normal_style))
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("Results Summary", heading_style))
    
    if 'results_summary' in report_data:
        story.append(Paragraph(report_data['results_summary'], normal_style))
    else:
        story.append(Paragraph("No summary available.", normal_style))
    
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("Detailed Output", heading_style))
    
    output_text = report_data.get('full_output', 'No output captured.')
    if len(output_text) > 2000:
        output_text = output_text[:2000] + "\n\n...[Output truncated for PDF - see full log in application]..."
    
    story.append(Paragraph(output_text.replace('\n', '<br/>'), normal_style))
    
    doc.build(story)
    return filename

def generate_text_report(report_data, filename=None):
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fucyfuzz_report_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("FucyFuzz Security Assessment Report\n")
        f.write("=" * 60 + "\n\n")
        
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Tool: {report_data.get('tool', 'Unknown')}\n")
        f.write(f"Target ID: {report_data.get('target_id', 'N/A')}\n\n")
        
        f.write("Execution Details:\n")
        f.write("-" * 40 + "\n")
        f.write(f"Command: {report_data.get('command', 'N/A')}\n")
        f.write(f"Working Directory: {report_data.get('working_dir', 'N/A')}\n")
        f.write(f"Exit Code: {report_data.get('exit_code', 'N/A')}\n\n")
        
        f.write("Results Summary:\n")
        f.write("-" * 40 + "\n")
        if 'results_summary' in report_data:
            f.write(f"{report_data['results_summary']}\n")
        else:
            f.write("No summary available.\n")
        
        f.write("\nDetailed Output:\n")
        f.write("-" * 40 + "\n")
        f.write(report_data.get('full_output', 'No output captured.'))
    
    return filename

def save_logs_only(root, filename=None):
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fucyfuzz_logs_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("FucyFuzz Application Logs\n")
        f.write("=" * 60 + "\n\n")
        
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total log entries: {len(root.all_logs)}\n\n")
        
        f.write("Log Entries:\n")
        f.write("-" * 40 + "\n")
        for log_entry in root.all_logs:
            f.write(f"{log_entry}\n")
    
    return filename

def generate_overall_report(root, filename=None):
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fucyfuzz_overall_report_{timestamp}.pdf"
    
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=30,
        textColor=colors.HexColor("#0078d7")
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=12,
        spaceAfter=12,
        textColor=colors.HexColor("#0078d7")
    )
    
    normal_style = styles['Normal']
    
    story = []
    
    story.append(Paragraph("FucyFuzz Overall Security Assessment Report", title_style))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    story.append(Paragraph(f"Total processes executed: {len(root.all_reports)}", normal_style))
    story.append(Paragraph(f"Total log entries: {len(root.all_logs)}", normal_style))
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("Application Logs Summary", heading_style))
    
    if root.all_logs:
        recent_logs = root.all_logs[-50:] if len(root.all_logs) > 50 else root.all_logs
        logs_text = "\n".join(recent_logs)
        if len(root.all_logs) > 50:
            logs_text = f"...showing last 50 of {len(root.all_logs)} log entries...\n\n" + logs_text
        
        story.append(Paragraph(logs_text.replace('\n', '<br/>'), normal_style))
    else:
        story.append(Paragraph("No logs available.", normal_style))
    
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("Individual Process Reports", heading_style))
    
    for i, report in enumerate(root.all_reports):
        story.append(Paragraph(f"Report {i+1}: {report.get('tool', 'Unknown Tool')}", 
                             ParagraphStyle('SubHeading', parent=heading_style, fontSize=10)))
        
        story.append(Paragraph(f"Command: {report.get('command', 'N/A')}", normal_style))
        story.append(Paragraph(f"Exit Code: {report.get('exit_code', 'N/A')}", normal_style))
        story.append(Paragraph(f"Timestamp: {report.get('timestamp', 'N/A')}", normal_style))
        
        if 'results_summary' in report:
            summary = report['results_summary']
            if len(summary) > 500:
                summary = summary[:500] + "... [truncated]"
            story.append(Paragraph(f"Summary: {summary}", normal_style))
        
        story.append(Spacer(1, 10))
    
    doc.build(story)
    return filename

# ----------- DIALOG HELPERS -----------
def save_report_dialog(root, report_data, parent_window):
    def save_pdf():
        filename = filedialog.asksaveasfilename(
            parent=parent_window,
            title="Save PDF Report",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if filename:
            try:
                pdf_file = generate_pdf_report(report_data, filename)
                messagebox.showinfo("Success", f"PDF report saved as:\n{pdf_file}")
                parent_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save PDF report:\n{str(e)}")
    
    def save_txt():
        filename = filedialog.asksaveasfilename(
            parent=parent_window,
            title="Save Text Report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                txt_file = generate_text_report(report_data, filename)
                messagebox.showinfo("Success", f"Text report saved as:\n{txt_file}")
                parent_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save text report:\n{str(e)}")
    
    def save_json():
        filename = filedialog.asksaveasfilename(
            parent=parent_window,
            title="Save JSON Report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(report_data, f, indent=2)
                messagebox.showinfo("Success", f"JSON report saved as:\n{filename}")
                parent_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save JSON report:\n{str(e)}")
    
    def save_logs():
        filename = filedialog.asksaveasfilename(
            parent=parent_window,
            title="Save Logs Only",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                log_file = save_logs_only(root, filename)
                messagebox.showinfo("Success", f"Logs saved as:\n{log_file}")
                parent_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs:\n{str(e)}")
    
    save_dialog = tk.Toplevel(parent_window)
    save_dialog.title("Save Report")
    save_dialog.geometry("300x250")
    save_dialog.configure(bg="#ffffff")
    
    tk.Label(save_dialog, text="Choose Report Format", 
             font=("Segoe UI", 12, "bold"), bg="#ffffff").pack(pady=15)
    
    btn_style = {
        "bg": "#0078d7",
        "fg": "white",
        "font": ("Segoe UI", 10, "bold"),
        "relief": "flat",
        "width": 20,
        "height": 1
    }
    
    tk.Button(save_dialog, text="Save as PDF", command=save_pdf, **btn_style).pack(pady=5)
    tk.Button(save_dialog, text="Save as Text", command=save_txt, **btn_style).pack(pady=5)
    tk.Button(save_dialog, text="Save as JSON", command=save_json, **btn_style).pack(pady=5)
    tk.Button(save_dialog, text="Save Logs Only", command=save_logs, **btn_style).pack(pady=5)
    
    tk.Button(save_dialog, text="Cancel", bg="#6c757d", fg="white",
              font=("Segoe UI", 10), relief="flat", width=15,
              command=save_dialog.destroy).pack(pady=10)

def show_report_dialog(root, report_data, tool_name, success=True):
    report_dialog = tk.Toplevel(root)
    report_dialog.title(f"{tool_name} - Results")
    report_dialog.geometry("700x550")
    report_dialog.configure(bg="#ffffff")
    
    # Title
    title_frame = tk.Frame(report_dialog, bg="#e7f0ff")
    title_frame.pack(fill="x", padx=10, pady=10)
    tk.Label(title_frame, text=f"{tool_name} Completed", 
             font=("Segoe UI", 14, "bold"), bg="#e7f0ff").pack(pady=10)
    
    # Results summary
    summary_frame = tk.LabelFrame(report_dialog, text="Results Summary", 
                                 bg="#ffffff", font=("Segoe UI", 11, "bold"))
    summary_frame.pack(fill="x", padx=10, pady=5)
    
    summary_text = scrolledtext.ScrolledText(summary_frame, height=8, wrap=tk.WORD,
                                           font=("Consolas", 9))
    summary_text.pack(fill="both", expand=True, padx=5, pady=5)
    
    if 'results_summary' in report_data:
        summary_text.insert(tk.END, report_data['results_summary'])
    else:
        summary_text.insert(tk.END, "No summary available.")
    summary_text.config(state=tk.DISABLED)
    
    # Status bar
    status_frame = tk.Frame(report_dialog, bg="#f8f9fa", relief="sunken", bd=1)
    status_frame.pack(fill="x", padx=10, pady=5)
    
    status_color = "#28a745" if success else "#dc3545"
    status_text = "✅ SUCCESS" if success else "❌ FAILED"
    tk.Label(status_frame, text=status_text, fg=status_color, bg="#f8f9fa",
             font=("Segoe UI", 10, "bold")).pack(side="left", padx=10, pady=5)
    
    exit_code = report_data.get('exit_code', 'N/A')
    tk.Label(status_frame, text=f"Exit Code: {exit_code}", bg="#f8f9fa",
             font=("Segoe UI", 9)).pack(side="right", padx=10, pady=5)
    
    # Button frame
    button_frame = tk.Frame(report_dialog, bg="#ffffff")
    button_frame.pack(fill="x", padx=10, pady=10)
    
    btn_style = {
        "bg": "#0078d7",
        "fg": "white",
        "font": ("Segoe UI", 10, "bold"),
        "relief": "flat",
        "width": 15
    }
    
    tk.Button(button_frame, text="Download Report", 
              command=lambda: save_report_dialog(root, report_data, report_dialog),
              **btn_style).pack(side="left", padx=5)
    
    tk.Button(button_frame, text="Download Logs", 
              command=lambda: save_logs_dialog(root, report_dialog),
              **btn_style).pack(side="left", padx=5)
    
    tk.Button(button_frame, text="View Logs", 
              command=lambda: view_logs_dialog(root, report_dialog),
              **btn_style).pack(side="left", padx=5)
    
    tk.Button(button_frame, text="Close", bg="#6c757d", fg="white",
              font=("Segoe UI", 10), relief="flat", width=15,
              command=report_dialog.destroy).pack(side="right", padx=5)

def save_logs_dialog(root, parent_window):
    filename = filedialog.asksaveasfilename(
        parent=parent_window,
        title="Save Logs",
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if filename:
        try:
            log_file = save_logs_only(root, filename)
            messagebox.showinfo("Success", f"Logs saved as:\n{log_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save logs:\n{str(e)}")

def view_logs_dialog(root, parent_window):
    logs_dialog = tk.Toplevel(parent_window)
    logs_dialog.title("View Application Logs")
    logs_dialog.geometry("800x600")
    logs_dialog.configure(bg="#ffffff")
    
    title_frame = tk.Frame(logs_dialog, bg="#e7f0ff")
    title_frame.pack(fill="x", padx=10, pady=10)
    tk.Label(title_frame, text="Application Logs", 
             font=("Segoe UI", 14, "bold"), bg="#e7f0ff").pack(pady=10)
    
    info_frame = tk.Frame(logs_dialog, bg="#ffffff")
    info_frame.pack(fill="x", padx=10, pady=5)
    tk.Label(info_frame, text=f"Total log entries: {len(root.all_logs)}", 
             font=("Segoe UI", 10), bg="#ffffff").pack(side="left")
    
    logs_text = scrolledtext.ScrolledText(logs_dialog, wrap=tk.WORD, font=("Consolas", 9))
    logs_text.pack(fill="both", expand=True, padx=10, pady=10)
    
    if root.all_logs:
        logs_text.insert(tk.END, "\n".join(root.all_logs))
    else:
        logs_text.insert(tk.END, "No logs available.")
    logs_text.config(state=tk.DISABLED)
    
    button_frame = tk.Frame(logs_dialog, bg="#ffffff")
    button_frame.pack(fill="x", padx=10, pady=10)
    
    btn_style = {
        "bg": "#0078d7",
        "fg": "white",
        "font": ("Segoe UI", 10, "bold"),
        "relief": "flat",
        "width": 15
    }
    
    tk.Button(button_frame, text="Download Logs", 
              command=lambda: save_logs_dialog(root, logs_dialog),
              **btn_style).pack(side="left", padx=5)
    
    tk.Button(button_frame, text="Close", bg="#6c757d", fg="white",
              font=("Segoe UI", 10), relief="flat", width=15,
              command=logs_dialog.destroy).pack(side="right", padx=5)

def view_overall_logs_dialog(root):
    if not root.all_logs:
        messagebox.showinfo("No Logs", "No logs available to view.")
        return
    
    logs_dialog = tk.Toplevel(root)
    logs_dialog.title("Overall Application Logs")
    logs_dialog.geometry("900x700")
    logs_dialog.configure(bg="#ffffff")
    
    title_frame = tk.Frame(logs_dialog, bg="#e7f0ff")
    title_frame.pack(fill="x", padx=10, pady=10)
    tk.Label(title_frame, text="Overall Application Logs", 
             font=("Segoe UI", 14, "bold"), bg="#e7f0ff").pack(pady=10)
    
    info_frame = tk.Frame(logs_dialog, bg="#ffffff")
    info_frame.pack(fill="x", padx=10, pady=5)
    tk.Label(info_frame, text=f"Total log entries: {len(root.all_logs)}", 
             font=("Segoe UI", 10, "bold"), bg="#ffffff").pack(side="left")
    tk.Label(info_frame, text=f"Total processes: {len(root.all_reports)}", 
             font=("Segoe UI", 10, "bold"), bg="#ffffff").pack(side="left", padx=20)
    
    logs_text = scrolledtext.ScrolledText(logs_dialog, wrap=tk.WORD, font=("Consolas", 9))
    logs_text.pack(fill="both", expand=True, padx=10, pady=10)
    
    logs_text.insert(tk.END, "\n".join(root.all_logs))
    logs_text.config(state=tk.DISABLED)
    
    button_frame = tk.Frame(logs_dialog, bg="#ffffff")
    button_frame.pack(fill="x", padx=10, pady=10)
    
    btn_style = {
        "bg": "#0078d7",
        "fg": "white",
        "font": ("Segoe UI", 10, "bold"),
        "relief": "flat",
        "width": 15
    }
    
    tk.Button(button_frame, text="Download Logs", 
              command=lambda: save_overall_logs_dialog(root),
              **btn_style).pack(side="left", padx=5)
    
    tk.Button(button_frame, text="Close", bg="#6c757d", fg="white",
              font=("Segoe UI", 10), relief="flat", width=15,
              command=logs_dialog.destroy).pack(side="right", padx=5)

def save_overall_logs_dialog(root):
    if not root.all_logs:
        messagebox.showinfo("No Logs", "No logs available to save.")
        return
    
    filename = filedialog.asksaveasfilename(
        title="Save Overall Logs",
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if filename:
        try:
            log_file = save_logs_only(root, filename)
            messagebox.showinfo("Success", f"Overall logs saved as:\n{log_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save overall logs:\n{str(e)}")

def save_overall_report_dialog(root):
    if not root.all_reports and not root.all_logs:
        messagebox.showinfo("No Data", "No processes executed or logs available to generate overall report.")
        return
    
    filename = filedialog.asksaveasfilename(
        title="Save Overall Report",
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
    )
    if filename:
        try:
            report_file = generate_overall_report(root, filename)
            messagebox.showinfo("Success", f"Overall report saved as:\n{report_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save overall report:\n{str(e)}")

# ----------- SPECIALIZED DIALOGS -----------
def parse_and_update_from_lenattack(root, output_text, original_dbc_content):
    try:
        discovered_messages = []
        lines = output_text.split('\n')
        patterns = [
            r'Found message with ID\s+(0x[0-9a-fA-F]+|\d+).*?DLC\s+(\d+)',
            r'Message\s+(0x[0-9a-fA-F]+|\d+).*?length\s*[:=]\s*(\d+)',
            r'ID\s*(0x[0-9a-fA-F]+|\d+).*?DLC\s*[:=]\s*(\d+)',
            r'(0x[0-9a-fA-F]+|\d+)\s+.*?(\d+)\s+bytes?'
        ]
        for line in lines:
            line = line.strip()
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

def show_lenattack_results_dialog(root, report_data, full_command, working_dir, result_summary, success=True):
    popup = tk.Toplevel(root)
    popup.title("Length Attack Results")
    popup.geometry("800x650")
    popup.configure(bg="#ffffff")
    
    button_frame = tk.Frame(popup, bg="#ffffff")
    button_frame.pack(fill="x", padx=10, pady=5)
    
    tk.Button(button_frame, text="Download Report", bg="#0078d7", fg="white",
             font=("Segoe UI", 10, "bold"), relief="flat",
             command=lambda: save_report_dialog(root, report_data, popup)).pack(side="left", padx=5)
    
    tk.Button(button_frame, text="Download Logs", bg="#28a745", fg="white",
             font=("Segoe UI", 10, "bold"), relief="flat",
             command=lambda: save_logs_dialog(root, popup)).pack(side="left", padx=5)
    
    tk.Button(button_frame, text="View Logs", bg="#ffc107", fg="black",
             font=("Segoe UI", 10, "bold"), relief="flat",
             command=lambda: view_logs_dialog(root, popup)).pack(side="left", padx=5)
    
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
    
    # Status bar
    status_frame = tk.Frame(popup, bg="#f8f9fa", relief="sunken", bd=1)
    status_frame.pack(fill="x", padx=10, pady=5)
    
    status_color = "#28a745" if success else "#dc3545"
    status_text = "✅ SUCCESS" if success else "❌ FAILED"
    tk.Label(status_frame, text=status_text, fg=status_color, bg="#f8f9fa",
             font=("Segoe UI", 10, "bold")).pack(side="left", padx=10, pady=5)
    
    exit_code = report_data.get('exit_code', 'N/A')
    tk.Label(status_frame, text=f"Exit Code: {exit_code}", bg="#f8f9fa",
             font=("Segoe UI", 9)).pack(side="right", padx=10, pady=5)
    tk.Label(status_frame, text=f"Messages Found: {len(re.findall(r'ID: 0x', result_summary))}", bg="#f8f9fa",
             font=("Segoe UI", 9)).pack(side="right", padx=10, pady=5)
    
    tk.Button(button_frame, text="Close", bg="#6c757d", fg="white",
             command=popup.destroy).pack(side="right", padx=5)

def show_fuzzer_results_dialog(root, report_data, full_command, working_dir, full_output, success=True):
    popup = tk.Toplevel(root)
    popup.title("Fuzzing Results")
    popup.geometry("800x650")
    popup.configure(bg="#ffffff")
    
    button_frame = tk.Frame(popup, bg="#ffffff")
    button_frame.pack(fill="x", padx=10, pady=5)
    
    tk.Button(button_frame, text="Download Report", bg="#0078d7", fg="white",
             font=("Segoe UI", 10, "bold"), relief="flat",
             command=lambda: save_report_dialog(root, report_data, popup)).pack(side="left", padx=5)
    
    tk.Button(button_frame, text="Download Logs", bg="#28a745", fg="white",
             font=("Segoe UI", 10, "bold"), relief="flat",
             command=lambda: save_logs_dialog(root, popup)).pack(side="left", padx=5)
    
    tk.Button(button_frame, text="View Logs", bg="#ffc107", fg="black",
             font=("Segoe UI", 10, "bold"), relief="flat",
             command=lambda: view_logs_dialog(root, popup)).pack(side="left", padx=5)
    
    result_text = scrolledtext.ScrolledText(popup, wrap=tk.WORD, font=("Consolas", 10))
    result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    result_text.insert(tk.END, "=== FUZZING COMMAND ===\n")
    result_text.insert(tk.END, f"Command: {full_command}\n")
    result_text.insert(tk.END, f"Working Directory: {working_dir}\n")
    result_text.insert(tk.END, f"PYTHONPATH: {working_dir}\n")
    result_text.insert(tk.END, f"Exit Code: {report_data.get('exit_code', 'N/A')}\n")
    result_text.insert(tk.END, "\n" + "="*50 + "\n\n")
    result_text.insert(tk.END, "=== COMPLETE FUZZING OUTPUT ===\n\n")
    result_text.insert(tk.END, full_output)
    result_text.config(state=tk.DISABLED)
    
    # Status bar
    status_frame = tk.Frame(popup, bg="#f8f9fa", relief="sunken", bd=1)
    status_frame.pack(fill="x", padx=10, pady=5)
    
    status_color = "#28a745" if success else "#dc3545"
    status_text = "✅ SUCCESS" if success else "❌ FAILED"
    tk.Label(status_frame, text=status_text, fg=status_color, bg="#f8f9fa",
             font=("Segoe UI", 10, "bold")).pack(side="left", padx=10, pady=5)
    
    exit_code = report_data.get('exit_code', 'N/A')
    tk.Label(status_frame, text=f"Exit Code: {exit_code}", bg="#f8f9fa",
             font=("Segoe UI", 9)).pack(side="right", padx=10, pady=5)
    
    lines = full_output.split('\n')
    error_count = sum(1 for line in lines if 'error' in line.lower() or 'fail' in line.lower())
    success_count = sum(1 for line in lines if 'success' in line.lower() or 'found' in line.lower())
    tk.Label(status_frame, text=f"Potential Errors: {error_count}", bg="#f8f9fa",
             font=("Segoe UI", 9)).pack(side="right", padx=10, pady=5)
    tk.Label(status_frame, text=f"Potential Successes: {success_count}", bg="#f8f9fa",
             font=("Segoe UI", 9)).pack(side="right", padx=10, pady=5)
    
    tk.Button(button_frame, text="Close", bg="#6c757d", fg="white",
             command=popup.destroy).pack(side="right", padx=5)