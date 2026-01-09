import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import hashlib
import csv
import threading
import shutil
import time
from pathlib import Path

class AdvancedScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Sentinel Hash Scanner - Advanced")
        self.root.geometry("900x600")
        
        # --- State Variables ---
        self.signatures = set()
        self.folder_path = Path.home() / "Downloads"
        self.quarantine_folder = Path.home() / "Malware_Quarantine"
        self.db_path = "recent.csv"
        self.is_monitoring = False
        self.stop_event = threading.Event()

        # Create Quarantine Folder if not exists
        if not os.path.exists(self.quarantine_folder):
            os.makedirs(self.quarantine_folder)

        # --- STYLE CONFIGURATION ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", rowheight=25)
        style.configure("TButton", padding=6, font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))

        # --- LAYOUT FRAMES ---
        
        # 1. Top Bar (Configuration)
        self.frame_top = tk.Frame(root, bg="#f0f0f0", pady=10)
        self.frame_top.pack(fill="x")
        
        tk.Label(self.frame_top, text="Database:", bg="#f0f0f0").pack(side="left", padx=(10, 5))
        self.lbl_db = tk.Label(self.frame_top, text=self.db_path, fg="blue", bg="#f0f0f0", width=20, anchor="w")
        self.lbl_db.pack(side="left")
        ttk.Button(self.frame_top, text="📂 Load DB", command=self.load_db_thread).pack(side="left", padx=5)

        tk.Label(self.frame_top, text="|  Target:", bg="#f0f0f0").pack(side="left", padx=10)
        self.lbl_folder = tk.Label(self.frame_top, text=str(self.folder_path), fg="blue", bg="#f0f0f0", width=30, anchor="w")
        self.lbl_folder.pack(side="left")
        ttk.Button(self.frame_top, text="📂 Change", command=self.choose_folder).pack(side="left", padx=5)

        # 2. Dashboard Stats
        self.frame_stats = tk.Frame(root, pady=10)
        self.frame_stats.pack(fill="x", padx=10)
        
        self.lbl_sig_count = ttk.Label(self.frame_stats, text="⚠️ Signatures: 0", style="Header.TLabel", foreground="red")
        self.lbl_sig_count.pack(side="left", padx=20)
        
        self.lbl_status = ttk.Label(self.frame_stats, text="🟢 System Idle", style="Header.TLabel", foreground="green")
        self.lbl_status.pack(side="right", padx=20)

        # 3. Controls & Progress
        self.frame_controls = tk.LabelFrame(root, text="Scanner Controls", padx=10, pady=10)
        self.frame_controls.pack(fill="x", padx=10, pady=5)
        
        self.btn_scan = ttk.Button(self.frame_controls, text="🚀 Run Full Scan", command=self.start_scan_thread)
        self.btn_scan.pack(side="left", padx=5)

        self.btn_monitor = ttk.Button(self.frame_controls, text="👁️ Enable Auto-Monitor", command=self.toggle_monitor)
        self.btn_monitor.pack(side="left", padx=5)

        self.progress = ttk.Progressbar(self.frame_controls, orient="horizontal", mode="indeterminate")
        self.progress.pack(side="right", fill="x", expand=True, padx=10)

        # 4. Results Table (Treeview)
        self.tree_frame = tk.Frame(root)
        self.tree_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("file", "status", "path")
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("file", text="File Name")
        self.tree.heading("status", text="Threat Status")
        self.tree.heading("path", text="Full Path")
        
        self.tree.column("file", width=200)
        self.tree.column("status", width=150)
        self.tree.column("path", width=400)
        
        scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        # 5. Bottom Actions (Quarantine)
        self.frame_bottom = tk.Frame(root, pady=10)
        self.frame_bottom.pack(fill="x", padx=10)
        
        ttk.Button(self.frame_bottom, text="🚫 Quarantine Selected", command=self.quarantine_selected).pack(side="right")
        ttk.Button(self.frame_bottom, text="🗑️ Clear List", command=self.clear_list).pack(side="right", padx=10)

    # --- LOGIC ---

    def log_threat(self, filename, status, filepath):
        """Insert a row into the table"""
        self.tree.insert("", "end", values=(filename, status, filepath))

    def choose_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path = folder
            self.lbl_folder.config(text=folder)

    def load_db_thread(self):
        threading.Thread(target=self._load_db, daemon=True).start()

    def _load_db(self):
        """
        Loads the database and FIXES the quote issue from Excel/CSV
        """
        self.progress.start(10)
        self.lbl_status.config(text="⏳ Loading DB...", foreground="orange")
        
        temp_sigs = set()
        try:
            with open(self.db_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                for row in reader:
                    if not row or row[0].startswith('#'): continue
                    
                    for item in row:
                        # --- CRITICAL FIX: Remove quotes (" or ') ---
                        clean_item = item.strip().strip('"').strip("'")
                        
                        if len(clean_item) == 32:
                            temp_sigs.add(clean_item)
                            # Do not break immediately; some lines might have multiple hashes
            
            self.signatures = temp_sigs
            
            # Update GUI safely
            self.root.after(0, lambda: self.lbl_sig_count.config(text=f"✅ Signatures: {len(self.signatures)}", foreground="green"))
            self.root.after(0, lambda: self.lbl_status.config(text="🟢 Ready", foreground="green"))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        self.root.after(0, self.progress.stop)

    def start_scan_thread(self):
        if not self.signatures:
            messagebox.showwarning("Warning", "Load Database first!")
            return
        threading.Thread(target=self._scan, daemon=True).start()

    def _scan(self):
        self.root.after(0, lambda: self.btn_scan.config(state="disabled"))
        self.root.after(0, lambda: self.lbl_status.config(text="🔍 Scanning...", foreground="orange"))
        self.root.after(0, self.progress.start, 10)
        
        threat_count = 0
        
        if not self.is_monitoring:
            self.root.after(0, self.clear_list)

        for root_dir, _, files in os.walk(self.folder_path):
            if self.stop_event.is_set(): break
            
            for file in files:
                file_path = os.path.join(root_dir, file)
                
                # Check MD5
                local_md5 = self.calculate_md5(file_path)
                
                if local_md5 and local_md5 in self.signatures:
                    threat_count += 1
                    self.root.after(0, lambda f=file, p=file_path: self.log_threat(f, "⚠️ MALWARE MATCH", p))
        
        self.root.after(0, self.progress.stop)
        self.root.after(0, lambda: self.btn_scan.config(state="normal"))
        
        if threat_count == 0:
            self.root.after(0, lambda: self.lbl_status.config(text="🟢 Clean", foreground="green"))
        else:
            self.root.after(0, lambda: self.lbl_status.config(text=f"🔴 Found {threat_count} Threats!", foreground="red"))

    def calculate_md5(self, file_path):
        hasher = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None

    def toggle_monitor(self):
        if self.is_monitoring:
            self.is_monitoring = False
            self.stop_event.set()
            self.btn_monitor.config(text="👁️ Enable Auto-Monitor")
            self.lbl_status.config(text="🟢 Monitor Stopped", foreground="green")
        else:
            if not self.signatures:
                messagebox.showwarning("Warning", "Load Database first!")
                return
            self.is_monitoring = True
            self.stop_event.clear()
            self.btn_monitor.config(text="⏹️ Stop Monitor")
            threading.Thread(target=self._monitor_loop, daemon=True).start()

    def _monitor_loop(self):
        while self.is_monitoring:
            self.root.after(0, lambda: self.lbl_status.config(text="👁️ Monitoring...", foreground="blue"))
            self._scan()
            time.sleep(60)

    def quarantine_selected(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Select File", "Please select a threat from the list to quarantine.")
            return

        item_data = self.tree.item(selected_item)
        file_path = item_data['values'][2]
        file_name = item_data['values'][0]

        try:
            destination = self.quarantine_folder / file_name
            shutil.move(file_path, destination)
            self.tree.item(selected_item, values=(file_name, "🛡️ QUARANTINED", str(destination)))
            messagebox.showinfo("Success", f"File moved to:\n{destination}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not quarantine file:\n{e}")

    def clear_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

# --- Run ---
if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedScannerApp(root)
    root.mainloop()