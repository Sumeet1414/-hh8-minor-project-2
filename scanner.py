import os
import time
import hashlib
import csv
from pathlib import Path


DB_FILE = "recent.csv" 

FOLDER_TO_SCAN = Path.home() / "Downloads"

def load_signatures(csv_path):
    """
    Loads MD5 hashes from the MalwareBazaar CSV into a Python set.
    """
    malicious_hashes = set()
    print(f"[*] Loading signatures from {csv_path}...")
    
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].startswith('#'):
                    continue
                
                for item in row:
                    item = item.strip()
                    if len(item) == 32:
                        malicious_hashes.add(item)
                        break 

        print(f"[+] Loaded {len(malicious_hashes)} malicious signatures.")
        return malicious_hashes
        
    except FileNotFoundError:
        print(f"[!] Error: '{csv_path}' not found. Make sure it is in this folder!")
        return set()

def calculate_md5(file_path):
    """
    Calculates the MD5 hash of a file efficiently.
    """
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None

def scan_directory(folder_path, signature_set):
    """
    Scans the folder and checks files against the bad signature set.
    """
    print(f"\n[*] Scanning directory: {folder_path}")
    found_threats = []

    
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            
            
            local_md5 = calculate_md5(file_path)
            
           
            if local_md5 and local_md5 in signature_set:
                print(f" [!!!] ALERT: MALWARE DETECTED!")
                print(f"       File: {file_path}")
                print(f"       Hash: {local_md5}")
                found_threats.append(file_path)

    if not found_threats:
        print("[*] Scan complete. No threats found.")
    else:
        print(f"[*] Scan complete. {len(found_threats)} threats detected.")


if __name__ == "__main__":
    signatures = load_signatures(DB_FILE)
    
    if len(signatures) > 0:
        print("------------------------------------------------")
        print("Scanner is RUNNING. Press Ctrl+C to stop.")
        print("------------------------------------------------")
        
        try:
            while True:
                scan_directory(FOLDER_TO_SCAN, signatures)
                print("[*] Sleeping for 60 seconds...")
                time.sleep(60)
        except KeyboardInterrupt:
            print("\n[!] Stopping scanner.")
    else:
        print("[!] Scanner stopped because no signatures were loaded.")