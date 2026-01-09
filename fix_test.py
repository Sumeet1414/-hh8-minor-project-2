import hashlib
import os
from pathlib import Path

# --- CONFIGURATION ---
# This script creates a file and puts its hash directly into your CSV
# so there is ZERO chance of a mistake.

folder = Path.home() / "Downloads"
csv_path = "recent.csv"

# 1. Create the dummy virus file
file_path = folder / "simulation_virus.txt"
content = b"DANGEROUS_VIRUS_SIMULATION_DATA" # Specific content

try:
    with open(file_path, "wb") as f:
        f.write(content)
    print(f"[+] Created test file at: {file_path}")
except Exception as e:
    print(f"[!] Error creating file: {e}")
    exit()

# 2. Calculate its EXACT MD5 Hash
md5 = hashlib.md5(content).hexdigest()
print(f"[+] The exact hash is: {md5}")

# 3. Append this hash to your CSV file
try:
    # We add a new line to be safe
    new_row = f"\n2025-01-08,{md5},sha256_fake,Simulation_Virus"
    
    with open(csv_path, "a") as f:
        f.write(new_row)
        
    print(f"[+] Successfully added hash to {csv_path}")
    print("\n---------------------------------------------------")
    print("SOLVED! Now run 'advanced_scanner.py' and scan.")
    print("---------------------------------------------------")
    
except PermissionError:
    print("[!] ERROR: Could not write to recent.csv.")
    print("    Please CLOSE the CSV file if it is open in Excel!")