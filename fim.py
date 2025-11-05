import sys
import os
import json
import hashlib
import logging
import re
from datetime import datetime

# --- Konfigurasi Sistem ---

# Folder yang akan dipantau
MONITOR_DIR = "./secure_files/"

# File untuk menyimpan baseline hash
HASH_DB_FILE = "hash_db.json"

# File log untuk mencatat semua aktivitas
LOG_FILE = "security.log"

# --- Fungsi Inti ---

def setup_logging():
    """Mengatur logger untuk menulis ke file dengan format yang diminta."""
    
    # 1. Tambahkan level "ALERT"
    # Kita petakan level ALERT ke level CRITICAL di logging
    logging.addLevelName(logging.CRITICAL, 'ALERT')

    # 2. Dapatkan logger utama
    logger = logging.getLogger('FIM')
    logger.setLevel(logging.INFO) # Tangkap semua level dari INFO ke atas

    # 3. Buat formatter
    # Format: [2025-10-30 13:25:11] LEVEL: Pesan
    log_format = logging.Formatter(
        fmt='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 4. Buat file handler
    if not logger.handlers: # Hindari duplikasi handler jika skrip diimpor
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(log_format)
        
        # 5. Tambahkan handler ke logger
        logger.addHandler(file_handler)

    return logger

def calculate_hash(filepath):
    """Menghitung hash SHA-256 dari sebuah file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Baca file dalam chunk untuk file besar
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
    except IOError as e:
        # Tangani jika file tidak bisa diakses
        logger.error(f"Could not read file {filepath} for hashing: {e}")
        return None

def load_baseline():
    """Memuat database baseline hash dari file JSON."""
    if not os.path.exists(HASH_DB_FILE):
        return {} # Kembalikan dict kosong jika file belum ada
    try:
        with open(HASH_DB_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        logger.error(f"Error decoding baseline file {HASH_DB_FILE}.")
        return {} # Kembalikan dict kosong jika file korup

def save_baseline(baseline_db):
    """Menyimpan database baseline hash ke file JSON."""
    try:
        with open(HASH_DB_FILE, 'w') as f:
            json.dump(baseline_db, f, indent=4)
    except IOError as e:
        logger.error(f"Could not write to baseline file {HASH_DB_FILE}: {e}")

# --- Fungsi Operasional ---

def create_baseline(logger):
    """Membuat dan menyimpan hash awal dari semua file di folder monitor."""
    print(f"Creating baseline for directory: {MONITOR_DIR}...")
    baseline_db = {}
    
    try:
        for filename in os.listdir(MONITOR_DIR):
            filepath = os.path.join(MONITOR_DIR, filename)
            
            if os.path.isfile(filepath):
                file_hash = calculate_hash(filepath)
                if file_hash:
                    baseline_db[filename] = file_hash
                    logger.info(f"Baselined file: \"{filename}\"")
                    print(f"  > Baselined: {filename}")
                    
        save_baseline(baseline_db)
        print(f"\nBaseline created successfully. {len(baseline_db)} files indexed.")
        logger.info(f"Baseline successfully created/updated in {HASH_DB_FILE}.")
        
    except FileNotFoundError:
        print(f"\nERROR: Directory not found: {MONITOR_DIR}")
        print("Please create the directory and add files to monitor.")
        logger.error(f"Directory not found during baseline creation: {MONITOR_DIR}")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        logger.error(f"An error occurred during baseline creation: {e}")


def check_integrity(logger):
    """Memeriksa integritas file di folder monitor terhadap baseline."""
    print("Running integrity check...")
    baseline_db = load_baseline()
    
    if not baseline_db:
        print("No baseline found. Run 'init' first.")
        logger.warning("Integrity check ran but no baseline exists.")
        return

    # Dapatkan file yang ada di baseline dan yang ada di disk saat ini
    baseline_files = set(baseline_db.keys())
    
    try:
        current_files_list = os.listdir(MONITOR_DIR)
        current_files = set(f for f in current_files_list if os.path.isfile(os.path.join(MONITOR_DIR, f)))
    except FileNotFoundError:
        print(f"ERROR: Monitored directory not found: {MONITOR_DIR}")
        logger.error(f"Monitored directory not found during check: {MONITOR_DIR}")
        return

    # Bandingkan set file
    new_files = current_files - baseline_files
    deleted_files = baseline_files - current_files
    common_files = current_files.intersection(baseline_files)

    # 1. Periksa file yang baru ditambahkan (Mencurigakan)
    for filename in new_files:
        # Gunakan level CRITICAL, yang akan dipetakan ke "ALERT"
        logger.critical(f'Unknown file "{filename}" detected.')
        print(f"ALERT: Unknown file found: {filename}")

    # 2. Periksa file yang dihapus
    for filename in deleted_files:
        logger.warning(f'File "{filename}" was deleted.')
        print(f"WARNING: Monitored file deleted: {filename}")

    # 3. Periksa file yang dimodifikasi
    for filename in common_files:
        filepath = os.path.join(MONITOR_DIR, filename)
        current_hash = calculate_hash(filepath)
        
        if not current_hash:
            continue # Skip file jika tidak bisa dibaca

        if baseline_db[filename] == current_hash:
            logger.info(f'File "{filename}" verified OK.')
        else:
            logger.warning(f'File "{filename}" integrity failed!')
            print(f"WARNING: INTEGRITY FAILED for file: {filename}")
            
            # Simulasi kirim alert ke konsol
            print(f"  > ALERT: Hash mismatch for {filename}")
            print(f"  > Expected: {baseline_db[filename]}")
            print(f"  > Got:      {current_hash}")

    print("Integrity check finished.")


def show_monitoring_summary():
    """Membaca file log dan menampilkan ringkasan status."""
    print("--- Security Log Summary ---")
    
    safe_count = 0
    corrupted_count = 0
    last_anomaly_time = "None"
    
    # Pola regex untuk menangkap timestamp dari log WARNING atau ALERT
    anomaly_pattern = re.compile(r"\[(.*?)\].*(WARNING|ALERT):.*")

    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                if 'verified OK' in line:
                    safe_count += 1
                elif 'integrity failed!' in line:
                    corrupted_count += 1
                
                # Cek anomali (WARNING atau ALERT)
                match = anomaly_pattern.search(line)
                if match:
                    last_anomaly_time = match.group(1) # Ambil timestamp

        print(f"File Aman (Verified OK):     {safe_count}")
        print(f"File Rusak (Integrity Failed): {corrupted_count}")
        print(f"Waktu Terakhir Ada Anomali:  {last_anomaly_time}")

    except FileNotFoundError:
        print("Log file 'security.log' not found.")
        print("Run 'init' and 'check' first.")
    except Exception as e:
        print(f"Error reading log file: {e}")
        
    print("----------------------------")


def main():
    """Fungsi utama untuk menjalankan skrip dari command line."""
    
    # Buat folder monitor jika belum ada
    os.makedirs(MONITOR_DIR, exist_ok=True)
    
    # Setup logger
    logger = setup_logging()

    if len(sys.argv) != 2:
        print("Sistem Deteksi Integritas File Sederhana")
        print("Usage: python fim.py [command]")
        print("\nCommands:")
        print("  init      - Membuat baseline hash baru dari folder monitor.")
        print("  check     - Memeriksa file saat ini terhadap baseline.")
        print("  summary   - Menampilkan ringkasan dari file log.")
        sys.exit(1)

    command = sys.argv[1]

    if command == "init":
        create_baseline(logger)
    elif command == "check":
        check_integrity(logger)
    elif command == "summary":
        show_monitoring_summary()
    else:
        print(f"Error: Unknown command '{command}'")
        sys.exit(1)

if __name__ == "__main__":
    main()