import os
import shutil
import time
from getpass import getuser
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

print("\n[ Tripwire ]\n[ https://github.com/blwhit/Tripwire ]\n")

# Get current Windows username
username = getuser()

default_monitored_dir = fr"C:\Users\{username}\AppData\Local\Temp"
default_snapshot_dir = fr"C:\Users\{username}\Tripwire"

# --- Inputs ---
monitored_dirs_input = input(f"Enter the directories to monitor (comma-separated) [{default_monitored_dir}]: ").strip() or default_monitored_dir
monitored_dirs = [os.path.abspath(dir.strip()) for dir in monitored_dirs_input.split(",")]

snapshot_dir = input(f"Enter the snapshot backup directory [{default_snapshot_dir}]: ").strip() or default_snapshot_dir
snapshot_dir = os.path.abspath(snapshot_dir)
os.makedirs(snapshot_dir, exist_ok=True)

for monitored_dir in monitored_dirs:
    if os.path.commonpath([monitored_dir]) == os.path.commonpath([monitored_dir, snapshot_dir]):
        print(f"[!] Error: Snapshot directory cannot be inside the monitored directory: {monitored_dir}")
        exit(1)

# Retry attempts
retry_attempts_input = input("Enter the number of retry attempts for failed snapshot backups [3]: ").strip()
retry_attempts = int(retry_attempts_input) if retry_attempts_input.isdigit() else 3
retry_attempts = max(0, retry_attempts)  # Prevent negatives

# File types to monitor
file_types_input = input("Enter the file types/extensions to monitor (comma-separated, e.g., .txt,.exe) [all types]: ").strip()
file_types = None if not file_types_input or file_types_input.lower() == "all types" else [
    ext.strip().lower() for ext in file_types_input.split(",")
]

# File types to exclude
exclude_types_input = input("Enter file types/extensions to exclude from monitoring (comma-separated) [none]: ").strip()
exclude_types = [] if not exclude_types_input or exclude_types_input.lower() == "none" else [
    ext.strip().lower() for ext in exclude_types_input.split(",")
]

# --- Event Handler ---
class MalwareFileHandler(FileSystemEventHandler):

    def on_created(self, event):
        if not event.is_directory:
            self.backup_file(event.src_path, "FileCreated")

    def on_modified(self, event):
        if not event.is_directory:
            self.backup_file(event.src_path, "FileModified")

    def backup_file(self, filepath, event_type):
        _, ext = os.path.splitext(filepath)
        ext = ext.lower()

        if (file_types and ext not in file_types) or (ext in exclude_types):
            return  # Skip this file

        filename = os.path.basename(filepath)
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        safe_filename = f"{timestamp}_{event_type}_{filename}"

        if len(safe_filename) > 100:
            name, ext_part = os.path.splitext(filename)
            safe_filename = f"{timestamp}_{event_type}_{name[:40]}...{ext_part}"

        dest_path = os.path.join(snapshot_dir, safe_filename)
        delay = 0.75
        attempt = 0

        while attempt <= retry_attempts:
            try:
                if snapshot_dir in os.path.abspath(filepath):
                    print(f"[X] Skipped (internal snapshot): {filepath}")
                    return

                shutil.copy2(filepath, dest_path)
                print(f"[+] {event_type.upper()}: {filename} → Snapshot saved → {safe_filename}")
                return  # Success, exit
            except PermissionError:
                print(f"[!] {event_type.upper()}: {filename} → Permission Denied → {filepath}")
            except Exception as e:
                print(f"[!] {event_type.upper()}: Failed to backup {filename}: {e}")

            attempt += 1
            if attempt <= retry_attempts:
                time.sleep(delay)

        print(f"[!] {event_type.upper()}: {filename} → Snapshot failed after {retry_attempts} attempt(s).")

# --- Main Program ---
if __name__ == "__main__":
    print("\n[i] Monitoring the following directories:")
    for d in monitored_dirs:
        print(f"    - {d}")
    print(f"[i] Snapshots will be saved to: {snapshot_dir}")
    print(f"[i] Monitoring file types: {', '.join(file_types) if file_types else 'All'}")
    print(f"[i] Excluding file types: {', '.join(exclude_types) if exclude_types else 'None'}")

    event_handler = MalwareFileHandler()
    observer = Observer()

    for monitored_dir in monitored_dirs:
        observer.schedule(event_handler, monitored_dir, recursive=True)

    observer.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[i] Stopped monitoring.")

    observer.join()
