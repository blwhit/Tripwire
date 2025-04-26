import os
import shutil
import time
from getpass import getuser
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

print(Fore.CYAN + Style.BRIGHT + "\n[ Tripwire ]")
print(Fore.CYAN + "[ https://github.com/blwhit/Tripwire ]\n")

# Get current Windows username
username = getuser()

default_monitored_dir = fr"C:\Users\{username}\AppData\Local\Temp"
default_snapshot_dir = fr"C:\Users\{username}\Tripwire"

# Graceful input handling
try:
    # --- Inputs ---
    monitored_dirs_input = input(Fore.YELLOW + f"[?] Enter the directories to monitor (comma-separated) [{default_monitored_dir}]: ").strip() or default_monitored_dir
    monitored_dirs = [os.path.abspath(dir.strip()) for dir in monitored_dirs_input.split(",")]

    snapshot_dir = input(Fore.YELLOW + f"[?] Enter the snapshot backup directory [{default_snapshot_dir}]: ").strip() or default_snapshot_dir
    snapshot_dir = os.path.abspath(snapshot_dir)
    os.makedirs(snapshot_dir, exist_ok=True)

    for monitored_dir in monitored_dirs:
        if os.path.commonpath([monitored_dir]) == os.path.commonpath([monitored_dir, snapshot_dir]):
            print(Fore.RED + f"[!] Error: Snapshot directory cannot be inside the monitored directory: {monitored_dir}")
            exit(1)

    # Retry attempts
    retry_attempts_input = input(Fore.YELLOW + "[?] Enter the number of retry attempts for failed snapshot backups [3]: ").strip()
    retry_attempts = int(retry_attempts_input) if retry_attempts_input.isdigit() else 3
    retry_attempts = max(0, retry_attempts)

    # File types to monitor
    file_types_input = input(Fore.YELLOW + "[?] Enter the file types/extensions to monitor (comma-separated, e.g., .txt,.exe) [all types]: ").strip()
    file_types = None if not file_types_input or file_types_input.lower() == "all types" else [
        ext.strip().lower() for ext in file_types_input.split(",")
    ]

    # File types to exclude
    exclude_types_input = input(Fore.YELLOW + "[?] Enter file types/extensions to exclude from monitoring (comma-separated) [none]: ").strip()
    exclude_types = [] if not exclude_types_input or exclude_types_input.lower() == "none" else [
        ext.strip().lower() for ext in exclude_types_input.split(",")
    ]

except KeyboardInterrupt:
    print(Fore.RED + "\n\n[!] Exiting...\n")
    exit(0)

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
            return

        filename = os.path.basename(filepath)
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        safe_filename = f"{timestamp}_{event_type}_{filename}"

        if len(safe_filename) > 100:
            name, ext_part = os.path.splitext(filename)
            safe_filename = f"{timestamp}_{event_type}_{name[:40]}...{ext_part}"

        dest_path = os.path.join(snapshot_dir, safe_filename)
        delay = 0.1
        attempt = 0

        while attempt <= retry_attempts:
            try:
                if snapshot_dir in os.path.abspath(filepath):
                    print(Fore.MAGENTA + f"[X] Skipped (internal snapshot): {filepath}")
                    return
                
                if not os.path.exists(filepath):
                    print(f"[!] {event_type.upper()}: {filename} vanished before backup attempt.")
                    return

                shutil.copy2(filepath, dest_path)
                print(Fore.GREEN + f"[+] {event_type.upper()}: {filename}")
                print(Fore.WHITE + f"    ├── Original Path: {filepath}")
                print(Fore.WHITE + f"    └── Snapshot Saved As: {safe_filename}")
                return
            except PermissionError:
                print(Fore.RED + f"[!] {event_type.upper()}: {filename} → Permission Denied")
                print(Fore.YELLOW + f"    └── Original Path: {filepath}")
            except Exception as e:
                print(Fore.RED + f"[!] {event_type.upper()}: Failed to backup {filename}: {e}")
                print(Fore.YELLOW + f"    └── Original Path: {filepath}")

            attempt += 1
            if attempt <= retry_attempts:
                time.sleep(delay)

        print(Fore.RED + f"[!] {event_type.upper()}: {filename} → Snapshot failed after {retry_attempts} attempt(s).")
        print(Fore.YELLOW + f"    └── Original Path: {filepath}")

# --- Main Program ---
if __name__ == "__main__":

    print(Fore.WHITE + "\n[i] Monitoring the following directories:")
    for d in monitored_dirs:
        print(Fore.WHITE + f"    - {d}")
    print(Fore.WHITE + f"[i] Snapshots will be saved to: {snapshot_dir}")
    print(Fore.WHITE + f"[i] Monitoring file types: {', '.join(file_types) if file_types else 'All'}")
    print(Fore.WHITE + f"[i] Excluding file types: {', '.join(exclude_types) if exclude_types else 'None'}")

    print(Fore.GREEN + Style.BRIGHT + "\n[*] Tripwire Active\n")

    event_handler = MalwareFileHandler()
    observer = Observer()

    for monitored_dir in monitored_dirs:
        observer.schedule(event_handler, monitored_dir, recursive=True)

    observer.start()

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Detected Ctrl + C. Stopping observer...")
        try:
            observer.stop()
        except Exception as e:
            print(Fore.RED + f"[!] Error stopping observer: {e}")
    finally:
        observer.join()
        print(Fore.RED + "[i] Exiting...\n")
