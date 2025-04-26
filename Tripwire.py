import os
import shutil
import time
from getpass import getuser
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

print("\n[ Tripwire ]\n[ https://github.com/blwhit/Tripwire ]\n")

# Get current Windows username
username = getuser()

default_monitored_dir = fr"C:\Users\{username}\AppData\Local\Temp"  # Default path for monitoring files
default_snapshot_dir = fr"C:\Users\{username}\Tripwire"  # Default path for storing snapshot backups

# Prompt user to input multiple directories to monitor, separated by commas
monitored_dirs_input = input(f"Enter the directories to monitor (comma-separated) [{default_monitored_dir}]: ").strip() or default_monitored_dir

# Split the input into a list of directories, stripping whitespace
monitored_dirs = [dir.strip() for dir in monitored_dirs_input.split(",")]

# Ensure all directories are absolute paths
monitored_dirs = [os.path.abspath(dir) for dir in monitored_dirs]

# Ensure the snapshot directory exists, if not, create it
snapshot_dir = input(f"Enter the snapshot backup directory [{default_snapshot_dir}]: ").strip() or default_snapshot_dir
snapshot_dir = os.path.abspath(snapshot_dir)
os.makedirs(snapshot_dir, exist_ok=True)

# Ensure the snapshot directory is not inside any of the monitored directories
for monitored_dir in monitored_dirs:
    if os.path.commonpath([monitored_dir]) == os.path.commonpath([monitored_dir, snapshot_dir]):
        print(f"[!] Error: Snapshot directory cannot be inside the monitored directory: {monitored_dir}")
        exit(1)

# Prompt user to set the number of retry attempts (default 3)
retry_attempts = input(f"Enter the number of retry attempts for failed snapshot backups [3]: ").strip()
retry_attempts = int(retry_attempts) if retry_attempts else 3  # Default to 3 if empty input

# Prompt user to specify file extensions to monitor (default is all files)
file_types_input = input(f"Enter the file types/extensions to monitor (comma-separated, e.g., .txt,.exe) [all types]: ").strip()
if file_types_input.lower() == "all types" or not file_types_input:
    file_types = None  # None means all types will be monitored
else:
    file_types = [ext.strip().lower() for ext in file_types_input.split(",")]  # List of file extensions

# Define a class to handle file system events like file creation or modification
class MalwareFileHandler(FileSystemEventHandler):

    def on_created(self, event):
        """ Called when a file is created in the monitored directory """
        if not event.is_directory:  # Ensure it's not a directory but a file
            self.backup_file(event.src_path, "FileCreated")  # Backup the created file

    def on_modified(self, event):
        """ Called when a file is modified in the monitored directory """
        if not event.is_directory:  # Ensure it's not a directory but a file
            self.backup_file(event.src_path, "FileModified")  # Backup the modified file

    def backup_file(self, filepath, event_type):
        """ Backup the file to the snapshot directory """
        retries = retry_attempts  # Use the number of retry attempts set by the user
        delay = .75  # Wait between retries
        attempt = 0
        
        # Get the file extension and check if it matches the allowed types
        _, ext = os.path.splitext(filepath)
        ext = ext.lower()

        if file_types and ext not in file_types:
            return  # Skip files that don't match the specified extensions

        while attempt < retries:
            try:
                # Skip backing up files that are already in the snapshot directory to avoid duplication
                if snapshot_dir in os.path.abspath(filepath):
                    print(f"[X] Path error in backup function at: {filepath}")  # Print an error if the file is in snapshot dir
                    return

                filename = os.path.basename(filepath)  # Get the file's name (no path)
                timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
                safe_filename = f"{timestamp}_{event_type}_{filename}"

                # If the filename is too long, truncate it to fit the 100-character limit
                if len(safe_filename) > 100:
                    name, ext = os.path.splitext(filename)  # Split the name and extension
                    safe_filename = f"{timestamp}_{event_type}_{name[:40]}...{ext}"  # Truncate the name if it's too long

                # Construct the full path where the backup will be saved
                dest_path = os.path.join(snapshot_dir, safe_filename)

                # Copy the file to the snapshot directory (preserving metadata)
                shutil.copy2(filepath, dest_path)
                print(f"[+] {event_type.upper()}: {filename} → Snapshot saved → {safe_filename}")
                break  # If successful, break out of the loop

            except PermissionError as e:
                print(f"[!] {event_type.upper()}: {filename} → Snapshot Failed, Permission Denied → {filepath}")
                attempt += 1
                time.sleep(delay)
            except Exception as e:
                # If an error occurs other than permission, retry after delay
                print(f"[!] Failed to backup {filepath}: {e}. Retrying in {delay} seconds.")
                attempt += 1
                time.sleep(delay)

            if attempt == retries:
                print(f"[!] Failed to backup {filepath} after {retries} attempts.")

if __name__ == "__main__":
    
    print("\n")
    print(f"[i] Monitoring the following directories: {', '.join(monitored_dirs)}")
    print(f"[i] Snapshots will be saved to: {snapshot_dir}")
    if file_types:
        print(f"[i] Monitoring the following file types: {', '.join(file_types)}")
    else:
        print("[i] Monitoring all file types.")

    # Create an instance of the MalwareFileHandler class to handle events
    event_handler = MalwareFileHandler()
    # Create an observer object to watch for file system changes
    observer = Observer()

    # Schedule the observer to watch each monitored directory
    for monitored_dir in monitored_dirs:
        observer.schedule(event_handler, monitored_dir, recursive=True)

    # Start the observer in a separate thread to listen for events continuously
    observer.start()

    try:
        # Keep the program running indefinitely
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[i] Stopped monitoring.")

    # Wait for the observer thread to properly finish before exiting the program
    observer.join()
