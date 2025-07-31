from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
from logger import Logger  # Assuming logger.py has a Logger class

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, logger):
        """Initialize with a logger instance."""
        self.logger = logger
        self.last_events = {}  # Track last event time per file

    def on_created(self, event):
        """Log when a file is created in the uploads directory."""
        if not event.is_directory:
            file_path = event.src_path
            if file_path not in self.last_events or time.time() - self.last_events[file_path] > 1:
                self.logger.log(f"File created: {file_path} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                self.last_events[file_path] = time.time()

    def on_modified(self, event):
        """Log when a file is modified (e.g., encrypted/decrypted)."""
        if not event.is_directory:
            file_path = event.src_path
            if file_path not in self.last_events or time.time() - self.last_events[file_path] > 1:
                self.logger.log(f"File modified: {file_path} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                self.last_events[file_path] = time.time()

    def on_deleted(self, event):
        """Log when a file is deleted."""
        if not event.is_directory:
            file_path = event.src_path
            if file_path not in self.last_events or time.time() - self.last_events[file_path] > 1:
                self.logger.log(f"File deleted: {file_path} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                self.last_events[file_path] = time.time()

def start_monitoring(upload_dir, logger, callback=None):
    """Start monitoring the specified directory with an optional callback."""
    event_handler = FileEventHandler(logger)
    observer = Observer()
    observer.schedule(event_handler, upload_dir, recursive=False)
    observer.start()
    print(f"Monitoring {upload_dir} started...")
    try:
        while True:
            time.sleep(1)
            if callback:
                callback()  # Call the refresh function if provided
    except KeyboardInterrupt:
        observer.stop()
        print("Monitoring stopped.")
    observer.join()

if __name__ == "__main__":
    # Placeholder for logger setup (replace with actual Logger instance)
    logger = Logger()  # Adjust based on logger.py implementation
    upload_dir = "/home/kali/SecureFileTransfer/uploads/"
    start_monitoring(upload_dir, logger)