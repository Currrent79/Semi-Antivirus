import os
import sqlite3
import logging
from datetime import datetime
import threading

class Logger:
    def __init__(self, log_file="logs/file_transfer.log", db_file="db/access_control.db"):
        """Initialize logger with file and database."""
        self.log_file = log_file
        self.db_file = db_file
        
        # Set up file logging
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Create table if it doesn't exist (done once in main thread)
        with sqlite3.connect(self.db_file) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS file_logs 
                            (id INTEGER PRIMARY KEY, timestamp TEXT, message TEXT)''')

    def log(self, message):
        """Log message to file and database in a thread-safe way."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        full_message = f"{timestamp} - {message}"
        self.logger.info(message)
        
        # Create a new connection for each log to avoid thread issues
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("INSERT INTO file_logs (timestamp, message) VALUES (?, ?)", 
                        (timestamp, message))
            conn.commit()

if __name__ == "__main__":
    logger = Logger()
    logger.log("Test log entry")