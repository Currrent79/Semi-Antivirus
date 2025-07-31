# from gui import SecureBankingApp
# import tkinter as tk
# from monitor import start_monitoring
# import threading
# from logger import Logger  # Assuming logger.py has the Logger class

# def run_app():
#     root = tk.Tk()
#     app = SecureBankingApp(root)
#     logger = Logger()  # Initialize the logger
#     monitor_thread = threading.Thread(target=start_monitoring, args=("/home/kali/SecureFileTransfer/uploads/", logger), daemon=True)
#     monitor_thread.start()  # Start monitoring in the background
#     root.mainloop()

# if __name__ == "__main__":
#     run_app()
from gui import SecureBankingApp
import tkinter as tk
from monitor import start_monitoring
import threading
from logger import Logger # Assuming logger.py has the Logger class

def run_app():
    root = tk.Tk()
    app = SecureBankingApp(root)
    logger = Logger() # Initialize the logger
    monitor_thread = threading.Thread(target=start_monitoring, args=("/home/kali/SecureFileTransfer/uploads/", logger), daemon=True)
    monitor_thread.start() # Start monitoring in the background
    root.mainloop()

if __name__ == "__main__":
    run_app()