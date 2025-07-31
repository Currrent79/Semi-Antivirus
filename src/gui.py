import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
import os
import shutil
import time
from auth import AuthManager
from scanner import FileScanner
from encryptor import encrypt_file, decrypt_file
from monitor import start_monitoring
from logger import Logger
import threading
import ttkbootstrap as ttk
import pystray
from pystray import MenuItem as item
from PIL import Image

class SecureBankingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Kathmandu Valley Bank - Secure File Transfer Portal")
        self.root.configure(bg="#f8fafc")
        self.root.geometry("1400x1000")
        self.root.minsize(1200, 800)
        
        # Set window icon and state
        self.root.state('zoomed') if os.name == 'nt' else None
        
        # Modern color scheme
        self.colors = {
            'primary': '#1e40af',      # Blue
            'primary_dark': '#1e3a8a',
            'secondary': '#059669',     # Green
            'accent': '#dc2626',       # Red
            'warning': '#d97706',      # Orange
            'bg_light': '#f8fafc',
            'bg_card': '#ffffff',
            'bg_sidebar': '#f1f5f9',
            'text_primary': '#1f2937',
            'text_secondary': '#6b7280',
            'border': '#e5e7eb',
            'success': '#10b981',
            'error': '#ef4444'
        }

        # Configure styles
        self.setup_styles()
        
        # Create main layout
        self.create_layout()
        
        # Initialize backend components (keeping your original logic)
        self.auth = AuthManager()
        self.uploaded_file = None
        self.current_role = None
        self.scanner = FileScanner("/home/kali/SecureFileTransfer/rules/malware_rules.yar")
        self.scan_thread = None
        self.scan_results = []
        self.malicious_files = []
        
        # File management
        self.upload_dir = "/home/kali/SecureFileTransfer/uploads/"
        if not os.path.exists(self.upload_dir):
            os.makedirs(self.upload_dir)
        self.uploaded_files = {"user": [], "admin": []}
        self.all_uploaded_files = []

        self.logger = Logger()
        self.monitor_thread = threading.Thread(target=start_monitoring, args=(self.upload_dir, self.logger, self._trigger_refresh), daemon=True)
        self.monitor_thread.start()

        self.setup_tray()

    def setup_styles(self):
        """Configure modern TTK styles"""
        self.style = ttk.Style()
        
        # Configure button styles
        self.style.configure("Primary.TButton", 
                           font=("Segoe UI", 10, "bold"),
                           padding=(20, 12))
        
        self.style.configure("Secondary.TButton", 
                           font=("Segoe UI", 9),
                           padding=(15, 8))
        
        self.style.configure("Success.TButton", 
                           font=("Segoe UI", 9),
                           padding=(15, 8))
        
        self.style.configure("Danger.TButton", 
                           font=("Segoe UI", 9),
                           padding=(15, 8))
        
        # Configure label styles
        self.style.configure("Title.TLabel", 
                           font=("Segoe UI", 24, "bold"),
                           foreground=self.colors['text_primary'])
        
        self.style.configure("Subtitle.TLabel", 
                           font=("Segoe UI", 14),
                           foreground=self.colors['text_secondary'])
        
        self.style.configure("Heading.TLabel", 
                           font=("Segoe UI", 16, "bold"),
                           foreground=self.colors['text_primary'])
        
        self.style.configure("Body.TLabel", 
                           font=("Segoe UI", 10),
                           foreground=self.colors['text_primary'])
        
        # Configure frame styles
        self.style.configure("Card.TFrame", 
                           background=self.colors['bg_card'],
                           relief="flat",
                           borderwidth=1)

    def create_layout(self):
        """Create the main application layout"""
        # Header
        self.create_header()
        
        # Main content area
        main_container = ttk.Frame(self.root, padding="0")
        main_container.pack(fill="both", expand=True)
        
        # Sidebar
        self.create_sidebar(main_container)
        
        # Content area
        self.create_content_area(main_container)
        
        # Footer/Status bar
        self.create_footer()

    def create_header(self):
        """Create modern header with bank branding"""
        header_frame = tk.Frame(self.root, bg=self.colors['primary'], height=80)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        # Bank logo and title
        logo_frame = tk.Frame(header_frame, bg=self.colors['primary'])
        logo_frame.pack(side="left", fill="y", padx=30, pady=15)
        
        # Bank logo (using text for now, you can replace with actual logo)
        logo_label = tk.Label(logo_frame, text="KVB", 
                             font=("Segoe UI", 20, "bold"),
                             bg=self.colors['primary'], 
                             fg="white",
                             width=4, height=2,
                             relief="solid", bd=2)
        logo_label.pack(side="left")
        
        title_frame = tk.Frame(header_frame, bg=self.colors['primary'])
        title_frame.pack(side="left", fill="y", pady=15, padx=20)
        
        title_label = tk.Label(title_frame, 
                              text="Kathmandu Valley Bank",
                              font=("Segoe UI", 18, "bold"),
                              bg=self.colors['primary'], 
                              fg="white")
        title_label.pack(anchor="w")
        
        subtitle_label = tk.Label(title_frame, 
                                 text="Secure File Transfer Portal",
                                 font=("Segoe UI", 12),
                                 bg=self.colors['primary'], 
                                 fg="#e2e8f0")
        subtitle_label.pack(anchor="w")
        
        # User info area (will be populated after login)
        self.user_info_frame = tk.Frame(header_frame, bg=self.colors['primary'])
        self.user_info_frame.pack(side="right", fill="y", padx=30, pady=15)

    def create_sidebar(self, parent):
        """Create sidebar navigation"""
        self.sidebar = tk.Frame(parent, bg=self.colors['bg_sidebar'], width=300)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        
        # Sidebar title
        sidebar_title = tk.Label(self.sidebar, 
                                text="Navigation",
                                font=("Segoe UI", 14, "bold"),
                                bg=self.colors['bg_sidebar'],
                                fg=self.colors['text_primary'],
                                pady=20)
        sidebar_title.pack(fill="x", padx=20)
        
        # Navigation buttons (will be enabled after login)
        self.nav_buttons = {}
        nav_items = [
            ("🏠 Dashboard", "dashboard"),
            ("📁 File Operations", "files"),
            ("🔒 Security", "security"),
            ("📊 Activity Log", "logs"),
            ("⚙️ Settings", "settings")
        ]
        
        for text, key in nav_items:
            btn = tk.Button(self.sidebar, 
                           text=text,
                           font=("Segoe UI", 11),
                           bg=self.colors['bg_sidebar'],
                           fg=self.colors['text_primary'],
                           bd=0,
                           pady=12,
                           padx=20,
                           anchor="w",
                           cursor="hand2",
                           state="disabled")
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[key] = btn

    def create_content_area(self, parent):
        """Create main content area"""
        self.content_frame = tk.Frame(parent, bg=self.colors['bg_light'])
        self.content_frame.pack(side="right", fill="both", expand=True)
        
        # Create login view
        self.create_login_view()
        
        # Create main app view (hidden initially)
        self.create_main_view()

    def create_login_view(self):
        """Create modern login interface"""
        self.login_container = tk.Frame(self.content_frame, bg=self.colors['bg_light'])
        self.login_container.pack(fill="both", expand=True)
        
        # Center the login card
        login_wrapper = tk.Frame(self.login_container, bg=self.colors['bg_light'])
        login_wrapper.place(relx=0.5, rely=0.5, anchor="center")
        
        # Login card
        login_card = tk.Frame(login_wrapper, 
                             bg=self.colors['bg_card'],
                             relief="solid",
                             bd=1,
                             padx=50,
                             pady=40)
        login_card.pack()
        
        # Login title
        login_title = tk.Label(login_card,
                              text="Secure Access Portal",
                              font=("Segoe UI", 20, "bold"),
                              bg=self.colors['bg_card'],
                              fg=self.colors['text_primary'])
        login_title.pack(pady=(0, 10))
        
        login_subtitle = tk.Label(login_card,
                                 text="Please authenticate to continue",
                                 font=("Segoe UI", 11),
                                 bg=self.colors['bg_card'],
                                 fg=self.colors['text_secondary'])
        login_subtitle.pack(pady=(0, 30))
        
        # Username field
        username_label = tk.Label(login_card,
                                 text="Username",
                                 font=("Segoe UI", 10, "bold"),
                                 bg=self.colors['bg_card'],
                                 fg=self.colors['text_primary'])
        username_label.pack(anchor="w", pady=(0, 5))
        
        self.username_entry = tk.Entry(login_card,
                                      font=("Segoe UI", 11),
                                      relief="solid",
                                      bd=1,
                                      width=30,
                                      bg="white")
        self.username_entry.pack(pady=(0, 15), ipady=8)
        
        # Password field
        password_label = tk.Label(login_card,
                                 text="Password",
                                 font=("Segoe UI", 10, "bold"),
                                 bg=self.colors['bg_card'],
                                 fg=self.colors['text_primary'])
        password_label.pack(anchor="w", pady=(0, 5))
        
        self.password_entry = tk.Entry(login_card,
                                      font=("Segoe UI", 11),
                                      relief="solid",
                                      bd=1,
                                      width=30,
                                      show="*",
                                      bg="white")
        self.password_entry.pack(pady=(0, 25), ipady=8)
        
        # Login button
        login_btn = tk.Button(login_card,
                             text="Sign In",
                             font=("Segoe UI", 11, "bold"),
                             bg=self.colors['primary'],
                             fg="white",
                             relief="flat",
                             cursor="hand2",
                             command=self.dummy_login,
                             width=25,
                             pady=10)
        login_btn.pack()
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda e: self.dummy_login())

    def create_main_view(self):
        """Create main application view"""
        self.main_container = tk.Frame(self.content_frame, bg=self.colors['bg_light'])
        # Don't pack initially - will be shown after login
        
        # Main content with padding
        content_wrapper = tk.Frame(self.main_container, bg=self.colors['bg_light'])
        content_wrapper.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Dashboard cards row
        self.create_dashboard_cards(content_wrapper)
        
        # File operations section
        self.create_file_operations(content_wrapper)
        
        # Activity log section
        self.create_activity_log(content_wrapper)

    def create_dashboard_cards(self, parent):
        """Create dashboard overview cards"""
        cards_frame = tk.Frame(parent, bg=self.colors['bg_light'])
        cards_frame.pack(fill="x", pady=(0, 20))
        
        # Files uploaded card
        files_card = self.create_stat_card(cards_frame, "📁", "Files Uploaded", "0", self.colors['primary'])
        files_card.pack(side="left", padx=(0, 15))
        
        # Security scans card
        security_card = self.create_stat_card(cards_frame, "🛡️", "Security Scans", "0", self.colors['secondary'])
        security_card.pack(side="left", padx=(0, 15))
        
        # Transfers card
        transfers_card = self.create_stat_card(cards_frame, "📤", "Transfers", "0", self.colors['warning'])
        transfers_card.pack(side="left", padx=(0, 15))
        
        # System status card
        self.status_card_content = self.create_stat_card(cards_frame, "⚡", "System Status", "Online", self.colors['success'])
        self.status_card_content.pack(side="left")

    def create_stat_card(self, parent, icon, title, value, color):
        """Create a statistics card"""
        card = tk.Frame(parent, 
                       bg=self.colors['bg_card'],
                       relief="solid",
                       bd=1,
                       width=200,
                       height=120)
        card.pack_propagate(False)
        
        # Card content
        content = tk.Frame(card, bg=self.colors['bg_card'])
        content.pack(fill="both", expand=True, padx=20, pady=15)
        
        # Icon and value row
        top_row = tk.Frame(content, bg=self.colors['bg_card'])
        top_row.pack(fill="x")
        
        icon_label = tk.Label(top_row,
                             text=icon,
                             font=("Segoe UI", 20),
                             bg=self.colors['bg_card'],
                             fg=color)
        icon_label.pack(side="left")
        
        value_label = tk.Label(top_row,
                              text=value,
                              font=("Segoe UI", 18, "bold"),
                              bg=self.colors['bg_card'],
                              fg=color)
        value_label.pack(side="right")
        
        # Title
        title_label = tk.Label(content,
                              text=title,
                              font=("Segoe UI", 10),
                              bg=self.colors['bg_card'],
                              fg=self.colors['text_secondary'])
        title_label.pack(anchor="w", pady=(10, 0))
        
        return card

    def create_file_operations(self, parent):
        """Create file operations section"""
        operations_frame = tk.Frame(parent, bg=self.colors['bg_light'])
        operations_frame.pack(fill="both", expand=True, pady=(0, 20))
        
        # Section title
        title_label = tk.Label(operations_frame,
                              text="File Operations",
                              font=("Segoe UI", 16, "bold"),
                              bg=self.colors['bg_light'],
                              fg=self.colors['text_primary'])
        title_label.pack(anchor="w", pady=(0, 15))
        
        # Operations container
        ops_container = tk.Frame(operations_frame, bg=self.colors['bg_light'])
        ops_container.pack(fill="both", expand=True)
        
        # Left panel - File list and controls
        left_panel = tk.Frame(ops_container, 
                             bg=self.colors['bg_card'],
                             relief="solid",
                             bd=1)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        # File list header
        list_header = tk.Frame(left_panel, bg=self.colors['bg_card'])
        list_header.pack(fill="x", padx=20, pady=(20, 10))
        
        list_title = tk.Label(list_header,
                             text="Uploaded Files",
                             font=("Segoe UI", 12, "bold"),
                             bg=self.colors['bg_card'],
                             fg=self.colors['text_primary'])
        list_title.pack(side="left")
        
        upload_btn = tk.Button(list_header,
                              text="+ Upload File",
                              font=("Segoe UI", 9, "bold"),
                              bg=self.colors['primary'],
                              fg="white",
                              relief="flat",
                              cursor="hand2",
                              command=self.upload_file,
                              padx=15,
                              pady=5)
        upload_btn.pack(side="right")
        
        # File list
        list_frame = tk.Frame(left_panel, bg=self.colors['bg_card'])
        list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Scrollable file list
        list_container = tk.Frame(list_frame, bg=self.colors['bg_card'])
        list_container.pack(fill="both", expand=True)
        
        scrollbar = tk.Scrollbar(list_container)
        scrollbar.pack(side="right", fill="y")
        
        self.files_list = tk.Listbox(list_container,
                                    font=("Segoe UI", 10),
                                    bg="white",
                                    fg=self.colors['text_primary'],
                                    selectbackground=self.colors['primary'],
                                    selectforeground="white",
                                    relief="flat",
                                    bd=0,
                                    yscrollcommand=scrollbar.set,
                                    selectmode=tk.SINGLE)
        self.files_list.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.files_list.yview)
        
        # Right panel - Actions and status
        right_panel = tk.Frame(ops_container, 
                              bg=self.colors['bg_card'],
                              relief="solid",
                              bd=1,
                              width=350)
        right_panel.pack(side="right", fill="y")
        right_panel.pack_propagate(False)
        
        # Actions header
        actions_header = tk.Label(right_panel,
                                 text="Actions",
                                 font=("Segoe UI", 12, "bold"),
                                 bg=self.colors['bg_card'],
                                 fg=self.colors['text_primary'])
        actions_header.pack(pady=(20, 15))
        
        # Action buttons
        self.create_action_buttons(right_panel)
        
        # Status section
        self.create_status_section(right_panel)

    def create_action_buttons(self, parent):
        """Create action buttons panel"""
        buttons_frame = tk.Frame(parent, bg=self.colors['bg_card'])
        buttons_frame.pack(fill="x", padx=20)
        
        # Button configurations
        buttons = [
            ("🔍 Scan File", self.scan_file, self.colors['warning']),
            ("🔒 Encrypt File", self.encrypt_file, self.colors['secondary']),
            ("🔓 Decrypt File", self.decrypt_file, self.colors['secondary']),
            ("📤 Transfer File", self.transfer_file, self.colors['primary']),
            ("🗑️ Delete File", self.delete_file, self.colors['error']),
            ("✅ Select All", self.select_all, self.colors['text_secondary'])
        ]
        
        for i, (text, command, color) in enumerate(buttons):
            btn = tk.Button(buttons_frame,
                           text=text,
                           font=("Segoe UI", 9),
                           bg=color,
                           fg="white" if color != self.colors['text_secondary'] else self.colors['text_primary'],
                           relief="flat",
                           cursor="hand2",
                           command=command,
                           width=20,
                           pady=8)
            btn.pack(fill="x", pady=3)

    def create_status_section(self, parent):
        """Create status and progress section"""
        status_frame = tk.Frame(parent, bg=self.colors['bg_card'])
        status_frame.pack(fill="x", padx=20, pady=(20, 0))
        
        # Status title
        status_title = tk.Label(status_frame,
                               text="Status",
                               font=("Segoe UI", 11, "bold"),
                               bg=self.colors['bg_card'],
                               fg=self.colors['text_primary'])
        status_title.pack(anchor="w", pady=(0, 10))
        
        # Progress bar
        self.status_progress = ttk.Progressbar(status_frame, 
                                              mode="determinate", 
                                              maximum=100,
                                              length=300)
        self.status_progress.pack(fill="x", pady=(0, 10))
        
        # Status indicator
        indicator_frame = tk.Frame(status_frame, bg=self.colors['bg_card'])
        indicator_frame.pack(fill="x")
        
        self.status_indicator = tk.Label(indicator_frame,
                                        text="●",
                                        font=("Segoe UI", 12),
                                        bg=self.colors['bg_card'],
                                        fg=self.colors['success'])
        self.status_indicator.pack(side="left")
        
        self.status_text = tk.Label(indicator_frame,
                                   text="System Ready",
                                   font=("Segoe UI", 9),
                                   bg=self.colors['bg_card'],
                                   fg=self.colors['text_secondary'])
        self.status_text.pack(side="left", padx=(10, 0))
        
        # File status
        self.file_label = tk.Label(status_frame,
                                  text="No file selected",
                                  font=("Segoe UI", 9),
                                  bg=self.colors['bg_card'],
                                  fg=self.colors['text_secondary'],
                                  wraplength=300)
        self.file_label.pack(anchor="w", pady=(10, 0))
        
        # Upload status
        self.upload_status = tk.Label(status_frame,
                                     text="",
                                     font=("Segoe UI", 9),
                                     bg=self.colors['bg_card'],
                                     fg=self.colors['text_secondary'],
                                     wraplength=300)
        self.upload_status.pack(anchor="w", pady=(5, 0))

    def create_activity_log(self, parent):
        """Create activity log section"""
        log_frame = tk.Frame(parent, bg=self.colors['bg_light'])
        log_frame.pack(fill="x")
        
        # Log title
        log_title = tk.Label(log_frame,
                            text="Activity Log",
                            font=("Segoe UI", 16, "bold"),
                            bg=self.colors['bg_light'],
                            fg=self.colors['text_primary'])
        log_title.pack(anchor="w", pady=(0, 15))
        
        # Log container
        log_container = tk.Frame(log_frame,
                                bg=self.colors['bg_card'],
                                relief="solid",
                                bd=1)
        log_container.pack(fill="x", ipady=10)
        
        # Log text widget
        log_text_frame = tk.Frame(log_container, bg=self.colors['bg_card'])
        log_text_frame.pack(fill="x", padx=20, pady=10)
        
        log_scrollbar = tk.Scrollbar(log_text_frame)
        log_scrollbar.pack(side="right", fill="y")
        
        self.log_text = tk.Text(log_text_frame,
                               height=6,
                               font=("Consolas", 9),
                               bg="#f8f9fa",
                               fg=self.colors['text_primary'],
                               relief="flat",
                               bd=0,
                               yscrollcommand=log_scrollbar.set,
                               wrap=tk.WORD)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scrollbar.config(command=self.log_text.yview)

    def create_footer(self):
        """Create footer status bar"""
        footer = tk.Frame(self.root, bg=self.colors['border'], height=30)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        
        # Footer content
        footer_content = tk.Frame(footer, bg=self.colors['border'])
        footer_content.pack(fill="both", expand=True, padx=20, pady=5)
        
        # Left side - app info
        app_info = tk.Label(footer_content,
                           text="Kathmandu Valley Bank - Secure File Transfer v1.0",
                           font=("Segoe UI", 8),
                           bg=self.colors['border'],
                           fg=self.colors['text_secondary'])
        app_info.pack(side="left")
        
        # Right side - logout button (hidden initially)
        self.logout_btn = tk.Button(footer_content,
                                   text="🚪 Logout",
                                   font=("Segoe UI", 8),
                                   bg=self.colors['border'],
                                   fg=self.colors['text_secondary'],
                                   relief="flat",
                                   cursor="hand2",
                                   command=self.logout,
                                   bd=0)
        # Don't pack initially

    # Keep all your original methods unchanged
    def update_progress(self, value, duration=0.5):
        self.status_progress["value"] = 0
        start_time = time.time()
        while time.time() - start_time < duration and self.status_progress["value"] < value:
            elapsed = time.time() - start_time
            progress = min(int((elapsed / duration) * value), value)
            self.status_progress["value"] = progress
            self.root.update_idletasks()
            time.sleep(0.01)
        self.status_progress["value"] = value
        self.root.update_idletasks()

    def upload_file(self):
        self.update_progress(0, 0.5)
        try:
            file_path = filedialog.askopenfilename(initialdir="/home/kali/SecureFileTransfer/", title="Upload File", filetypes=[("All files", "*.*")])
            if file_path and os.access(os.path.dirname(file_path), os.R_OK):
                file_name = os.path.basename(file_path)
                dest_path = os.path.join(self.upload_dir, file_name)
                self.update_progress(50, 0.5)
                shutil.copy2(file_path, dest_path)
                self.update_progress(100, 0.5)
                self.upload_status.config(text="Upload completed successfully!")
                self.file_label.config(text=f"Uploaded: {file_name}")
                if self.current_role:
                    tagged_name = f"[Admin] {file_name}" if self.current_role == "admin" else file_name
                    self.uploaded_files[self.current_role].append(tagged_name)
                    if tagged_name not in self.all_uploaded_files:
                        self.all_uploaded_files.append(tagged_name)
                    if self.current_role == "user":
                        self.uploaded_files["admin"].append(tagged_name)
                self.refresh_file_list()
                self.update_log(f"Uploaded: {file_name}")
                self.set_status_indicator("green")
            else:
                raise PermissionError("Cannot access the selected file.")
        except (tk.TclError, PermissionError, shutil.Error) as e:
            self.upload_status.config(text="Upload failed!")
            messagebox.showerror("Upload Error", f"Failed to upload: {str(e)}. Ensure /home/kali/ permissions are set.")
            self.file_label.config(text="No file uploaded")
            self.set_status_indicator("red")
        self.update_progress(0, 0)

    def scan_file(self):
        if not self.current_role or self.current_role != "admin" or not self.auth.has_permission(self.current_role, 'scan'):
            messagebox.showerror("Permission Denied", "Only admin can scan files.")
            self.set_status_indicator("red")
            return
        selected_indices = self.files_list.curselection()
        if not selected_indices and not self.files_list.size():
            messagebox.showwarning("No Selection", "No files selected or available to scan.")
            self.set_status_indicator("red")
            return
        if not selected_indices:
            selected_indices = range(self.files_list.size())
        self.scan_results = []
        self.malicious_files = []
        self.set_status_indicator("yellow")
        self.update_progress(0, 1.0)
        self.scan_thread = threading.Thread(target=self._scan_files, args=(selected_indices,))
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def _scan_files(self, selected_indices):
        total_files = len(selected_indices)
        for i, index in enumerate(selected_indices, 1):
            file_name = self.files_list.get(index)
            full_path = os.path.join(self.upload_dir, file_name.replace("[Admin] ", "")) if file_name.startswith("[Admin] ") else os.path.join(self.upload_dir, file_name)
            print(f"Attempting to scan: {full_path}")
            if os.path.exists(full_path):
                progress = int((i / total_files) * 100)
                self.root.after(0, lambda p=progress: self.update_progress(p, 0.1))
                result = self.scanner.scan_file(full_path)
                print(f"Scan result: {result}")
                detailed_result = f"{file_name}: {result}"
                self.scan_results.append(detailed_result)
                if "File quarantined" in result:
                    file_name = result.split("File quarantined: ")[1].split(" - Detected")[0]
                    if file_name in self.uploaded_files.get("user", []):
                        self.uploaded_files["user"].remove(file_name)
                    if file_name in self.uploaded_files.get("admin", []):
                        self.uploaded_files["admin"].remove(file_name)
                    if file_name in self.all_uploaded_files:
                        self.all_uploaded_files.remove(file_name)
                    self.root.after(0, lambda idx=index: self.files_list.delete(idx))
                    self.show_alert(f"Malware Quarantined: {file_name}")
                    self.show_tray_notification(f"Quarantined: {file_name}")
                    self.set_status_indicator("red")
                elif "Malicious" in result:
                    self.malicious_files.append(detailed_result)
                    self.show_alert(f"Malware Detected: {file_name}")
                    self.show_tray_notification(f"Detected: {file_name}")
                    self.set_status_indicator("red")
            else:
                self.scan_results.append(f"{file_name}: Error: File not found")
        self.root.after(0, self._scan_complete)

    def _scan_complete(self):
        if self.scan_results:
            self.upload_status.config(text="\n".join(self.scan_results))
        if self.malicious_files:
            messagebox.showwarning("Malware Detected", "\n".join(self.malicious_files))
        self.update_progress(100, 0.5)
        self.set_status_indicator("green")
        self.scan_thread = None

    def encrypt_file(self):
        if not self.current_role or not self.auth.has_permission(self.current_role, 'encrypt'):
            messagebox.showerror("Permission Denied", "You do not have permission to encrypt files.")
            self.set_status_indicator("red")
            return
        selected_indices = self.files_list.curselection()
        if not selected_indices and not self.files_list.size():
            messagebox.showwarning("No Selection", "No files selected or available to encrypt.")
            self.set_status_indicator("red")
            return
        if not selected_indices:
            selected_indices = range(self.files_list.size())
        for index in selected_indices:
            self.update_progress(0, 0.5)
            file_name = self.files_list.get(index)
            full_path = self.uploaded_file if self.uploaded_file and "/home/kali/SecureFileTransfer/" in self.uploaded_file else os.path.join(self.upload_dir, file_name.replace("[Admin] ", ""))
            if os.path.exists(full_path):
                password = simpledialog.askstring("Encryption Password", "Enter password for encryption:", show="*")
                if password:
                    self.update_progress(50, 0.5)
                    try:
                        encrypted_path = encrypt_file(full_path, password)
                        new_file_name = os.path.basename(encrypted_path)
                        self.upload_status.config(text=f"Encrypted: {file_name} -> {new_file_name}")
                        if self.current_role:
                            tagged_name = f"[Admin] {new_file_name}" if self.current_role == "admin" else new_file_name
                            self.uploaded_files[self.current_role].append(tagged_name)
                            if tagged_name not in self.all_uploaded_files:
                                self.all_uploaded_files.append(tagged_name)
                            if self.current_role == "user":
                                self.uploaded_files["admin"].append(tagged_name)
                        self.files_list.delete(index)
                        self.files_list.insert(index, new_file_name)
                        if full_path == self.uploaded_file:
                            self.uploaded_file = encrypted_path
                    except Exception as e:
                        self.upload_status.config(text=f"Encryption failed: {str(e)}")
                        messagebox.showerror("Encryption Error", str(e))
                        self.set_status_indicator("red")
                    self.update_progress(100, 0.5)
                else:
                    self.upload_status.config(text="Encryption cancelled: No password provided.")
            else:
                self.upload_status.config(text=f"Error: File {full_path} not found")
                self.set_status_indicator("red")
            self.update_progress(0, 0)

    def decrypt_file(self):
        if not self.current_role or not self.auth.has_permission(self.current_role, 'encrypt'):
            messagebox.showerror("Permission Denied", "You do not have permission to decrypt files.")
            self.set_status_indicator("red")
            return
        selected_indices = self.files_list.curselection()
        if not selected_indices and not self.files_list.size():
            messagebox.showwarning("No Selection", "No files selected or available to decrypt.")
            self.set_status_indicator("red")
            return
        if not selected_indices:
            selected_indices = range(self.files_list.size())
        for index in selected_indices:
            self.update_progress(0, 0.5)
            file_name = self.files_list.get(index)
            if not file_name.endswith(".aes"):
                self.upload_status.config(text=f"Error: {file_name} is not an encrypted file (.aes)")
                self.set_status_indicator("red")
                continue
            full_path = self.uploaded_file if self.uploaded_file and "/home/kali/SecureFileTransfer/" in self.uploaded_file else os.path.join(self.upload_dir, file_name.replace("[Admin] ", ""))
            if os.path.exists(full_path):
                password = simpledialog.askstring("Decryption Password", "Enter password for decryption:", show="*")
                if password:
                    self.update_progress(50, 0.5)
                    try:
                        decrypted_path = decrypt_file(full_path, password)
                        new_file_name = os.path.basename(decrypted_path)
                        self.upload_status.config(text=f"Decrypted: {file_name} -> {new_file_name}")
                        if self.current_role:
                            tagged_name = f"[Admin] {new_file_name}" if self.current_role == "admin" else new_file_name
                            self.uploaded_files[self.current_role].append(tagged_name)
                            if tagged_name not in self.all_uploaded_files:
                                self.all_uploaded_files.append(tagged_name)
                            if self.current_role == "user":
                                self.uploaded_files["admin"].append(tagged_name)
                        self.files_list.delete(index)
                        self.files_list.insert(index, new_file_name)
                        if full_path == self.uploaded_file:
                            self.uploaded_file = decrypted_path
                    except Exception as e:
                        self.upload_status.config(text=f"Decryption failed: {str(e)}")
                        messagebox.showerror("Decryption Error", str(e))
                        self.set_status_indicator("red")
                    self.update_progress(100, 0.5)
                else:
                    self.upload_status.config(text="Decryption cancelled: No password provided.")
            else:
                self.upload_status.config(text=f"Error: File {full_path} not found")
                self.set_status_indicator("red")
            self.update_progress(0, 0)

    def select_all(self):
        self.files_list.selection_clear(0, tk.END)
        for i in range(self.files_list.size()):
            self.files_list.selection_set(i)

    def transfer_file(self):
        if not self.current_role or not self.auth.has_permission(self.current_role, 'transfer'):
            messagebox.showerror("Permission Denied", "You do not have permission to transfer files.")
            self.set_status_indicator("red")
            return
        selected_indices = self.files_list.curselection()
        if not selected_indices and not self.files_list.size():
            messagebox.showwarning("No Selection", "No files selected or available to transfer.")
            self.set_status_indicator("red")
            return
        if not selected_indices:
            selected_indices = range(self.files_list.size())
        transfer_dir_main = "/home/kali/SecureFileTransfer/transferred/main/"
        transfer_dir_other = "/home/kali/SecureFileTransfer/transferred/other/"
        if not os.path.exists(transfer_dir_main):
            os.makedirs(transfer_dir_main)
        if not os.path.exists(transfer_dir_other):
            os.makedirs(transfer_dir_other)
        for index in selected_indices:
            self.update_progress(0, 0.5)
            file_name = self.files_list.get(index)
            full_path = os.path.join(self.upload_dir, file_name.replace("[Admin] ", "")) if file_name.startswith("[Admin] ") else os.path.join(self.upload_dir, file_name)
            if os.path.exists(full_path):
                if not file_name.startswith("[Admin]") or self.current_role == "admin":
                    branch = messagebox.askquestion("Transfer Destination", "Send to Main Branch?", icon='question', type=messagebox.YESNO)
                    dest_dir = transfer_dir_main if branch == "yes" else transfer_dir_other
                    if messagebox.askyesno("Confirm Transfer", f"Transfer {file_name} to {('Main Branch' if branch == 'yes' else 'Other Branch')}?"):
                        try:
                            shutil.move(full_path, os.path.join(dest_dir, file_name.replace("[Admin] ", "")))
                            if file_name in self.uploaded_files.get("user", []):
                                self.uploaded_files["user"].remove(file_name)
                            if file_name in self.uploaded_files.get("admin", []):
                                self.uploaded_files["admin"].remove(file_name)
                            if file_name in self.all_uploaded_files:
                                self.all_uploaded_files.remove(file_name)
                            self.refresh_file_list()
                            self.update_log(f"Transferred: {file_name} to {('Main Branch' if branch == 'yes' else 'Other Branch')}")
                            messagebox.showinfo("Success", f"Transferred {file_name} to {('Main Branch' if branch == 'yes' else 'Other Branch')}.")
                            self.set_status_indicator("green")
                        except OSError as e:
                            messagebox.showerror("Transfer Error", f"Failed to transfer {file_name}: {str(e)}")
                            self.set_status_indicator("red")
                    self.update_progress(100, 0.5)
                else:
                    messagebox.showerror("Permission Denied", f"Cannot transfer [Admin] file {file_name} as {self.current_role}")
                    self.set_status_indicator("red")
            self.update_progress(0, 0)

    def delete_file(self):
        if not self.current_role or (self.current_role != "admin" and not self.auth.has_permission(self.current_role, 'delete')):
            messagebox.showerror("Permission Denied", "You do not have permission to delete files.")
            self.set_status_indicator("red")
            return
        selected_indices = self.files_list.curselection()
        if not selected_indices and not self.files_list.size():
            messagebox.showwarning("No Selection", "No files selected or available to delete.")
            self.set_status_indicator("red")
            return
        if not selected_indices:
            selected_indices = range(self.files_list.size())
        for index in selected_indices:
            self.update_progress(0, 0.5)
            file_name = self.files_list.get(index)
            full_path = os.path.join(self.upload_dir, file_name.replace("[Admin] ", "")) if file_name.startswith("[Admin] ") else os.path.join(self.upload_dir, file_name)
            if os.path.exists(full_path):
                if not file_name.startswith("[Admin]") or (file_name.startswith("[Admin]") and self.current_role == "admin"):
                    if messagebox.askyesno("Confirm Delete", f"Delete {file_name}?"):
                        try:
                            os.remove(full_path)
                            if file_name in self.uploaded_files.get("user", []):
                                self.uploaded_files["user"].remove(file_name)
                            if file_name in self.uploaded_files.get("admin", []):
                                self.uploaded_files["admin"].remove(file_name)
                            if file_name in self.all_uploaded_files:
                                self.all_uploaded_files.remove(file_name)
                            self.files_list.delete(index)
                            self.refresh_file_list()
                            self.update_log(f"Deleted: {file_name}")
                            self.upload_status.config(text="File deleted successfully!")
                            messagebox.showinfo("Success", f"Deleted {file_name}.")
                            self.set_status_indicator("green")
                        except OSError as e:
                            self.upload_status.config(text="Delete failed!")
                            messagebox.showerror("Delete Error", f"Failed to delete {file_name}: {str(e)}")
                            self.set_status_indicator("red")
                    self.update_progress(100, 0.5)
                else:
                    messagebox.showerror("Permission Denied", f"Only admin can delete [Admin] file {file_name}.")
                    self.set_status_indicator("red")
            self.update_progress(0, 0)
        if not self.files_list.size():
            self.file_label.config(text="No file uploaded")
            self.uploaded_file = None

    def dummy_login(self):
        credentials = self.auth.authenticate(self.username_entry.get(), self.password_entry.get())
        if credentials["authenticated"]:
            # Hide login view and show main view
            self.login_container.pack_forget()
            self.main_container.pack(fill="both", expand=True)
            
            # Update header with user info
            self.update_user_info(credentials)
            
            # Enable navigation buttons
            for btn in self.nav_buttons.values():
                btn.config(state="normal")
            
            # Show logout button in footer
            self.logout_btn.pack(side="right")
            
            self.current_role = credentials["role"]
            self.refresh_file_list()
            self.set_status_indicator("green")
            
            # Show welcome message
            if self.current_role == "admin":
                self.update_log("Welcome admin - Full access granted")
            else:
                self.update_log(f"Welcome {self.username_entry.get()} - User access granted")
        else:
            messagebox.showerror("Login Error", "Invalid username or password")
            self.set_status_indicator("red")

    def update_user_info(self, credentials):
        """Update header with user information"""
        # Clear existing user info
        for widget in self.user_info_frame.winfo_children():
            widget.destroy()
        
        # User role indicator
        role_color = self.colors['success'] if credentials['role'] == 'admin' else self.colors['primary']
        role_text = "Administrator" if credentials['role'] == 'admin' else "User"
        
        user_label = tk.Label(self.user_info_frame,
                             text=f"👤 {self.username_entry.get()}",
                             font=("Segoe UI", 10, "bold"),
                             bg=self.colors['primary'],
                             fg="white")
        user_label.pack(anchor="e")
        
        role_label = tk.Label(self.user_info_frame,
                             text=f"🔑 {role_text}",
                             font=("Segoe UI", 9),
                             bg=self.colors['primary'],
                             fg="#e2e8f0")
        role_label.pack(anchor="e")

    def logout(self):
        # Hide main view and show login view
        self.main_container.pack_forget()
        self.login_container.pack(fill="both", expand=True)
        
        # Clear user info
        for widget in self.user_info_frame.winfo_children():
            widget.destroy()
        
        # Disable navigation buttons
        for btn in self.nav_buttons.values():
            btn.config(state="disabled")
        
        # Hide logout button
        self.logout_btn.pack_forget()
        
        # Clear form data
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.current_role = None
        self.files_list.delete(0, tk.END)
        self.upload_status.config(text="")
        self.file_label.config(text="No file selected")
        self.log_text.delete(1.0, tk.END)
        self.set_status_indicator("green")
        self.status_text.config(text="System Ready")

    def on_closing(self):
        self.root.withdraw()

    def on_restore(self):
        self.root.deiconify()

    def refresh_file_list(self):
        self.files_list.delete(0, tk.END)
        existing_files = [f for f in os.listdir(self.upload_dir) if os.path.isfile(os.path.join(self.upload_dir, f))]
        self.all_uploaded_files = []
        for file in existing_files:
            if self.current_role:
                tagged_name = f"[Admin] {file}" if self.current_role == "admin" else file
                self.all_uploaded_files.append(tagged_name)
                self.uploaded_files[self.current_role].append(tagged_name)
                if self.current_role == "user":
                    self.uploaded_files["admin"].append(tagged_name)
        for file in self.all_uploaded_files:
            base_name = file.replace("[Admin] ", "")
            if (self.current_role == "admin" or not file.startswith("[Admin] ")) or (self.current_role == "user" and file in self.uploaded_files["user"]):
                if base_name in existing_files:
                    self.files_list.insert(tk.END, file)

    def _trigger_refresh(self):
        self.root.after(0, self.refresh_file_list)

    def update_log(self, message):
        self.log_text.insert(tk.END, f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
        self.log_text.see(tk.END)

    def setup_tray(self):
        image = Image.new('RGB', (16, 16), color=(0, 128, 0))
        menu = (item('Show', self.on_restore), item('Exit', self.on_closing))
        self.icon = pystray.Icon("SecureBanking", image, "Secure Banking Portal", menu)
        self.icon.run_detached()

    def show_alert(self, message):
        messagebox.showerror("Security Alert", message, icon='error')

    def show_tray_notification(self, message):
        if hasattr(self, 'icon'):
            try:
                self.icon.notify(message, title="Malware Alert")
            except NotImplementedError:
                print(f"Notification fallback: {message}")

    def set_status_indicator(self, color):
        color_map = {"green": self.colors['success'], "yellow": self.colors['warning'], "red": self.colors['error']}
        if color in color_map:
            self.status_indicator.config(foreground=color_map[color])
            status_text_map = {"green": "System Ready", "yellow": "Processing...", "red": "Error Occurred"}
            if color in status_text_map:
                self.status_text.config(text=status_text_map[color])