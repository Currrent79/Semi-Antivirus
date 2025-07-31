import yara
import os
import shutil

class FileScanner:
    def __init__(self, rules_path):
        self.rules_path = rules_path
        self.rules = self.load_rules()
        if self.rules:
            print(f"Rules loaded successfully from {rules_path}")
        else:
            print(f"Failed to load rules from {rules_path}. Check syntax or path.")

    def load_rules(self):
        try:
            if os.path.exists(self.rules_path):
                return yara.compile(self.rules_path)
            else:
                print(f"Rules file not found at {rules_path}")
                return None
        except yara.Error as e:
            print(f"Error loading YARA rules: {e}")
            return None

    def scan_file(self, file_path):
        if not self.rules:
            return "Error: YARA rules not loaded. Check terminal for details."
        if not os.path.exists(file_path):
            return f"Error: File not found at {file_path}"
        try:
            matches = self.rules.match(file_path)
            if matches:
                matched_rules = [match.rule for match in matches]
                # Quarantine the file if malicious
                quarantine_dir = "/home/kali/SecureFileTransfer/quarantine/"
                os.makedirs(quarantine_dir, exist_ok=True)
                file_name = os.path.basename(file_path)
                quarantine_path = os.path.join(quarantine_dir, file_name)
                shutil.move(file_path, quarantine_path)
                return f"File quarantined: {file_name} - Detected by rules - {', '.join(matched_rules)}"
            return "Clean: No threats detected"
        except Exception as e:
            return f"Scan failed: {str(e)}"

    def scan_directory(self, dir_path):
        if not self.rules or not os.path.exists(dir_path):
            return "Error: Invalid rules or directory not found"
        results = []
        for root, _, files in os.walk(dir_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                result = self.scan_file(file_path)
                results.append(f"{file_name}: {result}")
        return "\n".join(results) if results else "No files found in directory"

if __name__ == "__main__":
    scanner = FileScanner("/home/kali/SecureFileTransfer/rules/malware_rules.yar")
    single_file = input("Enter a file path to scan (or press Enter to skip): ")
    if single_file and os.path.exists(single_file):
        result = scanner.scan_file(single_file)
        print(result)
    dir_path = input("Enter a directory path to scan all files (or press Enter to skip): ")
    if dir_path and os.path.exists(dir_path):
        results = scanner.scan_directory(dir_path)
        print(results)