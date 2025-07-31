import requests
import os
import shutil

# Your Auth-Key from MalwareBazaar
AUTH_KEY = "00f3f063e3a2a95d9eb055dbfd3112a1c0ace72900f53da8"
MALWARE_DIR = "/home/kali/malware_samples/"
BENIGN_DIR = "/home/kali/benign_samples/"

os.makedirs(MALWARE_DIR, exist_ok=True)
os.makedirs(BENIGN_DIR, exist_ok=True)

# Fetch malware samples
url = "https://mb-api.abuse.ch/api/v1/"
headers = {"Auth-Key": AUTH_KEY}
params = {"query": "get_recent", "selector": "time", "limit": 50}
response = requests.post(url, headers=headers, data=params)
if response.status_code == 200:
    data = response.json()
    for item in data["data"]:
        if "sha256_hash" in item:
            sample_url = f"https://bazaar.abuse.ch/download/{item['sha256_hash']}/"
            sample_response = requests.get(sample_url, headers=headers, allow_redirects=True)
            if sample_response.status_code == 200:
                with open(os.path.join(MALWARE_DIR, item["sha256_hash"]), "wb") as f:
                    f.write(sample_response.content)

# Copy benign files (e.g., from /usr/bin or your docs)
benign_sources = ["/usr/bin/ls", "/usr/bin/cat", "/home/kali/sample.pdf"]  # Add your own paths
for src in benign_sources:
    if os.path.exists(src):
        shutil.copy2(src, BENIGN_DIR)
print("Data collection complete. Check folders!")
