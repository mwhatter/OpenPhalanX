import requests
import json
import sys
import os
from datetime import datetime
import hashlib

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def submit_file_to_anomali(file_path, api_key):
    url = "https://api.threatstream.com/api/v1/submit/new/"
    headers = {"Authorization": f"apikey {api_key}"}
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    sha256 = calculate_sha256(file_path)
    note = f"Submitted on {timestamp}, Filename: {os.path.basename(file_path)}, SHA256: {sha256}"
    data = {
        "use_vmray_sandbox": "true",
        "vmray_max_jobs": "3",
        "report_radio-classification": "private",
        "report_radio-notes": note
    }
    with open(file_path, "rb") as f:
        files = {"report_radio-file": f}
        response = requests.post(url, headers=headers, data=data, files=files)
    return response.json(), note

if __name__ == "__main__":
    directory_path = sys.argv[1]
    api_key = sys.argv[2]
    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)
        response, note = submit_file_to_anomali(file_path, api_key)
        print(f"Submitted file {file_name}. Response: {response}, Note: {note}")
