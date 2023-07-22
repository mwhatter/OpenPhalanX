# mass_submit_files_virustotal.py
import requests
import os
import sys
import glob

def submit_file_virustotal(filename):
    headers = {"x-apikey": "YOUR_API_KEY"}
    with open(filename, "rb") as sample:
        files = {"file": (os.path.basename(filename), sample)}
        response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)

    json_response = response.json()

    return json_response['data']['id']

directory_path = sys.argv[1]
for file_path in glob.glob(directory_path + '/*'):
    print(submit_file_virustotal(file_path))
