# submit_file_virustotal.py
import requests
import os
import sys

def submit_file_virustotal(filename):
    headers = {"x-apikey": "YOUR_API_KEY"}
    with open(filename, "rb") as sample:
        files = {"file": (os.path.basename(filename), sample)}
        response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)

    json_response = response.json()

    return json_response['data']['id']

print(submit_file_virustotal(sys.argv[1]))
