# submit_file_falcon.py
import requests
import os
import json
import sys

def submit_file_falcon(filename):
    headers = {"APIKEY": "YOUR_API_KEY"}
    with open(filename, "rb") as sample:
        files = {"file": (os.path.basename(filename), sample)}
        response = requests.post("https://www.hybrid-analysis.com/api/v2/submit/file", files=files, headers=headers)
    
    json_response = response.json()

    return json_response['job_id']

print(submit_file_falcon(sys.argv[1]))
