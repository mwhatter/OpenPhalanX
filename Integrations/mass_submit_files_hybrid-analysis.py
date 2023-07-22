# mass_submit_files_falcon.py
import requests
import os
import json
import sys
import glob

def submit_file_falcon(filename):
    headers = {"APIKEY": "YOUR_API_KEY"}
    with open(filename, "rb") as sample:
        files = {"file": (os.path.basename(filename), sample)}
        response = requests.post("https://www.hybrid-analysis.com/api/v2/submit/file", files=files, headers=headers)

    json_response = response.json()

    return json_response['job_id']

directory_path = sys.argv[1]
for file_path in glob.glob(directory_path + '/*'):
    print(submit_file_falcon(file_path))
