import requests
import os
import json
import sys
import glob

def submit_file_manalyzer(filename):
    with open(filename, "rb") as sample:
        files = {"file": (os.path.basename(filename), sample)}
        response = requests.post("https://manalyzer.org/api/submit", files=files)

    json_response = response.json()

    return json_response['task_id']

directory_path = sys.argv[1]
for file_path in glob.glob(directory_path + '/*'):
    print(submit_file_manalyzer(file_path))
