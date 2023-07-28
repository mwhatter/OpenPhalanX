import requests
import os
import json
import sys

def submit_file_manalyzer(filename):
    with open(filename, "rb") as sample:
        files = {"file": (os.path.basename(filename), sample)}
        response = requests.post("https://manalyzer.org/api/submit", files=files)

    json_response = response.json()

    return json_response['task_id']

print(submit_file_manalyzer(sys.argv[1]))
