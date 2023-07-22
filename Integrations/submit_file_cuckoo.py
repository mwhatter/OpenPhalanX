# submit_file_cuckoo.py
import requests
import os
import json
import sys

def submit_file_cuckoo(filename):
    headers = {"Authorization": "Bearer YOURTOKEN"}
    with open(filename, "rb") as sample:
        files = {"file": (os.path.basename(filename), sample)}
        response = requests.post("http://cuckoo-host:8090/tasks/create/submit", files=files, headers=headers)

    json_response = response.json()

    return json_response['task_id']

print(submit_file_cuckoo(sys.argv[1]))
