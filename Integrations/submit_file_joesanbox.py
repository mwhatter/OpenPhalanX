# submit_file_joe.py
import requests
import sys
import os

def submit_file_joe_sandbox(filename):
    url = "https://jbxcloud.joesecurity.org/api/v2/analysis"
    headers = {"Authorization": "API_KEY"}
    with open(filename, 'rb') as file_sample:
        files = {'sample': (os.path.basename(filename), file_sample)}
        response = requests.post(url, headers=headers, files=files)

    json_response = response.json()

    return json_response['data']['webid']

print(submit_file_joe_sandbox(sys.argv[1]))
