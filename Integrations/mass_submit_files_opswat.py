# mass_submit_files_opswat.py
import requests
import sys
import os
import glob

def submit_file_opswat(filename):
    url = "https://api.metadefender.com/v4/file"
    headers = {"apikey": "YOUR_API_KEY"}
    with open(filename, 'rb') as file_sample:
        files = {'file': (os.path.basename(filename), file_sample)}
        response = requests.post(url, headers=headers, files=files)

    json_response = response.json()

    return json_response['data_id']

directory_path = sys.argv[1]
for file_path in glob.glob(directory_path + '/*'):
    print(submit_file_opswat(file_path))
