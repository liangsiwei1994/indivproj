#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Aug 29 10:46:32 2023

@author: siweiliang
"""

import requests
import re

def find_latest_version(owner, repo_name):
    # Adjusted regex pattern to be more flexible for capturing versions embedded within text
    version_pattern = re.compile(r'(?<!\d)v(\d+\.\d+)(?!\d)')
    latest_version = None
    
    page = 1
    while True:
        url = f"https://api.github.com/repos/{owner}/{repo_name}/commits?page={page}"
        
        response = requests.get(url)
        count = 5
        if response.status_code == 200:
            commits = response.json()
            
            # If there are no more commits, break
            if not commits:
                break
            
            for commit_data in commits:
                message = commit_data['commit']['message']
                matches = version_pattern.findall(message)
                for match in matches:
                    # Extracting the version part without the 'v' prefix
                    print(match)
                    version = match
                    # print(version)
                    if not latest_version or tuple(map(int, version.split('.'))) > tuple(map(int, latest_version.split('.'))):
                        latest_version = version
                    elif tuple(map(int, version.split('.'))) < tuple(map(int, latest_version.split('.'))):
                        count = count-1

            # If you've already found a version, you might want to break early after a certain number of additional pages 
            # to prevent excessive API calls.
            # You can adjust this value or remove this condition.
            if (latest_version and page > 5) or count == 0:
                break

            page += 1
        else:
            print(f"Error: {response.status_code}")
            break

    return latest_version





# TRIAL FUNCTIONS

# owner = "mitre"
# repo_name = "cti"

# current_latest = float(find_latest_version(owner, repo_name))

# # with open("latest_version_no.txt", "w") as file:
# #     file.write(latest)


# # Read from the file named "latest_version.txt"
# with open("latest_version_no.txt", "r") as file:
#     saved_version_str = file.read().strip()  # for example, "v13.1"

# # Remove the "v" prefix and convert to float
# saved_version_float = float(saved_version_str)

# print(saved_version_float)  # This will print 13.1 as a float

# if current_latest == saved_version_float:
#     print("already latest")
# else:
#     print("update")
