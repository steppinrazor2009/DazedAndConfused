#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import json
import os
import multiprocessing
import sys
import importlib
import gitlab
from github3 import GitHub, GitHubEnterprise

#loads a line-by-line text file into a list        
def load_text_to_list(filename):
    result = []
    try:
        with open(filename) as f:
            result = f.readlines()
        result = [x.strip() for x in result]
    except Exception as e:
        print(f"Error: {e} in load_text_to_list")
        raise
    return result

#writes json output to filename
def write_output_file(resultsfile, resultsjson, print_name=True):
    try:
        jsonoutput = json.dumps(resultsjson, indent=4)
        with open(resultsfile, "w") as file:
            file.write(jsonoutput)
        if print_name:
            print(os.path.realpath(resultsfile))
    except Exception as e:
        print(f"Error: {e} in write_output_file")   


RateWarning = False

#server constants
GITHUB_URL = "https://github.com"#your github
GITHUB_AUTH = os.getenv("GITHUB_AUTH")
GITLAB_URL = "https://gitlab.com"#your gitlab
GITLAB_AUTH = os.getenv("GITLAB_AUTH")

#modules setup
MODULES = {'modules' : []}

#keywords
INTERNAL_KEYWORDS = ['internal'] #list of keywords that indicate a private repository
PRIVATE_KEYWORDS = load_text_to_list(os.path.abspath(os.path.join(os.path.dirname(__file__), '../keywordlists/privatekeywords.txt')))
IGNORE_LIST = load_text_to_list(os.path.abspath(os.path.join(os.path.dirname(__file__), '../keywordlists/ignore.txt')))    

if 'GITHUB_URL' in locals() and 'GITHUB_AUTH' in locals():
    GH = GitHubEnterprise(GITHUB_URL, token=GITHUB_AUTH, verify=False)
if 'GITLAB_URL' in locals() and 'GITLAB_AUTH' in locals():
    GL = gitlab.Gitlab(GITLAB_URL, private_token=GITLAB_AUTH)

#check modules.json and import our modules
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../modules'))
sys.path.append(lib_path)

#load modules.json
with open(os.path.abspath(os.path.join(os.path.dirname(__file__), '../modules.json'))) as f:
    MODULES = json.load(f)
for module in MODULES['modules']:
    #set d as a ref to the module itself (for calling funcs)
    module['d'] = importlib.import_module(module['name'])
    #set funcs as refs to funcs from the strings
    module['parse_func'] = getattr(module['d'], module['parse_func'])
    module['repo_check_func'] = getattr(module['d'], module['repo_check_func'])
    module['manifest_file'] = [x.lower() for x in module['manifest_file']]
    module['lock_file'] = [x.lower() for x in module['lock_file']]
    if 'config_file' in module:
        module['config_file'] = module['config_file'].lower()
        module['config_parse_func'] = getattr(module['d'], module['config_parse_func'])
