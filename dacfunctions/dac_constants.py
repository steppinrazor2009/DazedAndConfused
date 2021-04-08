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

#Yield n number of striped chunks from l.
def chunks(l, n):
    for i in range(0, n):
        yield l[i::n]

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

#get recap info for the dac.py file
def get_dac_recap(results):
    r = 0
    v = 0
    s = 0
    for org in results['orgs']:
        r += len(org['repos'])
        for repo in org['repos']:
            for file in repo['files']:
                v += len(file['vulnerable'])
                s += len(file['sus'])
    return {'repos_scanned': r, 'vulnerable': v, 'sus': s}

#get recap info for the dacgl.py file    
def get_dacgl_recap(results):
    p = 0
    v = 0
    s = 0
    for project in results['projects']:
        p += 1
        for file in project['files']:
            v += len(file['vulnerable'])
            s += len(file['sus'])
    return {'projects_scanned': p, 'vulnerable': v, 'sus': s}

#get recap info for the dacswarm.py file
def get_swarm_recap(results):
    v = 0
    s = 0
    b = 0
    p = 0
    for project in results['projects']:
        for branch in project['branches']:
            b += 1
            for path in branch['paths']:
                p += 1
                for file in path['files']:
                    v += len(file['vulnerable'])
                    s += len(file['sus'])
    return {'projects_scanned': len(results['projects']), 'branches_scanned': b, 'paths_scanned': p, 'vulnerable': v, 'sus': s}

#counter class for multiprocessing counter
class Counter(object):
    def __init__(self, initval=0):
        self.val = multiprocessing.Value('i', initval)
        self.lock = multiprocessing.Lock()

    def increment(self):
        with self.lock:
            self.val.value += 1

    def value(self):
        with self.lock:
            return self.val.value

#URL constants
GITHUB_URL = "https://api.github.com"#your internal github enterprise
GITLAB_URL = "https://gitlab.com/api/v4"#your internal gitlab

#auth env variable constants
GITHUB_AUTH = os.getenv("GITHUB_AUTH")
GITLAB_AUTH = os.getenv("GITLAB_AUTH")

#header constants
GITHUB_HEADERS = {
 'Accept': 'application/vnd.github.v3+json',
 'Authorization': 'bearer %s' % (GITHUB_AUTH),
}
GITLAB_HEADERS = {
    'PRIVATE-TOKEN': GITLAB_AUTH
}


#check modules.json and import our modules
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../modules'))
sys.path.append(lib_path)
MODULES = {'modules' : []}

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

#keywords considered internal
INTERNAL_KEYWORDS = ['internal'] #list of keywords that indicate a private repository

#load our private and ignore lists
PRIVATE_KEYWORDS = load_text_to_list(os.path.abspath(os.path.join(os.path.dirname(__file__), '../keywordlists/privatekeywords.txt')))
IGNORE_LIST = load_text_to_list(os.path.abspath(os.path.join(os.path.dirname(__file__), '../keywordlists/ignore.txt')))    
