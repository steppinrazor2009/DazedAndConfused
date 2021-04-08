#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import dacfunctions.dac_io as dac_io
import dacfunctions.dac.dac_single as dac_single
import json
import concurrent.futures
import time

#checks a single gh organization
def check_single_org(org, conc = 200):
    jsonresult = {'org': org, 'repos':[], 'errors': []}
    starttime = time.time()
    try:
        #load up the repos for this org
        repos = check_repos(org)
        #check each repo with a new thread (up to n=conc threads)
        with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as executor:
            fut = [executor.submit(dac_single.check_single_repo, org, repository['name'], repository['default_branch']) for repository in repos]
            for r in concurrent.futures.as_completed(fut):
                #if there is an error, ad it to the error list
                scanresult = r.result()
                if 'errors' in scanresult:
                    jsonresult['errors'].append(scanresult['repo'])
                jsonresult['repos'].append(scanresult)

    except Exception as e:
        print(f"Error: {e} in check_single_org({org})")
        jsonresult['errors'].append(f"check_single_org({org})")
    if len(jsonresult['errors']) == 0:
           del jsonresult['errors']
    jsonresult['scan_time'] = time.time() - starttime

    jsonresult['repos'] = sorted(jsonresult['repos'], key = lambda i: str.casefold(i['repo']))
    
    return jsonresult

# gets a list of repos for a git org
def check_repos(org):
    repos = []
    ppg = 100
    pg = 1
    cnt = ppg
    try:
        #loop through repos... paging is done with a parameter here *shrug*
        while cnt == ppg:
            res = dac_io.hit_branch(f"/orgs/{org}/repos?per_page={ppg}&page={pg}&sort=full_name")['results']
            if res is None:
                res = []
            for repo in res:
                repos.append({'name': repo['name'], 'default_branch': repo['default_branch']})
            pg += 1
            cnt = len(res)
    except Exception as e:
        print(f"Error: {e} in check_repos")
        raise
    return repos
