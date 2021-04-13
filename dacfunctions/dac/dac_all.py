#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import dacfunctions.dac.dac_single as dac_single
import dacfunctions.dac_constants as dac_constants
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
            fut = [executor.submit(dac_single.check_single_repo, org, repository) for repository in repos]
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
    ret = []
    organization = dac_constants.GH.organization(org)
    repos = organization.repositories(type="all")
    try:
        for repo in repos:
            ret.append(repo.name)
    except Exception as e:
        print(f"Error: {e} in check_repos")
        raise
    return ret
