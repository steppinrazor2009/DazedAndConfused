#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import dacfunctions.dac_constants as dac_constants
import dacfunctions.dac.dac_single as dac_single
import dacfunctions.dac.dac_all as dac_all
import multiprocessing
import logging
import json
import time
import re

logging.basicConfig(filename='dac.log', level=logging.INFO)

#scans all orgs in git server
def scan_all_orgs(conc = 200, procs = 4):
    starttime = time.time()
    counter = dac_constants.Counter(0)
    results = {'orgs_scanned': 0, 'repos_scanned': 0, 'vulnerable': 0, 'sus': 0, 'time_elapsed': 0, 'orgs':[]}
    print("Retrieving org list...")
    orgslist = check_orgs()
    print(f"Done - {len(orgslist)} items retrieved!")
    try:
        #chunk the list of orgs for co-processing
        orgchunks = list(dac_constants.chunks(orgslist, procs))
        processes = []
        rets = []
        
        #run each chunk with a different process
        resultqueue = multiprocessing.Queue()
        for chunk in orgchunks:
            tmp = multiprocessing.Process(target=check_org_chunk, args=(resultqueue, chunk, conc, counter,))
            processes.append(tmp)
            tmp.start()
        for process in processes:
            res = resultqueue.get()
            rets = rets + res
        for process in processes:
            process.join()
        results['orgs'] = rets

        #error check
        for org in results['orgs']:
            if 'errors' in org:
                for repo in org['errors']:
                    print(f"Retrying: {repo}...")
                    tmp = dac_single.check_single_repo(org['org'], repo)
                    index = next((index for (index, d) in enumerate(org['repos']) if d["repo"] == repo), None)
                    org['repos'][index] = tmp

        #do recap
        results['time_elapsed'] = time.time() - starttime
        results['orgs_scanned'] = len(orgslist)
        recap = dac_constants.get_dac_recap(results)
        results['repos_scanned'] = recap['repos_scanned']
        results['vulnerable'] = recap['vulnerable']
        results['sus'] = recap['sus']
        
        results['orgs'] = sorted(results['orgs'], key = lambda i: str.casefold(i['org']))
        
        return results
    except Exception as e:
        print(f"Error: {e} in scan_all_orgs")

#checks a list of orgs for dependency confusion    
def check_org_chunk(resultqueue, orgs, conc, counter):
    results = []
    try:
        for org in orgs:
            res = dac_all.check_single_org(org, conc)
            logging.info(f"{org}")
            results.append(res)
            counter.increment()   
            print(f"{counter.value()}:\t{org} ({res['scan_time']})")
    except Exception as e:
        print(f"Error: {e} in check_org_chunk")
    resultqueue.put(results)

# get list of orgs
def check_orgs():
    results = []
    try:
        orgs = dac_constants.GH.all_organizations()
        for org in orgs:
            results.append(org.login)
    except Exception as e:
        #print(f"Error: {e} in check_orgs")
        raise
    return results

