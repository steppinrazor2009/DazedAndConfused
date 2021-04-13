#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import dacfunctions.dac_constants as dac_constants
import dacfunctions.dacgl.dacgl_single as dacgl_single
import json
import time
import re
import ssl
import requests
import concurrent.futures

def scan_all_projects(conc = 200):
    results = {'projects_scanned': 0, 'vulnerable': 0, 'sus': 0, 'time_elapsed': 0, 'projects':[]}
    starttime = time.time()
    try:
        starttime = time.time()
        projectlist = dac_constants.GL.projects.list(order_by='id', min_access_level=10)
        #check each project concurrently (in threads)
        with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as executor:
            fut = [executor.submit(dacgl_single.check_single_project, project.id,) for project in projectlist]
            for r in concurrent.futures.as_completed(fut):
                tmp = r.result()
                print(tmp['project'])
                results['projects'].append(tmp)
                
        #error check
        for project in results['projects']:
            if 'errors' in project:
                print(f"Retrying: {project['project']}...")
                tmp = dacgl_single.check_single_project(project['id'])
                index = next((index for (index, d) in enumerate(results['projects']) if d["id"] == tmp['id']), None)
                results['projects'][index] = tmp
        
        #do recap
        results['time_elapsed'] = time.time() - starttime
        recap = dac_constants.get_dacgl_recap(results)
        results['vulnerable'] = recap['vulnerable']
        results['sus'] = recap['sus']
        results['projects_scanned'] = recap['projects_scanned']

        
    except Exception as e:
        print(f"Error: {e} in scan_all_projects")
    return results
