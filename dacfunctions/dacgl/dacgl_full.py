import dacfunctions.dac_io as dac_io
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
        projectlist = check_all_gitlab_projects()
        #check each project concurrently (in threads)
        with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as executor:
            fut = [executor.submit(dacgl_single.check_single_project, project['id'],) for project in projectlist]
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

#grabs all the available projects from a gitlab server
def check_all_gitlab_projects():
    projects = []
    try:
        #they use paging in the link header
        link = f"{dac_constants.GITLAB_URL}/projects?per_page=100&order_by=id&min_access_level=10&pagination=keyset&sort=asc"
        pattern = re.compile('<(?P<url>.*?)>;\srel="(?P<rel>\w*)"')
        
        #while there is still a next page
        while link:
            r = requests.get(link, headers=dac_constants.GITLAB_HEADERS, verify=ssl.CERT_NONE)
            res = [r.json(), r.headers]    
            for project in res[0]:
                projects.append({'id': project['id'], 'name': project['name'], 'default_branch': project['default_branch']})
                
            #if there is a next page, keep us going
            if 'Link' in res[1]:
                tmp = [m.groupdict() for m in pattern.finditer(res[1]['Link'])]
                link = next((item['url'] for item in tmp if item["rel"] == "next"), None)                        
            else:
                link = None
    except Exception as e:
        print(f"Error: {e} in check_all_gitlab_projects")
        raise
    return projects
