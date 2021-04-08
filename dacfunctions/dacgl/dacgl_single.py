#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import dacfunctions.dac_io as dac_io
import dacfunctions.dac_contentscan as dac_contentscan
import dacfunctions.dac_constants as dac_constants
import concurrent.futures
import requests
import time
import json
import ssl

# checks a single repo for dependency confusion (now with threading!)
def check_single_project(project):
    jsonresult = {'project': "", 'id': project, 'files': [], 'errors': []}
    if isinstance(project, str) and not project.isnumeric():
        return jsonresult
    starttime = time.time()
    try:
        project = check_single_gitlab_project(project)
        jsonresult['project'] = project['name']
        #grab packages from this repo and pull the dependencies from them
        files = check_gitlab_repo(project['id'])
        filecontents = get_all_gitlab_manifest_contents(files, project['id'], project['default_branch'])
        res = []
        for file in filecontents:
            contents = file['content']
            #if it aint a string, make it one
            if not isinstance(file['content'], str):
                contents = json.dumps(file['content'])

            if not file['override']:
                scanresult = dac_contentscan.scan_contents(file['file'], contents)
            else:
                scanresult = {'result': {'file': file['file'], 'vulnerable': [], 'sus': [], 'override': True}}
                
            #bubble errors
            if 'errors' in scanresult:
                jsonresult['errors'].append(file['file'])
            else:
                jsonresult['files'].append(scanresult['result'])

        if len(jsonresult['errors']) == 0:
               del jsonresult['errors']
        jsonresult['scan_time'] = time.time() - starttime
        
    except Exception as e:
        print(f"Error: {e} in check_single_project")
    return jsonresult

#checks a single gl project and returns the info we want
def check_single_gitlab_project(projectid):
    result = {}
    try:
        res = dac_io.hit_branch(f"/projects/{projectid}", "l")['results']
        if res:
            result['id'] = projectid
            result['name'] = res['name']
            result['default_branch'] = res['default_branch']
    except Exception as e:
        #print(f"Error: {e} in check_single_gitlab_project")
        raise
    return result

#grabs all manifest file contents from gitlab
def get_all_gitlab_manifest_contents(files, projectid, default_branch):
    if not files:
        return []
    filecontents = []
    try:
        #grabs the file contents for all found files concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            fut = [executor.submit(get_single_gitlab_manifest_contents, file, projectid, default_branch, ) for file in files]
            for r in concurrent.futures.as_completed(fut):
                tmp = r.result()
                if tmp is not None:
                    filecontents.append(r.result())
        
    except Exception as e:
        #print(f"Error: {e} in get_all_gitlab_manifest_contents")
        raise
    return filecontents

#grabs the contents from a single file
def get_single_gitlab_manifest_contents(file, projectid, default_branch):
    if file['override']:
        return {'file': file['name'], 'content': '', 'override': True}    
    urlcontent = f"{dac_constants.GITLAB_URL}/projects/{projectid}/repository/files/{file['name']}/raw?ref={default_branch}"
    r = requests.get(urlcontent, headers=dac_constants.GITLAB_HEADERS, verify=ssl.CERT_NONE)
    try:
        content = json.loads(r.content)
    except:
        content = r.content.decode('utf-8"')
    return {'file': file['name'], 'content': content, 'override': False}

#checks a repo and finds the manifest files
def check_gitlab_repo(project):
    files = []
    try:
        res = dac_io.hit_branch(f"/projects/{project}/repository/tree", "l")['results']
        if res:
            overrides = []
            for f in res:
                if f['type'] == 'blob':
                    for module in dac_constants.MODULES['modules']:
                        if f["path"].lower() in module['manifest_file'] or f['path'].lower() in module['lock_file'] or ('config_file' in module and f["path"].lower() == module['config_file']):
                            if 'config_file' in module and f["path"] == module['config_file']:
                                if module['config_parse_func'](get_single_gitlab_manifest_contents({'name': f['path'], 'override': False}, project['id'], project['default_branch'])):
                                    overrides = overrides + module['manifest_file'] + module['lock_file']
                            else:
                                files.append({'name': f['path'], 'override': False})
                                if f['path'].lower() in module['lock_file']:
                                    for file in module['manifest_file'] + module['lock_file'][:-1]:
                                        if not f['path'].lower() == file.lower():
                                            overrides.append(file)             
                            break        
        overrides = list(set(overrides))
        for f in files:
            if f['name'].lower() in overrides:
                f['override'] = True
    except Exception as e:
        #print(f"Error: {e} in check_gitlab_repo")
        raise
    return files
