#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import concurrent.futures
import time
import json
import os
import gitlab
import base64
from contentscanner import Scanner

class GLScanner:

    def __init__(self, conc=200):
        self.RateWarning = False
        self.conc = conc
        #GitHub API wrapper
        self.GL = gitlab.Gitlab("https://gitlab.com", private_token=os.getenv("GITLAB_AUTH"))
        self.FILESCANNER = Scanner("./modules", "modules.json")
        
    # checks a single repo for dependency confusion (now with threading!)
    def check_single_project(self, project):
        jsonresult = {'project': "", 'id': project, 'files': [], 'errors': []}
        if isinstance(project, str) and not project.isnumeric():
            return jsonresult
        starttime = time.time()
        try:
            project = self.GL.projects.get(project)
            jsonresult['project'] = project.name
            #grab packages from this repo and pull the dependencies from them
            files = self.check_gitlab_repo(project)
            filecontents = self.get_all_gitlab_manifest_contents(files, project)
            res = []
            for file in filecontents:
                contents = file['content']
                #if it aint a string, make it one
                if not isinstance(file['content'], str):
                    contents = json.dumps(file['content'])

                if not file['override']:
                    scanresult = self.FILESCANNER.scan_contents(file['file'], contents)
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

    #grabs all manifest file contents from gitlab
    def get_all_gitlab_manifest_contents(self, files, project):
        if not files:
            return []
        filecontents = []
        try:
            #grabs the file contents for all found files concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                fut = [executor.submit(self.get_single_gitlab_manifest_contents, file, project, ) for file in files]
                for r in concurrent.futures.as_completed(fut):
                    tmp = r.result()
                    if tmp is not None:
                        filecontents.append(r.result())
            
        except Exception as e:
            #print(f"Error: {e} in get_all_gitlab_manifest_contents")
            raise
        return filecontents

    #grabs the contents from a single file
    def get_single_gitlab_manifest_contents(self, file, project):
        if file['override']:
            return {'file': file['name'], 'content': '', 'override': True}    
        file_info = project.repository_blob(file['id'])
        content = base64.b64decode(file_info['content']).decode('utf-8')
        return {'file': file['name'], 'content': content, 'override': False}

    #checks a repo and finds the manifest files
    def check_gitlab_repo(self, project):
        files = []
        try:
            res = project.repository_tree()
            if res:
                overrides = []
                for f in res:
                    if f['type'] == 'blob':
                        for module in self.FILESCANNER.MODULES['modules']:
                            if f["path"].lower() in module['manifest_file'] or f['path'].lower() in module['lock_file'] or ('config_file' in module and f["path"].lower() == module['config_file']):
                                if 'config_file' in module and f["path"] == module['config_file']:
                                    if module['config_parse_func'](get_single_gitlab_manifest_contents({'name': f['path'], 'override': False}, project['id'], project['default_branch'])):
                                        overrides = overrides + module['manifest_file'] + module['lock_file']
                                else:
                                    files.append({'name': f['path'], 'override': False, 'id': f['id']})
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

    def scan_all_projects(self):
        results = {'projects_scanned': 0, 'vulnerable': 0, 'sus': 0, 'time_elapsed': 0, 'projects':[]}
        starttime = time.time()
        try:
            starttime = time.time()
            projectlist = self.GL.projects.list(order_by='id', min_access_level=10)
            #check each project concurrently (in threads)
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.conc) as executor:
                fut = [executor.submit(self.check_single_project, project.id,) for project in projectlist]
                for r in concurrent.futures.as_completed(fut):
                    tmp = r.result()
                    print(tmp['project'])
                    results['projects'].append(tmp)
                    
            #error check
            for project in results['projects']:
                if 'errors' in project:
                    print(f"Retrying: {project['project']}...")
                    tmp = self.check_single_project(project['id'])
                    index = next((index for (index, d) in enumerate(results['projects']) if d["id"] == tmp['id']), None)
                    results['projects'][index] = tmp
            
        except Exception as e:
            print(f"Error: {e} in scan_all_projects")
        return results

    #writes json output to filename
    @staticmethod
    def write_output_file(resultsfile, resultsjson, print_name=True):
        try:
            jsonoutput = json.dumps(resultsjson, indent=4)
            with open(resultsfile, "w") as file:
                file.write(jsonoutput)
            if print_name:
                print(os.path.realpath(resultsfile))
        except Exception as e:
            print(f"Error: {e} in write_output_file")   
            
    #get recap info for the dacgl.py file    
    @staticmethod
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