#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import dacfunctions.dac_contentscan as dac_contentscan
import dacfunctions.dac_constants as dac_constants
import concurrent.futures

# checks a single repo for dependency confusion (now with threading!)
def check_single_repo(org, repo):
    jsonresult = {'repo': repo, 'files':[], 'errors': []}
    try:
        #check rate limits and sleep if need be
        core = dac_constants.GH.rate_limit()['resources']['core']
        if int(core['remaining']) < 500:
            resettime = int(core['reset'])
            sleepamount = resettime - int(time.time())
            
            #if we havent said we are pausing yet, do so now
            if not dac_constants.RateWarning:
                print(f"GIT API RATE LIMIT HIT, SLEEPING FOR: {sleepamount} seconds")
                dac_constants.RateWarning = True

            #pause until the rate limiter resets
            time.sleep(sleepamount + 2)
            dac_constants.RateWarning = False

        repository = dac_constants.GH.repository(org, repo)
        #grab packages from this repo and pull the dependencies from them
        files = check_repo(repository)
        filecontents = get_all_manifest_contents(files, repository)
        for file in filecontents:
            if not file['override']:
                #scan it
                scanresult = dac_contentscan.scan_contents(file['file'], file['content'])
            else:
                scanresult = {'result': {'file': file['file'], 'vulnerable': [], 'sus': [], 'override': True}}

            #if we had errors, bubble them up
            if 'errors' in scanresult:
                jsonresult['errors'].append(scanresult['errors'])
            else:
                jsonresult['files'].append(scanresult['result'])
        #remove empty errors
        if len(jsonresult['errors']) == 0:
            del jsonresult['errors']

        jsonresult['files'] = sorted(jsonresult['files'], key = lambda i: str.casefold(i['file']))
    except Exception as e:
        if "new thread" not in str(e) and "repository is empty" not in str(e):
            print(f"{org} : {repo} : Error: {e} in check_single_repo")
    return jsonresult

#traverses a git repo and finds manifest files 
def check_repo(repo):
    files = []
    try:
        contents = repo.directory_contents("", return_as=dict)
        overrides = []
        for file in contents:
            f = contents[file]
            for module in dac_constants.MODULES['modules']:
                if f.path.lower() in module['manifest_file'] or f.path.lower() in module['lock_file'] or ('config_file' in module and f.path.lower() == module['config_file']):
                    if 'config_file' in module and f.path.lower() == module['config_file']:
                        if module['config_parse_func'](get_single_manifest_contents(repo, {'name': f.path, 'override': False})):
                            overrides = overrides + module['manifest_file'] + module['lock_file']
                    else:
                        files.append({'name': f.path, 'override': False})
                        if f.path.lower() in module['lock_file']:
                            for file in module['manifest_file'] + module['lock_file'][:-1]:
                                if not f.path.lower() == file.lower():
                                    overrides.append(file)             
                    break
        overrides = list(set(overrides))
        for f in files:
            if f['name'] in overrides:
                f['override'] = True
    except Exception as e:
        #print(f"Error: {e} in check_repo")
        raise
    return files

#grabs manifest file contents from git (but with threads this time!)
def get_single_manifest_contents(repo, file):
    try:
        if file['override']:
            return {'file': file['name'], 'content': '', 'override': True}
        content = repo.file_contents(file['name']).decoded.decode("utf-8")
        return {'file': file['name'], 'content': content, 'override': False}
    except Exception as e:
        #print(f"Error: {e} in ({filename}) get_single_manifest_contents")
        raise

#grabs all manifest file contents from git
def get_all_manifest_contents(files, repo):
    if not files or len(files) == 0:
        return []
    filecontents = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            fut = [executor.submit(get_single_manifest_contents, repo, file) for file in files]
            for r in concurrent.futures.as_completed(fut):
                tmp = r.result()
                if tmp is not None:
                    filecontents.append(r.result())
        
    except Exception as e:
        #print(f"Error: {e} in get_all_manifest_contents")
        raise
    return filecontents

