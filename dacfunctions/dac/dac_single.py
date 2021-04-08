import dacfunctions.dac_io as dac_io
import dacfunctions.dac_contentscan as dac_contentscan
import dacfunctions.dac_constants as dac_constants
import json
import requests
import ssl
import base64
import concurrent.futures

# checks a single repo for dependency confusion (now with threading!)
def check_single_repo(org, repo, defaultbranch = None):
    jsonresult = {'repo': repo, 'files':[], 'errors': []}
    try:
        #grab packages from this repo and pull the dependencies from them
        files = check_repo(org, repo, defaultbranch)
        filecontents = get_all_manifest_contents(files, org, repo)
        res = []
        for file in filecontents:
            #if its not a string, make it one
            if not isinstance(file['content'], str):
                contents = json.dumps(file['content'])
            else:
                contents = file['content']
            
            if not file['override']:
                #scan it
                scanresult = dac_contentscan.scan_contents(file['file'], contents)
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
        if "new thread" not in str(e):
            print(f"{org} : {repo} : Error: {e} in check_single_repo")
    return jsonresult

#traverses a git repo and finds manifest files 
def check_repo(org, repo, defaultbranch):
    files = []
    try:
        #grab the repo contents
        if defaultbranch:
            res = dac_io.hit_branch(f"/repos/{org}/{repo}/git/trees/{defaultbranch}")['results']
        else:
            res = dac_io.hit_branch(f"/repos/{org}/{repo}/git/trees/master")['results']
            if not res:
                res = dac_io.hit_branch(f"/repos/{org}/{repo}/git/trees/develop")['results']
                if not res:
                    res = dac_io.hit_branch(f"/repos/{org}/{repo}/git/trees/dev")['results']
                    if not res:
                        res = dac_io.hit_branch(f"/repos/{org}/{repo}/git/trees/main")['results']
        if not res:
            return []
        
        #check each file, return the ones we can process
        overrides = []
        for f in res["tree"]:
            for module in dac_constants.MODULES['modules']:
                if f['path'].lower() in module['manifest_file'] or f['path'].lower() in module['lock_file'] or ('config_file' in module and f['path'].lower() == module['config_file']):
                    if 'config_file' in module and f['path'].lower() == module['config_file']:
                        if module['config_parse_func'](get_single_manifest_contents(org, repo, {'name': f['path'], 'override': False})):
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
            if f['name'] in overrides:
                f['override'] = True
    except Exception as e:
        #print(f"Error: {e} in check_repo")
        raise
    return files

#grabs manifest file contents from git (but with threads this time!)
def get_single_manifest_contents(org, repo, file):
    try:
        url = dac_constants.GITHUB_URL
        githubheaders = dac_constants.GITHUB_HEADERS

        if file['override']:
            return {'file': file['name'], 'content': '', 'override': True}
        
        urlcontent = f"{url}/repos/{org}/{repo}/contents/{file['name']}"
        r = requests.get(urlcontent, headers=githubheaders, verify=ssl.CERT_NONE)
        if('content') not in r.json():
            return None
        data = base64.b64decode(r.json()['content'])
        try:
            content = base64.b64decode(r.json()['content']).decode('ascii')
        except:
            content = base64.b64decode(r.json()['content']).decode()
        return {'file': file['name'], 'content': content, 'override': False}
    except Exception as e:
        #print(f"Error: {e} in ({filename}) get_single_manifest_contents")
        raise

#grabs all manifest file contents from git
def get_all_manifest_contents(files, org, repo):
    if not files or len(files) == 0:
        return []
    filecontents = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            fut = [executor.submit(get_single_manifest_contents, org, repo, file) for file in files]
            for r in concurrent.futures.as_completed(fut):
                tmp = r.result()
                if tmp is not None:
                    filecontents.append(r.result())
        
    except Exception as e:
        #print(f"Error: {e} in get_all_manifest_contents")
        raise
    return filecontents

