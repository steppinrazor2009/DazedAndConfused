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
import multiprocessing
from github3 import GitHub, GitHubEnterprise
from contentscanner import Scanner

class GHScanner:

    def __init__(self, conc=200, procs=4, public=False):
        self.RateWarning = False
        self.conc = conc
        self.procs = procs
        self.public = public
        #GitHub API wrapper
        if public:
            self.GH = GitHub(os.getenv("GITHUB_URL"), token=os.getenv("GITHUB_AUTH"))
        else:
            self.GH = GitHubEnterprise(os.getenv("GITHUB_URL"), token=os.getenv("GITHUB_AUTH"), verify=False)

        self.FILESCANNER = Scanner("./modules", "modules.json")

    #scans all orgs in git server
    def scan_all_orgs(self):
        starttime = time.time()
        results = {'orgs_scanned': 0, 'repos_scanned': 0, 'vulnerable': 0, 'sus': 0, 'time_elapsed': 0, 'orgs':[]}
        print("Retrieving org list...")
        orgslist = self.check_orgs()
        print(f"Done - {len(orgslist)} items retrieved!")
        try:
            #chunk the list of orgs for co-processing
            orgchunks = list(self.chunks(orgslist, self.procs))
            processes = []
            rets = []
            
            #run each chunk with a different process
            resultqueue = multiprocessing.Queue()
            for chunk in orgchunks:
                tmp = multiprocessing.Process(target=self.check_org_chunk, args=(resultqueue, chunk, self.conc, self.procs, self.public))
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
                        tmp = self.check_single_repo(org['org'], repo)
                        index = next((index for (index, d) in enumerate(org['repos']) if d["repo"] == repo), None)
                        org['repos'][index] = tmp

            #do recap
            results['time_elapsed'] = time.time() - starttime
            results['orgs_scanned'] = len(orgslist)
            
            return results
        except Exception as e:
            print(f"Error: {e} in scan_all_orgs")

    # get list of orgs
    def check_orgs(self):
        results = []
        try:
            orgs = self.GH.organizations()
            for org in orgs:
                results.append(org.login)
        except Exception as e:
            #print(f"Error: {e} in check_orgs")
            raise
        return results

    #checks a single gh organization
    def check_single_org(self, org):
        jsonresult = {org:[], 'errors': []}
        starttime = time.time()
        try:
            #load up the repos for this org
            repos = self.check_repos(org)
            #check each repo with a new thread (up to n=conc threads)
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.conc) as executor:
                fut = [executor.submit(self.check_single_repo, org, repository) for repository in repos]
                for r in concurrent.futures.as_completed(fut):
                    #if there is an error, ad it to the error list
                    scanresult = r.result()
                    if 'errors' in scanresult:
                        jsonresult['errors'].append(scanresult['repo'])
                    jsonresult[org].append(scanresult)

        except Exception as e:
            print(f"Error: {e} in check_single_org({org})")
            jsonresult['errors'].append(f"check_single_org({org})")
        if len(jsonresult['errors']) == 0:
            del jsonresult['errors']
        jsonresult['scan_time'] = time.time() - starttime
        return jsonresult

    # gets a list of repos for a git org
    def check_repos(self, org):
        ret = []
        try:
            organization = self.GH.organization(org)
            repos = organization.repositories(type="all")
            for repo in repos:
                ret.append(repo.name)
        except Exception as e:
            print(f"Error: {e} in check_repos")
            raise
        return ret

    # checks a single repo for dependency confusion (now with threading!)
    def check_single_repo(self, org, repo):
        jsonresult = {repo: [], 'errors': []}
        try:
            #check rate limits and sleep if need be
            core = self.GH.rate_limit()['resources']['core']
            if int(core['remaining']) < 500:
                resettime = int(core['reset'])
                sleepamount = resettime - int(time.time())
                
                #if we havent said we are pausing yet, do so now
                if not self.RateWarning:
                    print(f"GIT API RATE LIMIT HIT, SLEEPING FOR: {sleepamount} seconds")
                    self.RateWarning = True

                #pause until the rate limiter resets
                time.sleep(sleepamount + 2)
                self.RateWarning = False

            repository = self.GH.repository(org, repo)
            #grab packages from this repo and pull the dependencies from them
            files = self.check_repo(repository)
            filecontents = self.get_all_manifest_contents(files, repository)
            for file in filecontents:
                #scan it
                scanresult = self.FILESCANNER.scan_contents(file['file'], file['content'], file['override'])

                #if we had errors, bubble them up
                if 'errors' in scanresult:
                    jsonresult['errors'].append(scanresult['errors'])
                else:
                    jsonresult[repo].append(scanresult)
            #remove empty errors
            if len(jsonresult['errors']) == 0:
                del jsonresult['errors']

        except Exception as e:
            if "new thread" not in str(e) and "repository is empty" not in str(e):
                print(f"{org} : {repo} : Error: {e} in check_single_repo")
        return jsonresult

    #traverses a git repo and finds manifest files 
    def check_repo(self, repo):
        files = []
        try:
            contents = repo.directory_contents("", return_as=dict)
            overrides = []
            for file in contents:
                f = contents[file]
                for module in self.FILESCANNER.MODULES['modules']:
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
    def get_single_manifest_contents(self, repo, file):
        try:
            if file['override']:
                return {'file': file['name'], 'content': '', 'override': True}
            content = repo.file_contents(file['name']).decoded.decode("utf-8")
            return {'file': file['name'], 'content': content, 'override': False}
        except Exception as e:
            #print(f"Error: {e} in ({filename}) get_single_manifest_contents")
            raise

    #grabs all manifest file contents from git
    def get_all_manifest_contents(self, files, repo):
        if not files or len(files) == 0:
            return []
        filecontents = []
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                fut = [executor.submit(self.get_single_manifest_contents, repo, file) for file in files]
                for r in concurrent.futures.as_completed(fut):
                    tmp = r.result()
                    if tmp is not None:
                        filecontents.append(r.result())
            
        except Exception as e:
            #print(f"Error: {e} in get_all_manifest_contents")
            raise
        return filecontents

    #Yield n number of striped chunks from l.
    @staticmethod
    def chunks(l, n):
        for i in range(0, n):
            yield l[i::n]
            
    #checks a list of orgs for dependency confusion  
    @staticmethod
    def check_org_chunk(resultqueue, orgs, conc, procs, public=False):
        results = []
        try:
            ghscanner = GHScanner(conc, procs, public)
            for org in orgs:
                res = ghscanner.check_single_org(org)
                results.append(res)
                print(f"{org} ({res['scan_time']})")
        except Exception as e:
            print(f"Error: {e} in check_org_chunk")
        resultqueue.put(results)

    #get recap info for the dac.py file
    @staticmethod
    def get_dac_recap(results):
        r = 0
        v = 0
        s = 0
        for org in results['orgs']:
            r += len(org)
            oname = next(iter(org))
            for repo in org[oname]:
                rname = next(iter(repo))
                for file in repo[rname]:
                    fname = next(iter(file))
                    v += len(file[fname]['vulnerable'])
                    s += len(file[fname]['sus'])
        return {'repos_scanned': r, 'vulnerable': v, 'sus': s}

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
