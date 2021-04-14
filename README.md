<!---

 Copyright (c) 2021, salesforce.com, inc.
 All rights reserved.
 SPDX-License-Identifier: BSD-3-Clause
 For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause

-->
# DazedAndConfused
DazedAndConfused is a tool to help determine dependency confusion exposure.
### Currently works on:
* Bower (bower.json)
* Cocoapods (podfile, podfile.lock)
* Composer (composer.json, composer.lock)
* GEMS (Gemfile, gemfile.lock)
* Gradle (gradle.build, gradle.lockfile)
* Gulp (gulpfile.js)
* Maven (pom.xml)
* NPM (package.json, package-lock.json, npm-shrinkwrap.json)
* Nuget (nuget.config) *** only determines if the configuration leaves it vulnerable ***
* PiP (requirements.txt, pipfile, pipfile.lock)
* SFDX (package.json)
* Yarn (yarn.lock)

## INSTALLATION
Clone this repo or download and unzip.

Install the requirements by running - ```pip (or pip3) install -r requirements.txt```

Create github personal token by clicking at the top right corner at your avatar and navigating to Settings > Developer Settings > Personal Access Tokens. Generate new token, make sure to copy it. Next, set all of the scopes for the repo. Finally, add token to your environment variables, name the token GITHUB_AUTH  / GITLAB_AUTH for a  github server and gitlab server respectively. For example, for Mac or Linux it will look like ```export GITHUB_AUTH="YOUR_TOKEN_GOES_HERE"```.  Finally, add tokens to your environment variables named GITLAB_URL and GITHUB_URL which should match the server you want to scan.

To improve the accuracy of results:
* dac_constants.py - ensure that the INTERNAL_KEYWORDS list contains keywords which will match your internal package servers.
* privatekeywords.txt seed the file with some private keywords (which are used to determine if a package is supposed to be private when checking for it on public registries).
* ignore.txt any packages with names matching items in the ignore file will be completely ignored (this will speed up scanning).

## USAGE
Once your environment variables are set (from above) and you have the correct URLs in place, follow the following usage guide:

### dac.py has 3 commands for scanning GitHub servers:
* single
```
Usage: dac.py single [OPTIONS]

  The [single] command scans a single github repository

Options:
  -org, -o TEXT           org name  [required]
  -repo, -r TEXT          repo name  [required]
  -resultsfile, -rf TEXT  file for results  [required]
  -h, --help              Show this message and exit.
```

* all
```
Usage: dac.py all [OPTIONS]

  The [all] command scans all github repositories in a single organization

Options:
  -org, -o TEXT           org name  [required]
  -resultsfile, -rf TEXT  file for results  [required]
  -c, --conc INTEGER      Number of concurrent repo scans per org (higher for
                          servers, lower for desktop/laptops)  [default: 200]
  -h, --help              Show this message and exit.
```

* full
```
Usage: dac.py full [OPTIONS]

  The [full] command scans all available organizations on a github server

Options:
  -resultsfile, -rf TEXT  file for results  [required]
  -c, --conc INTEGER      Number of concurrent repo scans per org (higher for
                          servers, lower for desktop/laptops)  [default: 200]

  --procs INTEGER         Number of concurrent processes to use for scanning
                          orgs (roughly, how many cores to use)  [default: 3]
  -h, --help              Show this message and exit.
```

### dacgl.py has 2 commands for scanning internal GitLab servers:
Please note that gitlab support is not fully tested and should be treated as extreme beta.

* single
```
Usage: dacgl.py single [OPTIONS]

  The [single] command scans a single gitlab project

Options:
  -projectid, -p TEXT     project id  [required]
  -resultsfile, -rf TEXT  file for results  [required]
  -h, --help              Show this message and exit.
```

* full
```
Usage: dacgl.py full [OPTIONS]

  The [full] command scans all available projects on a gitlab server

Options:
  -resultsfile, -rf TEXT  file for results  [required]
  -c, --conc INTEGER      Number of concurrent repo scans per org (higher for
                          servers, lower for desktop/laptops)  [default: 200]
  -h, --help              Show this message and exit.
```

### dacutil.py has 2 commands for scanning directly from local files or URLs:
* file
```
Usage: dacutil.py file [OPTIONS]

  The [file] command scans a single manifest file locally

Options:
  -filename, -f TEXT      file name  [required]
  -resultsfile, -rf TEXT  results file name  [required]
  -h, --help              Show this message and exit.
```

* url
```
Usage: dacutil.py url [OPTIONS]

  The [url] command scans a single manifest file via url

Options:
  -manifestname, -mn TEXT  manifest file name (e.g. package.json) [required]
  -url, -u TEXT            file url  [required]
  -resultsfile, -r TEXT    results file name  [required]
  -h, --help               Show this message and exit.
```

## OUTPUT
For each repository, a results array will be generated.
* file indicates which manifest file was scanned.
* vulnerable - this package exists internally but does not exist in public repositories and is possibly vulnerable to being taken over
* sus - this package seems like it should be private and exist only internally, but exists in public repositories and could indicate an in progress exploit
```
{
  "orgs_scanned": 1,
  "repos_scanned": 1,
  "vulnerable": 1,
  "sus": 2,
  "time_elapsed": 1.5069756507874,
  "orgs": [
    {
      "org": "Foo",
      "repos": [
        {
          "repo": "Bar",
          "files": [
            {
              "file": "pom.xml",
              "vulnerable": [
                "foo-bar-test1"
              ],
              "sus": [
                "foo-bar-test2",
                "foo-bar-test3"
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

## ADDING MODULES
Modules can be added easily to support more package managers.  Simply:
* Create a .py file for the module you wish to support 
* Include a function to parse the manifest file and another function to check the public repository
* Update modules.json in the main folder with the module, filename, and function names
The important features are the parsing function:
```
def get_gulp_dependencies(filename, contents):
    result = []
    try:
        #gulp is pretty straightforward js
        pat = re.compile(r"require\(\s*['\"](.*?)['\"]\s*\)", re.DOTALL)
        result = re.findall(pat, contents)
        result = [{'name': item, 'version': "TBD"} for item in result]
    except Exception as e:
        #print(f"gulp Error: {e}")
        raise
    return result
```

and the public repo check function, where a return of '0.0.0.0' means the dependency does not exist:
```
def check_gulp_public_repo(pkg):
    try:
        with urllib.request.urlopen(f"https://registry.npmjs.org/{pkg}/", timeout=10) as url:
            data = json.loads(url.read().decode())
        if "dist-tags" in data:
            return data['dist-tags']['latest']
        else:
            return data['time']['unpublished']['versions'][0]
    except Exception as e:
        #print(f"gulp Error: {e}")
        return '0.0.0.0'
```

A module in modules.json would look like this:
```
        {
            "name" : "npm",
            "file_name" : "npm.py",
            "manifest_file" : [
                "package.json"
            ],
            "lock_file": [
                "npm-shrinkwrap.json",
                "package-lock.json"
            ],
            "config_file": ".npmrc",
            "config_parse_func": "check_npm_config",
            "parse_func" : "get_npm_dependencies",
            "repo_check_func" : "check_npm_public_repo"
        }
```

* Lock files will be the only files checked for that module (instead of each "manifest_file").
* config_file specifies a configuration file for that package manager.  If it exists, a function (specified by config_parse_func) must also exist in the python file which will return True or False depending on whether files for this package manager can be skipped. (this is useful in the event that a package manager is pointing to an internal registry and you want to skip scanning those files)