import dacfunctions.dac_constants as dac_constants
import ssl
import requests
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

RateWarning = False

#despite the name, this function actually just hits a git url and returns the content and headers
def hit_branch(url, gitlab = False):
    global RateWarning
    try:
        #set the url and headers for public or internal
        if gitlab:
            url = dac_constants.GITLAB_URL + url
            githubheaders = dac_constants.GITLAB_HEADERS
        else:
            url = dac_constants.GITHUB_URL + url
            githubheaders = dac_constants.GITHUB_HEADERS

        #grab contents and headers
        r = requests.get(url, headers=githubheaders, verify=ssl.CERT_NONE)
        res = {'results': r.json(), 'headers': r.headers}

        #if we are approaching the rate limit for the api
        if "X-RateLimit-Remaining" in res['headers']:
            if int(res['headers']['X-RateLimit-Remaining']) < 500:
                resettime = int(res['headers']['X-RateLimit-Reset'])
                sleepamount = resettime - int(time.time())
                
                #if we havent said we are pausing yet, do so now
                if not RateWarning:
                    print(f"GIT API RATE LIMIT HIT, SLEEPING FOR: {sleepamount} seconds")
                    RateWarning = True

                #pause until the rate limiter resets
                time.sleep(sleepamount + 2)
                RateWarning = False

        #generic error catching
        if 'message' in res['results']:    
            res = {'results': None, 'headers': r.headers}
    except Exception as e:
        #print(f"Error: {e} in check_repos")
        raise
    return res
