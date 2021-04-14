#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import time
import click
import urllib3
from ghscanner import GHScanner
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
#default func when called
def dazed_and_confused():
    """ Dazed and Confused is a tool for scanning Github, Gitlab, and Swarm for instances of dependency confusion """
    pass

@dazed_and_confused.command('single', short_help='scans a single repository in a public or private github instance')
@click.option("-org", "-o", required=True, help="org name")
@click.option("-repo", "-r", required=True, help="repo name")
@click.option("-resultsfile", "-rf", required=True, help="file for results")
def single(org, repo, resultsfile):
    """ The [single] command scans a single github repository """
    scanner = GHScanner()
    starttime = time.time()
    results = {'orgs_scanned': 0, 'repos_scanned': 1, 'vulnerable': 0, 'sus': 0, 'time_elapsed': 0, 'orgs': []}
    singleresult = [{'org': org, 'repos': [scanner.check_single_repo(org, repo)]}]
    results['orgs'] = singleresult
                    
    #do recap
    results['time_elapsed'] = time.time() - starttime
    recap = scanner.get_dac_recap(results)
    results['vulnerable'] = recap['vulnerable']
    results['sus'] = recap['sus']
    scanner.write_output_file(resultsfile, results)


@dazed_and_confused.command('all', short_help='scans all repositories in a single org on a public or private github instance')
@click.option("-org", "-o", required=True, help="org name")
@click.option("-resultsfile", "-rf", required=True, help="file for results")
@click.option('--conc', "-c", default=200, show_default=True, help='Number of concurrent repo scans per org (higher for servers, lower for desktop/laptops)')
def all(org, resultsfile, conc):
    """ The [all] command scans all github repositories in a single organization """
    scanner = GHScanner(conc)
    starttime = time.time()
    results = {'orgs_scanned': 1, 'repos_scanned': 0, 'vulnerable': 0, 'sus': 0, 'time_elapsed': 0, 'orgs': []}
    results['orgs'] = [scanner.check_single_org(org)]
    
    #do recap
    results['time_elapsed'] = time.time() - starttime
    recap = scanner.get_dac_recap(results)
    results['repos_scanned'] = recap['repos_scanned']
    results['vulnerable'] = recap['vulnerable']
    results['sus'] = recap['sus']
    scanner.write_output_file(resultsfile, results)

@dazed_and_confused.command('full', short_help='scans orgs on a public or private github instance')
@click.option("-resultsfile", "-rf", required=True, help="file for results")
@click.option('--conc', "-c", default=200, show_default=True, help='Number of concurrent repo scans per org (higher for servers, lower for desktop/laptops)')
@click.option('--procs', default=3, show_default=True, help='Number of concurrent processes to use for scanning orgs (roughly, how many cores to use)')
def full(resultsfile, conc, procs):
    """ The [full] command scans all available organizations on a github server """
    scanner = GHScanner(conc, procs)
    starttime = time.time()
    results = scanner.scan_all_orgs()

    #do recap    
    recap = scanner.get_dac_recap(results)
    results['repos_scanned'] = recap['repos_scanned']
    results['vulnerable'] = recap['vulnerable']
    results['sus'] = recap['sus']
    results['orgs'] = sorted(results['orgs'], key = lambda i: str.casefold(i['org']))
    scanner.write_output_file(resultsfile, results)                

if __name__ == '__main__':
    dazed_and_confused()
