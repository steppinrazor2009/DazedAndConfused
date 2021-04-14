#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import time
import click
from glscanner import GLScanner

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
#default func when called
def dazed_and_confused():
    """ Dazed and Confused is a tool for scanning Github, Gitlab, and Swarm for instances of dependency confusion """
    pass

@dazed_and_confused.command('single', short_help='scans a single project in a gitlab instance')
@click.option("-projectid", "-p", required=True, help="project id")
@click.option("-resultsfile", "-rf", required=True, help="file for results")
def single(projectid, resultsfile):
    """ The [single] command scans a single gitlab project """
    scanner = GLScanner()
    starttime = time.time()
    results = {'projects_scanned': 1, 'vulnerable': 0, 'sus': 0, 'time_elapsed': 0, 'projects': []}
    singleresult = [scanner.check_single_project(projectid)]
    results['projects'] = singleresult
                    
    #do recap
    results['time_elapsed'] = time.time() - starttime
    recap = scanner.get_dacgl_recap(results)
    results['vulnerable'] = recap['vulnerable']
    results['sus'] = recap['sus']
    scanner.write_output_file(resultsfile, results)
    

@dazed_and_confused.command('full', short_help='scans all projects in a gitlab instance')
@click.option("-resultsfile", "-rf", required=True, help="file for results")
@click.option('--conc', "-c", default=200, show_default=True, help='Number of concurrent repo scans per org (higher for servers, lower for desktop/laptops)')
def full(resultsfile, conc):
    """ The [full] command scans all available projects on a gitlab server """
    scanner = GLScanner(conc)
    starttime = time.time()
    results = scanner.scan_all_projects()
    
    #do recap
    results['time_elapsed'] = time.time() - starttime
    recap = scanner.get_dacgl_recap(results)
    results['vulnerable'] = recap['vulnerable']
    results['sus'] = recap['sus']
    results['projects_scanned'] = recap['projects_scanned']    
    scanner.write_output_file(resultsfile, results) 


if __name__ == '__main__':
    dazed_and_confused()
