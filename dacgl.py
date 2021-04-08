import dacfunctions.dac_constants as dac_constants
import dacfunctions.dac_io as dac_io
import dacfunctions.dacgl.dacgl_single as dacgl_single
import dacfunctions.dacgl.dacgl_full as dacgl_full
import time
import json
import click

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
    starttime = time.time()
    results = {'projects_scanned': 1, 'vulnerable': 0, 'sus': 0, 'time_elapsed': 0, 'projects': []}
    singleresult = [dacgl_single.check_single_project(projectid)]
    results['projects'] = singleresult
                    
    #do recap
    results['time_elapsed'] = time.time() - starttime
    recap = dac_constants.get_dacgl_recap(results)
    results['vulnerable'] = recap['vulnerable']
    results['sus'] = recap['sus']
    dac_constants.write_output_file(resultsfile, results)

@dazed_and_confused.command('full', short_help='scans all projects in a gitlab instance')
@click.option("-resultsfile", "-rf", required=True, help="file for results")
@click.option('--conc', "-c", default=200, show_default=True, help='Number of concurrent repo scans per org (higher for servers, lower for desktop/laptops)')
def full(resultsfile, conc):
    """ The [full] command scans all available projects on a gitlab server """
    starttime = time.time()
    results = dacgl_full.scan_all_projects(conc)
    dac_constants.write_output_file(resultsfile, results) 

if __name__ == '__main__':
    dazed_and_confused()
