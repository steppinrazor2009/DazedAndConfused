#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import dacfunctions.dac_contentscan as dac_contentscan
import dacfunctions.dac_constants as dac_constants
import time
import json
import click
import os

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
#default func when called
def dazed_and_confused():
    """ Dazed and Confused is a tool for scanning Github, Gitlab, and Swarm for instances of dependency confusion """
    pass

#checks a single file for dependency confusion
@dazed_and_confused.command('file', short_help='scans a single manifest file locally')
@click.option("-filename", "-f", required=True, help="file name")
@click.option("-resultsfile", "-rf", required=True, help="results file name")
def check_file(filename, resultsfile):
    """ The [file] command scans a single manifest file locally """
    try:
        with open(file,"r") as f:
            data = f.read()
        singleresult = dac_contentscan.scan_contents(os.path.basename(filename), data)
        jsonoutput = json.dumps(singleresult, indent=4)
        dac_constants.write_output_file(resultsfile, jsonoutput)
    except Exception as e:
        print(f"Error: {e} in check_file")

#checks a single url for dependency confusion
@dazed_and_confused.command('url', short_help='scans a single manifest file via url')
@click.option("-manifestname", "-mn", required=True, help="manifest file name (e.g. package.json)")
@click.option("-url", "-u", required=True, help="file url")
@click.option("-resultsfile", "-r", required=True, help="results file name")
def check_url(manifestname, url, resultsfile):
    """ The [url] command scans a single manifest file via url """
    try:
        data = urllib.request.urlopen(url).read().decode('ascii')
        dac_contentscan.scan_contents(os.path.basename(file), data)
        jsonoutput = json.dumps(singleresult, indent=4)
        dac_constants.write_output_file(resultsfile, jsonoutput)
    except Exception as e:
        print(f"Error: {e} in check_url")

if __name__ == '__main__':
    dazed_and_confused()        
