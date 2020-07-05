from optparse import OptionParser
from os import path
import csv
import requests
import json
import central_oauth

# Set your credentials.
client_id = ""
client_secret = ""
vt_api = ""

# Get the stuff you need
jwt, tenant_id, tenant_type, data_region = central_oauth.Authenticate.auth(client_id, client_secret)

def check_vt(sha):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {
            'apikey': f'{vt_api}', 
            'resource': f'{sha}'
            }
    r = requests.get(url, params=params)
    if r.status_code == 200:
        j = json.loads(r.text)
        return j


def post_blocked_item(sha, comment):
    # use the api_creds to go to the correct URL
    uri = f'{data_region}/endpoint/v1/settings/blocked-items'
    # Set the headers.
    h = {
        'Authorization': f'Bearer {jwt}',
        'X-Tenant-ID': f'{tenant_id}'
        }
    # Set the params
    p = {
        "type": "sha256",
        "properties": {
            "sha256": f"{sha}"
        },
        "comment": f"{comment}",
        }
    # Run the initial request
    r = requests.post(uri, headers=h, json=p)
    # Make it JSON to make it easier.
    j = json.loads(r.text)
    print(j)


def add_to_central(**kwargs):
    # If filename is set loop through
    if kwargs.get('filename'):
        # Open File
        f = open(kwargs.get('filename'))
        # read 
        reader = csv.reader(f)
        # Loop through csv
        for row in reader:
            # If Virus Total is selected
            if kwargs.get('virustotal'):
                # Run check_vt to get a response
                vt = check_vt(row[0])
                # If the response code is 1 then it's been scanned
                if vt['response_code'] == 1:
                    if vt['scans']['Sophos']['detected']:
                        # Detected So Skip
                        print('detected by sophos')
                    else:
                        # Known to Virus total not detected by SOPHOS on VirusTotal
                        post_blocked_item(row[0], row[1])
                else:
                    # Not known to Virus Total so add it to Central
                    post_blocked_item(row[0], row[1])
            # if virus total isn't set
            else:
                # post to central
                post_blocked_item(row[0], row[1])
        # Close File
        f.close()

    # If SHA is set then add the one off
    if kwargs.get('sha'):
        # If Virus Total is selected
        if kwargs.get('virustotal'):
            # Run check_vt to get a response
            vt = check_vt(kwargs.get('sha'))
            # If the response code is 1 then it's been scanned
            if vt['response_code'] == 1:
                if vt['scans']['Sophos']['detected']:
                    # Detected So Skip
                    print('detected by sophos')
                else:
                    # Known to Virus total not detected by SOPHOS on VirusTotal
                    post_blocked_item(kwargs.get('sha'), kwargs.get('comment'))
            else:
                # Not known to Virus Total so add it to Central
                post_blocked_item(kwargs.get('sha'), kwargs.get('comment'))
        # if virus total isn't set
        else:
            # post to central
            post_blocked_item(kwargs.get('sha'), kwargs.get('comment'))


if __name__ == "__main__":

    # Setup usage
    usage = "usage: --file FILENAME --virustotal --sha SHA --comment COMMENT --output FILENAME"
    # Set Usage and initialise option parser
    parser = OptionParser(usage=usage)
    # Set the options
    parser.add_option("-f", "--file", dest="filename",
                    help="File to import to SOPHOS Central, this should be a CSV formatted: sha256, comment")
    parser.add_option("-o", "--output", dest="output",
                    help="File to output report too. Not yet implimented")
    parser.add_option("-s", "--sha", dest="sha",
                    help="A SHA to quickly add to SOPHOS Central if no CSV is provided")
    parser.add_option("-c", "--comment", dest="comment",
                    help="A comment for the SHA that's being added to SOPHOS Central used in conjunction with -sha")
    parser.add_option("-v", "--virustotal", dest="virustotal",
                    help="Check for detection against virus total before submitting to SOPHOS Central",
                    action="store_true", default=False)

    (options, args) = parser.parse_args()
    # If SHA is set then do a once off
    if options.sha:
        # If description is none then bail out
        if options.comment is None:
            # Error out
            parser.error(msg="A comment is needed when parsing a SHA")
        # Else Add to central
        add_to_central(sha=options.sha, comment=options.comment)

    # Else if filename is set loop through.
    elif options.filename:
        # check to see if a path exists
        if path.isfile(path=options.filename):
            # Add to central
            add_to_central(filename=options.filename)
        # If path doesn't exist
        else:
            # Error out
            parser.error(msg="Path doesn't exist")
    else:
        parser.error(msg="Needed arguments missing")