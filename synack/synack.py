import json
import csv
import os
import requests
import warnings
import contextlib
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning


# SET VARIABLES
APIKEY_ENV = "SYNACK_TOKEN"                                #THE VALUE OF THIS ENV VARIABLE TAKES PRECEDENT OVER KEYFILE_DEF
KEYFILE_DEF = os.path.dirname(os.path.realpath(__file__))  #CHANGE THIS TO THE PROPER LOCATION.
DOMAIN = 'https://api.ks-fedprod.synack.com'

'''
Description: Function taken from "https://stackoverflow.com/questions/15445981/how-do-i-disable-the-security-certificate-check-in-python-requests" to clear up error messages
Inputs: contextlib.contextmanager class definition
Outputs: redefined no_ssl_verification() function (decorator)
'''
@contextlib.contextmanager
def no_ssl_verification():
    old_merge_environment_settings = requests.Session.merge_environment_settings
    opened_adapters = set()
    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        # Verification happens only once per connection so we need to close
        # all the opened adapters once we're done. Otherwise, the effects of
        # verify=False persist beyond the end of this context manager.
        opened_adapters.add(self.get_adapter(url))
        settings = old_merge_environment_settings(self, url, proxies, stream, verify, cert)
        settings['verify'] = False
        return settings
    requests.Session.merge_environment_settings = merge_environment_settings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', InsecureRequestWarning)
            yield
    finally:
        requests.Session.merge_environment_settings = old_merge_environment_settings
        for adapter in opened_adapters:
            try:
                adapter.close()
            except:
                pass


'''
Description: Assumes that connection may/may not have VPN enabled and so toggles between INT_TOKEN & EXT_TOKEN
Inputs: none
Outputs: none
'''
def get_api_key(verbose=bool()):
    url = DOMAIN + "/v1/"
    tokens={}
    keyfile = Path(KEYFILE_DEF + "/.keys")
    if keyfile.exists:
        with open(keyfile, newline='') as keys:
            records = csv.reader(keys)
            for row in records:
                if row[0] != "" and row[0][0:1] != "#":
                    tokens[row[0]] = row[1]
        if verbose:
            print()
            print("- Testing Tokens")
        with no_ssl_verification():
            for tok in tokens:
                headers = {"Authorization": "Bearer " + tokens[tok]}
                r = requests.get(url, headers=headers)
                if r.status_code == 200:
                    if verbose:
                        print("   - USING " + tok)
                    os.environ[APIKEY_ENV] = tokens[tok]
                    return tokens[tok]
                else:
                    if verbose:
                        print("   - " + tok + " failed")
            if verbose:
                print("[!] Error with API Tokens")
            else:
                raise Exception("[!] Error with API Tokens")
            exit(0)
    else:
        if verbose:
            print("[!] Unable to find KEYFILE. Either set the %s environment variable, or modify the default in the code." % (APIKEY_ENV))
            exit(0)
        else:
            raise Exception("[!] Unable to find KEYFILE. Either set the %s environment variable, or modify the default in the code." % (APIKEY_ENV))


'''
Description: Makes API request to /v1/vulnerabilities to pull all vulnerabilities associated with search filter
Inputs: Codename as search filter
Outputs: All tags as a dictionary
'''
def get_vulnerabilities(apitoken="", searchfilter="",verbose=bool()):
    if apitoken=="":
        apitoken = get_api_key()
    page = 1
    pagesize = 50
    url = DOMAIN + "/v1/vulnerabilities"
    headers = { "Authorization": "Bearer " + apitoken }
    params = { "page[size]": pagesize, "page[number]": page, "filter[search]": searchfilter} # "filter[updated_since]": "2020-05-26T16:38:12Z", "filter[status_id][]": [1, 2] }
    with no_ssl_verification():
        r = requests.get(url, headers=headers, params=params)
        if r.status_code == 200:
            xpaging = json.loads(r.headers['x-pagination'])
            if verbose :
                print("Returned page %i of %i. Total Records = %i" % (xpaging['current_page'],xpaging['total_pages'], xpaging['total_entries'],))
            if xpaging['total_pages'] > 1:
                j = r.json()
                for page in range(2,xpaging['total_pages']+1):
                    params = {"page[size]": pagesize, "page[number]": page, "filter[search]": searchfilter}
                    r = requests.get(url, headers=headers, params=params)
                    xpaging = json.loads(r.headers['x-pagination'])
                    if verbose:
                        print("Returned page %i of %i. Total Records = %i" % (xpaging['current_page'],xpaging['total_pages'], xpaging['total_entries'],))
                    for item in r.json():
                        j.append(item)
                return j
            else:
                return r.json()
        else:
            if verbose:
                print("Error",r.status_code,r.reason)
            r.raise_for_status()

'''
Description: Makes API request to /v1/vulnerabilies/{ID}/patch_verifications to pull any verification requests
Inputs: apitoken
Outputs: All tags as a dictionary
'''
def get_patch_verifications(tagid, apitoken="",verbose=bool()):
    if apitoken == "":
        apitoken = get_api_key()
    url = DOMAIN + "/v1/vulnerabilities/" + tagid + "/patch_verifications"
    if verbose:
        print("-" + url)
    headers = {"Authorization": "Bearer " + apitoken}
    with no_ssl_verification():
        r = requests.get(url, headers=headers, verify=False)
        if r.status_code == 200:
            return r.json()  # parse JSON payload
        elif r.status_code == 404:
            if verbose:
                    print(tagid + " has no patch verification requests")
            return ""
        else:
            print(r.status_code)
            return ""

'''
Description: Makes API request to /v1/vulnerability_tags to pull all tags
Inputs: apitoken
Outputs: All tags as a dictionary
'''
def get_all_tags(apitoken=""):
    if apitoken == "":
        apitoken = get_api_key()
    url = DOMAIN + "/v1/vulnerability_tags"
    headers = {"Authorization": "Bearer " + apitoken}
    with no_ssl_verification():
        return requests.get(url, headers=headers).json()

'''
Description: Makes API request to /v1/vulnerability_tags to rename a specific tag
Inputs: tagid, new tagname, apitoken
Outputs: All tags as a dictionary
'''
def rename_tag(tagid, newtagname, apitoken=""):
    if tagid != "" and newtagname !="":
        if apitoken == "":
            apitoken = get_api_key()
        url = "%s/v1/vulnerability_tags/%i" % (DOMAIN,tagid)
        headers = {"Authorization": "Bearer " + apitoken}
        params = {"name": newtagname}
        with no_ssl_verification():
            r = requests.put(url, headers=headers, data=json.dumps(params), verify=False)

        try:
          r.raise_for_status()
          return r.status_code
        except requests.exceptions.HTTPError as e:
          print(e)
          return r.status_code
'''
Description: Makes API request to /v1/vulnerabilities/:id to see if 
Inputs: Codename or VulnID as input to test
Outputs: True if input is a vulnerability
'''
def isVulnerability(apitoken="", testName=""):
    if testName != "":
        if apitoken == "":
            apitoken = get_api_key()
        url = DOMAIN + "/v1/vulnerabilities/" + testName
        headers = {"Authorization": "Bearer " + apitoken}
        with no_ssl_verification():
            r = requests.get(url, headers=headers, verify=False)
            if r.status_code == 200:
                return bool("true")
            elif r.status_code == 404:
                return bool("")
            else:
                exit(0)
    else:
        exit(0)