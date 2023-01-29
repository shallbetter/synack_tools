#!/usr/bin/env python

import json
import warnings
import contextlib


import requests
from urllib3.exceptions import InsecureRequestWarning

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


EXT_TOKEN='gut8xlYaChFVQ81KFPgpeu0_4dADX38ZJlCb6YhoDVEMozJGYfHYFtZiyN2VD242lQVGgkA8BXcZcJ4Azh_4Tw' #98.169.248.65
INT_TOKEN='IBeoWSNgqziO0VZkPTuUv7uBC9tuikCfFg0au4obK6d4xOC_Op2sJF1bplITmBjUf47I0kh8fOWezSbsB1stjQ' #162.99.222.213


TOKEN = EXT_TOKEN
DOMAIN = 'https://api.ks-fedprod.synack.com/v1/'

#98.169.250.15: V9EJZYojST1Yg096NsZI-CqCtsO996WTxb0ckiC5TEY6nLvOMR0kRP5VSC9bHRMF2zSepquVdFU3AuDLi_kYuQ
#162.99.222.213: d

api_url_base = 'https://api.ks-fedprod.synack.com/v1/'


headers = { "Authorization": "Bearer dq8fGWaEiRHeGvGkeOKh8M7VhM4Jg9awOlL4Bz2DcNe5u0j_x7NQBY-VbZ8NFOKawVLkEcNsI_O_tg-6dSNyzg" }
#params = { "page[size]": 5, "page[number]": 2, "filter[search]": "XSS", "filter[updated_since]": "2020-04-07T23:35:21Z", "filter[status_id][]": [1, 2] }
params_A = "" # { "filter[search]": "CERBERUSCICADA" }
tags = [ 2170 ]
params_B = { "tags": tags }

# return 5 vulnerabilities (on page 2) updated since 2020-04-07T23:35:21Z (sorted by the resolved_at timestamp) with vulnerability status ID of 1 or 2 containing the term 'XSS'
r = requests.get('https://api.synack.com/v1/vulnerabilities', headers=headers, params=params_A, verify=False)


def get_vulnerabilities(searchfilter=""):
  page = 1
  api_url = DOMAIN + "vulnerabilities"
  headers = {"Authorization": "Bearer " + TOKEN}
  params = {"page[size]": 200, "page[number]": page,
            "filter[search]": searchfilter}  # "filter[updated_since]": "2020-05-26T16:38:12Z", "filter[status_id][]": [1, 2] }
  with no_ssl_verification():
    r = requests.get(api_url, headers=headers, params=params)
    if r.status_code == 200:
      xpaging = json.loads(r.headers['x-pagination'])
      print(
        f"Returned page {xpaging['current_page']} of {xpaging['total_pages']}. Total Records = {xpaging['total_entries']}")
      if xpaging['total_pages'] > 1:
        j = r.json()
        for page in range(2, xpaging['total_pages'] + 1):
          params = {"page[size]": 200, "page[number]": page}
          r = requests.get(url, headers=headers, params=params)
          xpaging = json.loads(r.headers['x-pagination'])
          print(
            f"Returned page {xpaging['current_page']} of {xpaging['total_pages']}. Total Records = {xpaging['total_entries']}")
          for item in r.json():
            j.append(item)
        return j
      else:
        return r.json()
    else:
      r.raise_for_status()

if __name__ == '__main__':

  try:
    vulns=get_vulnerabilities("CERBERUSResponsibleDisclosure")
    print()
    print("id|cvss|created_at|closed_at|workflow_status|status|title")
    for vuln in vulns:
      if vuln["vulnerability_status"]["flow_type"] !=2:
        status="open"
      else:
        status="closed"
      print(vuln['id'], "|", vuln['cvss_final'], "|", vuln["vulnerability_status"]["created_at"][0:10], "|", vuln["resolved_at"][0:10],"|",vuln["vulnerability_status"]["text"],"|",status, "|", vuln['title'])
  except requests.exceptions.HTTPError as e:
    print (e.message)