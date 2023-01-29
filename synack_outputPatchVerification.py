import json
import os
import sys
import time
from synack import synack

'''
Description: main function where program flow begins
Error Handling: the error handling is intentionally minimal.  If any errors are detected, either for input validation reasons or API request reasons, the program will exit.
Inputs: None
Outputs: None
'''
if __name__ == '__main__':
    def_fileout_base = "synack_patches_"
    env_api = "SYNACK_TOKEN"
    token = os.getenv(env_api,"")
    if token == "":
        synack.init_env()
        token = synack.get_api_key(env_api,bool("true"))

    w_fileout = os.path.dirname(os.path.realpath(__file__))
    w_ffileout = w_fileout + "\\" + def_fileout_base + time.strftime("%Y%m%d") + ".json"

    mylist=["cerberustardigrade-001-56","cerberusbugbug-5"]
    patchdata={}
    #for item in mylist:
    #    if item not in patchdata:
    #        response = synack.get_patch_verifications(item,token)
    #        patchdata.update({item:response})
    #print(json.dumps(patchdata,indent=3))


    #print(json.dumps(synack.get_patch_verifications("cerberustardigrade-001-56",token),indent=3))
    #print(json.dumps(synack.get_patch_verifications("cerberusbugbug-5", token),indent=3))
    #cerberusbugbug-5

    #vulns = synack.get_vulnerabilities(token, "cerberustardigrade-001-56")
    #vulns.append(synack.get_vulnerabilities(token, "cerberusbugbug-5"))

    stdout = open(sys.__stdout__.fileno(),
                  mode=sys.__stdout__.mode,
                  buffering=1,
                  encoding=sys.__stdout__.encoding,
                  errors=sys.__stdout__.errors,
                  newline='\n',
                  closefd=False)

    patchdata = {}
    vulns = synack.get_vulnerabilities(token)
    for vuln in vulns:
        if vuln['id'] not in patchdata:
            response = synack.get_patch_verifications(vuln['id'], token)
            patchdata.update({vuln['id']: response})

    with open(w_fileout, "w") as outfile:
        json.dump(patchdata, outfile)