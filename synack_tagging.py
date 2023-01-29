import requests
import csv
import os
import sys
from synack import synack

DOMAIN = 'https://api.ks-fedprod.synack.com'
global TOKEN
global TAGDATA

def return_tagid(new_tags):
    if new_tags == '':
        return

    if isinstance(new_tags, list) and len(new_tags)==1 and "," in new_tags[0]:
        new_tags=new_tags[0]

    if isinstance(new_tags, str):
        if "," in new_tags:                 # if there is a comma present, assume that there are multiple tabs
            new_tags = new_tags.split(",")  # fancy way of trimming all whitespace and junk off of each string in the list
        else:       # otherwise make a list with a single tag element in it (since the rest of the code handles a list
            new_tags = [new_tags]
    elif isinstance(new_tags, list):
        pass
    else:
        print("Unexpected Data Type", type(new_tags))
        return

    idtag=[]
    for item in TAGDATA:
        for tag in new_tags:
            if item["name"] == tag:
                idtag.append(item["id"])
    if len(idtag) == 0:
        print("Error: Provided Tag(s) do not exist in Synack.")
        raise RuntimeError
    elif len(idtag)!= len(new_tags):
        print("ALERT: Not all provided tags exist in Synack. Only existing tags will be added.")
    return idtag
'''
Description: Makes API call to https://api.synack.com/v1/vulnerabilities in order to apply tags to specified 
    vulnerabilities
Inputs: vuln_id (as String) with the vuln number, new_tags (as a list) 
Outputs: None
'''
def tag_vuln(vuln_id, new_tags):
    headers = { "Authorization": "Bearer " + TOKEN }
    if isinstance(new_tags,str):
        if "," in new_tags: #if there is a comma present, assume that there are multiple tabs
            new_tags = map(str.strip, new_tags.split(",")) #fancy way of trimming all whitespace and junk off of each string in the list
        else: #otherwise make a list with a single tag element in it (since the rest of the code handles a list
            new_tags = [new_tags]
    elif isinstance(new_tags,list):
        pass
    else:
        print("Unexpected Data Type",type(new_tags))
        return
    if tag_preserve:
        for tag in new_tags:
            with synack.no_ssl_verification():
                url = DOMAIN + "/v1/vulnerability_tags"
                data = {"name": tag, "vulnerability_id": vuln_id}
                r = requests.post(url, headers=headers, json=data, verify=False)
                if r.status_code == 200 or r.status_code == 201:
                    print("   ", "Successfully tagged " + vuln_id, tag)
                elif r.status_code == 404:
                    print("   ", "Insufficient Privilege to create tag: " + str(data))
                elif r.status_code == 400:
                    pass
                    print("   ", "Tag name is missing or is invalid (e.g. exists already): " + str(data))
                else:
                    print(r.status_code, r.reason)
    else:
        tagparam="?"
        for tag in new_tags:
            tagparam = "%stags[]=%i&" % (tagparam,tag)
        with synack.no_ssl_verification():
            url = DOMAIN + '/v1/vulnerabilities/' + vuln_id + tagparam
            r = requests.put(url, headers=headers, verify=False)
            if r.status_code == 200:
                print("  ","Successfully tagged " + vuln_id, new_tags)
            else:
                print("   ERROR (%i) while attempting to update %s %s: %s" % (r.status_code,vuln_id,new_tags,r.reason))
                r.raise_for_status

'''
Description: Parses the commandline for options
Inputs: none
Outputs: None
'''
def parse_commandline():
    global inputfile
    global tag_preserve
    global tag_single
    global tag_targetid
    global tag_append
    global tag_tags
    inputfile = ""
    tag_append = bool("")
    tag_preserve = bool("True")
    tag_single = bool("")
    tag_targetid=""
    tag_tags = []

    if len(sys.argv)>1:
        i=1
        while i < len(sys.argv):
            if sys.argv[i].lower() == "-h" or sys.argv[i].lower() == "--help":
                print("")
                print("USAGE: synack_tagging.py -h -p -f {inputfile} | {VULNID|ASSESSMENTID TAGNAME TAGNAME TAGNAME}")
                print("     -h | --help         This help statement")
                print("     -f | --file         Full Path to csv of assessments|vulnerability & tag pairs. ")
                print("                         Defaults to ./synack/synack_tagging.csv")
                print("     -a | --append       Tag already tagged records again (default is blank only)")
                print("     -r | --replace      Replace existing tags (default is preserve tags)")
                print("")
                print("EXAMPLE:")
                print("         synack_tagging.py CERBERUSEXAMPLE ORG:OS (apply same tag to entire assessment)")
                print("         synack_tagging.py CERBERUSEXAMPLE-2 ORG:OS SYS:OS_ENMS  (apply same tag to single vulnerability)")
                print("         synack_tagging.py CERBERUSEXAMPLE-2 ORG:OS,SYS:OS_ENMS  (apply same tag to single vulnerability)")
                exit(0)
            elif sys.argv[i].lower() == "-f" or sys.argv[i].lower() == "--file":
                i=i+1
                try:
                    inputfile=sys.argv[i]
                    i=i+1
                except:
                    inputfile = "synack\synack_tagging.csv"
                    inputfile = os.getcwd() + "\\" + inputfile
            elif sys.argv[i].lower() == "-a" or sys.argv[i].lower() == "--append":
                tag_append = bool("True")
                i = i + 1
            elif sys.argv[i].lower() == "-r" or sys.argv[i].lower() == "--replace":
                tag_preserve = bool("")
                i=i+1
            else:
                tag_single = bool("true")
                tag_targetid = sys.argv[i]
                i=i+1
                try:
                    while i < len(sys.argv):
                        if sys.argv[i][0:1] != "-":
                            for t in sys.argv[i].split(","):  # Method to handle a comma delim input
                                tag_tags.append(t)
                            i = i + 1
                        else:
                            break
                except:
                    print("No tags provided after assessment or vulnerability name: try -h or --help for information")
                    exit(0)
        if tag_targetid !="" and len(tag_tags)==0:
            print("No tags provided after assessment or vulnerability name: try -h or --help for information")
            exit(0)
    else:
        inputfile = "synack\synack_tagging.csv"
        inputfile = os.path.dirname(os.path.realpath(__file__)) + "\\" + inputfile


'''
Description: main function where program flow begins
Error Handling: the error handling is intentionally minimal.  If any errors are detected, either for input validation reasons or API request reasons, the program will exit.
Inputs: None
Outputs: None
'''
if __name__ == '__main__':
    parse_commandline() # parse the commandline for changes to behavior
    print("")
    print("SYNACK_API",os.getenv('SYNACK_API', "<empty>"))

    TOKEN = synack.get_api_key("True")  # call set_api_key to check connectivity and set proper key
    TAGDATA = synack.get_all_tags(TOKEN)  # call set_all_tags to establish the tag list

    print("")
    print("    Input File:",inputfile)
    print(" Preserve tags:",tag_preserve)
    print("Tagging Single:",tag_single)
    if tag_single:
        print("     Target id:", tag_targetid)
        print(" Target Tag(s):", tag_tags)
    print("")
# CONSIDER PUTTING A WAIT STOP HERE TO ALLOW CORRECTION
    if tag_single:
        if not(tag_preserve): tag_tags = return_tagid(tag_tags)     # Use Tag Name or Tag Id depending on approach
        if synack.isVulnerability(TOKEN, tag_targetid):
            tag_vuln(tag_targetid,tag_tags)
        else:
            vulns = synack.get_vulnerabilities(TOKEN, tag_targetid)
            if len(vulns):
                for vuln in vulns:
                    if tag_append or not(tag_preserve) or len(vuln['tag_list']) == 0:
                        tag_vuln(vuln['id'], tag_tags)
                    else:
                        print(f" [-] {vuln['id']} already tagged with {','.join('{0}'.format(vd['name']) for vd in vuln['tag_list'])}")
            else:
                print(f"No records found for {tag_targetid}")
    else:
        if os.path.isfile(inputfile):
            with open(inputfile, newline='') as csvfile:
                records = csv.reader(csvfile)
                for row in records:
                    if len(row) > 0 and row[0][0:1] != "#":
                        if row[0].lower()[:8] == "cerberus": #IGNORE ANYTHING OTHER THAN CERBERUS NAMES.
                            if synack.isVulnerability(TOKEN, row[0].lower()):
                                if tag_preserve:  # if using admin access then use a separate call
                                    tagid = row[1:]
                                else:
                                   tagid = return_tagid(row[1:])
                                tag_vuln(row[0].lower(), tagid)
                            else:
                                vulns = synack.get_vulnerabilities(TOKEN, row[0].upper())
                                if len(vulns):
                                    print("Found %i vulnerabilities in %s. Tagging with %s" % (
                                    len(vulns), row[0].lower(), row[1:]))
                                    for vuln in vulns:
                                        if tag_append or len(vuln['tag_list'])==0:
                                            if tag_preserve:                    # if preserving tags then use Name ...
                                                tagid = row[1:]
                                            else:
                                                tagid = return_tagid(row[1:])   # ...otherwise convert to id value
                                            tag_vuln(vuln['id'],tagid)
                                        else:
                                            print(f" [-] {vuln['id']} already tagged with {','.join('{0}'.format(vd['name']) for vd in vuln['tag_list'])}")
                                else:
                                    print(f"{row[0].upper()} has no vulnerabilities reported")
        else:
            print("Error: File not found: " + inputfile)