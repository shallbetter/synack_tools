#!/usr/bin/env python
'''
*DISCLAIMER* - This script is presented by Synack as a demonstration of the tagging
API functions and how to scale them to multiple vulnerabilities.
This script is considered to be a "use at will" demonstration and
should not be considered to be a supported product by Synack, INC.

Developed by Trent Gordon and Jeremiah Roe
'''

import json
import requests
from pip._vendor.distlib.compat import raw_input
from collections import defaultdict
from consolemenu import SelectionMenu
from synack import synack



'''
Global Variables:
TOKEN is the API token generated by the portal.  The API token MUST correspond to an "Admin" user. 
DOMAIN is a configuration variable and needs to be changed to reflect the current API domain being used by the client (currently the demo domain for debug purposes
PROMPT is a formatting variable to customize the input prompt for user input.
'''

OUTPUTFILENAME="tests"

global TOKEN
DOMAIN = 'https://api.ks-fedprod.synack.com'
PROMPT = "==>"
codenames = defaultdict(list)

def print_container(input_list):
    if type(input_list) is dict:
        print (str(input_list['name']))
    elif type(input_list) is list:
        for item in input_list:
            print (str(item))

'''
Description: Makes API request to /v1/vulnerability_tags to pull all tags
Inputs: None
Outputs: All tags as a dictionary
'''
def get_all_tags():
    url = DOMAIN + "/v1/vulnerability_tags"
    headers = {"Authorization": "Bearer " + TOKEN}
    with synack.no_ssl_verification():
        return requests.get(url, headers=headers).json()

def add_user (new_user, asessmentList):
    url = DOMAIN + "/v1/users"
    headers = { "Authorization": "Bearer " + TOKEN }
    isAdmin = False
    sendInvite = True

    if new_user == "": #if the new_tag option wasnt explicitly set in the function call, then prompt the user now
        print ("[*] Enter the user\'s email. To add multiple users, separate them with a comma (i.e. foo@bar, boo@hiss)")
        new_user = str(raw_input(PROMPT))
    if "," in new_user:
        new_users = map(str.strip, new_user.split(",")) #fancy way of trimming all whitespace and junk off of each string in the list
    else: #otherwise make a list with a single tag element in it (since the rest of the code handles a list
        new_users = [new_user]

    print("[*] Please enter an assessment codename or id, then, press 'Enter'")
    assessment = raw_input(PROMPT).upper()
    try:
        print("%s is the Id for %s" % (assessment, codenames[assessment][0]))
    except:
        for key, value in codenames.items():
            if value[0] == assessment:
                assessment = key
                break
            pass
        
    for user in new_users:
        data = { "email": user, "admin": isAdmin, "assessments": assessment, "send_invite": sendInvite }
        with synack.no_ssl_verification():
            r = requests.post(url, headers=headers, json=data,verify=False)


def get_vulnerabilities(searchfilter=""):
    page = 1
    pagesize = 50
    url = DOMAIN + "/v1/vulnerabilities"
    headers = { "Authorization": "Bearer " + TOKEN }
    params = { "page[size]": pagesize, "page[number]": page, "filter[search]": searchfilter} # "filter[updated_since]": "2020-05-26T16:38:12Z", "filter[status_id][]": [1, 2] }
    with synack.no_ssl_verification():
        r = requests.get(url, headers=headers, params=params)
        if r.status_code == 200:
            xpaging = json.loads(r.headers['x-pagination'])
            print(f"Returned page {xpaging['current_page']} of {xpaging['total_pages']}. Total Records = {xpaging['total_entries']}")
            if xpaging['total_pages'] > 1:
                j = r.json()
                for page in range(2,xpaging['total_pages']+1):
                    params = {"page[size]": pagesize, "page[number]": page}
                    r = requests.get(url, headers=headers, params=params)
                    xpaging = json.loads(r.headers['x-pagination'])
                    print(f"Returned page {xpaging['current_page']} of {xpaging['total_pages']}. Total Records = {xpaging['total_entries']}")
                    for item in r.json():
                        j.append(item)
                return j
            else:
                return r.json()
        else:
            r.raise_for_status()

'''
Description: Makes API request to /v1/vulnerabilities to pull all user data for the account
Inputs: None
Outputs: All vulnerabilities and their information as a dictionary
'''
def get_all_codenames():
    assments = get_all_assessments()
    for assment in assments:
        slug = assment['id']
        codename = assment['codename']
        if not codenames[slug]:
            codenames[slug].append(codename)
    return codenames

'''
Description: Makes API request to /v1/users to pull all user data for the account
Inputs: None
Outputs: All vulnerabilities and their information as a dictionary
'''
def get_all_users():
    url = DOMAIN + "/v1/users"
    headers = { "Authorization": "Bearer " + TOKEN }
    with synack.no_ssl_verification():
        return requests.get(url, headers=headers).json()


'''
Description: Makes API request to /v1/assessments to pull all assessments
Inputs: None
Outputs: All vulnerabilities and their information as a dictionary
'''
def get_all_assessments():
    url = DOMAIN + "/v1/assessments"
    headers = {"Authorization": "Bearer " + TOKEN}
    with synack.no_ssl_verification():
        return requests.get(url, headers=headers).json()

'''
Description: Makes API request to /v1/assessments/[ASSESSID]
Inputs: None
Outputs: the json data for a vulnerability.  If invalid ASSESSID, returns None
'''
def get_single_assessment(assess_id = ""):
    headers = { "Authorization": "Bearer " + TOKEN }
    if assess_id == "":
        assess_id = raw_input(PROMPT)
    url = DOMAIN + '/v1/assessments/' + vuln_id
    with synack.no_ssl_verification():
        assessment = requests.get(url, headers=headers)
        if assessment.status_code == 404:
            print ("[!] No Assessments found with that ID")
            return None
        else:
            return assessment.json()

'''
Description: Makes API call to https://api-demo.synack.com/v1/vulnerability_tags in order to apply tags to specified vulnerabilities
Inputs: vuln_id (as String) with the vuln number, show_tags (as optional Boolean) to select if previous tags for the Vuln in question should be displayed, new_tag (optional String) if you dont want to UI prompt for a new tag and want to automatically asing one
Outputs: None
'''
def tag_single_vuln(vuln_id, new_tag = ""):
    headers = { "Authorization": "Bearer " + TOKEN }
    new_tags = []
    if new_tag == "": #if the new_tag option wasnt explicitly set in the function call, then prompt the user now
        print ("[*] Enter a new tag to assign to " + vuln_id+ ". To assign multiple tags, separate them with a comma (i.e. foo, bar, boo, hiss)")
        new_tag = str(raw_input(PROMPT))
    if "," in new_tag: #if there is a comma present, assume that there are multiple tabs
        new_tags = map(str.strip, new_tag.split(",")) #fancy way of trimming all whitespace and junk off of each string in the list
    else: #otherwise make a list with a single tag element in it (since the rest of the code handles a list
        new_tags = [new_tag]
    for tag in new_tags:
        data = { "name": tag, "vulnerability_id": vuln_id }
        with synack.no_ssl_verification():
            url = DOMAIN + "/v1/vulnerability_tags"
            r=requests.post(url, headers=headers, json=data, verify=False)
            if r.status_code == 200 or r.status_code == 201:
                print("[*] Created tag: " + str(data))
            elif r.status_code == 404:
                print("[*] Insufficient Privilege to create tag: " + str(data))
            elif r.status_code == 400:
                print("[*] Tag name is missing or is invalid (e.g. exists already): " + str(data))
            else:
                print(r.status_code,r.reason)

'''
Description: Applies the tag_single_vuln() function to all vulns in a date range
Inputs: None
Outputs: None
'''
def tag_multiple_vulns():
    print ("[*] Enter start date for vulns to be tagged in format YYYY-MM-DD (i.e. 2018-11-30), then, press 'Enter'.  A blank entry will be treated as a wildcard.")
    start_input = str(raw_input(PROMPT)).split("-")
    start_date = None
    if start_input[0] == '': #if an "enter" is pushed, make wildcard
        start_date = datetime.datetime(1, 1, 1)#min date, per class documentation
    else:
        start_input = map(int, start_input) #datetime needs ints
        start_date = datetime.datetime(start_input[0], start_input[1], start_input[2])
    print ("[*] Enter end date for vulns to be tagged in format YYYY-MM-DD (i.e. 2018-11-30), then, press 'Enter'  A blank entry will be treated as a wildcard.")
    end_input = str(raw_input(PROMPT)).split("-")
    end_date = None
    if end_input[0] == '': #if an "enter" is pushed, make wildcard
        end_date = datetime.datetime(9999, 12, 31) #min date, per class documentation
    else:
        end_input = map(int, end_input) #datetime needs ints
        end_date = datetime.datetime(end_input[0], end_input[1], end_input[2])
    vuln_matches = []
    vulns = get_vulnerabilities()
    for vuln in vulns:
        #pull out date
        date_created = vuln["vulnerability_status"]["created_at"][0:10].split("-") #"2017-05-15T15:13:58.825Z" into ["2017", "05", "15"]
        date_created = map(int, date_created) #datetime needs ints
        vuln_date = datetime.datetime(date_created[0], date_created[1], date_created[2])
        if vuln_date >= start_date and vuln_date <= end_date:
            vuln_matches.append(vuln)
    print ("[*] Enter a new tag to assign to selected Vulns. To assign multiple tags, separate them with a comma (i.e. foo, bar, boo, hiss)")
    new_tag = str(raw_input(PROMPT))
    message = "[*] The Changes will be applied to " + str(len(vuln_matches)) + " vulns, continue? [Y/n]: "#doublecheck that they're sure
    response = str(raw_input(message))
    if response == "" or response.lower() == "y" or response.lower() == "yes":
        for vuln in vuln_matches:
            tag_single_vuln(vuln['id'], new_tag = new_tag)
    else:
        return

'''
Description: Applies the tag_single_vuln() function to all vulns matching an assessment name
Inputs: None
Outputs: None
'''
def tag_vulns_in_assessment():
    print("[*] Enter assessment name with switches below to control action")
    print("[CERBERUS NAME] {blank} Add New Tag to Everything")
    print("[CERBERUS NAME] -u Add tags only to untagged vulnerabilities")
    print("[CERBERUS NAME] -r Replace all tags with new tags")
    mc_args=raw_input(PROMPT).lower().split(" ")
    match_codename = mc_args[0]
    if len(mc_args)==2:
        mc_action=mc_args[1]
    elif len(mc_args)>2:
        return

    if match_codename == '':  # if an "enter" is pushed escape
        return

    vuln_matches = []
    vulns = get_vulnerabilities(match_codename)
    print("[*] Enter a new tag to assign to selected Vulns. To assign multiple tags, separate them with a comma (i.e. foo, bar, boo, hiss)")
    new_tag = str(raw_input(PROMPT))
    message = "[*] The Changes will be applied to " + str(
        len(vulns)) + " vulns, continue? [Y/n]: "  # doublecheck that they're sure
    response = str(raw_input(message))
    if response == "" or response.lower() == "y" or response.lower() == "yes":
        for vuln in vulns:
            tag_single_vuln(vuln['id'], new_tag=new_tag)
        else:
            return


def get_multiple_vulns(tag_query):
    vulns = get_vulnerabilities(tag_query)
    vuln_matches = []
    for vuln in vulns:
        for tag in vuln['tag_list']:
            if tag['name'] == tag_query:
                vuln_matches.append(vuln['id'])
            elif len(tag) == 0:
                print("hello")
                
    return vuln_matches


'''
Description: main function where program flow begins
Error Handling: the error handling is intentionally minimal.  If any errors are detected, either for input validation reasons or API request reasons, the program will exit.
Inputs: None
Outputs: None
'''
if __name__ == '__main__':
    selection = ""
    TOKEN = synack.get_api_key()
    codenames = get_all_codenames()
    print("[-] Got Codenames")
    print_container(codenames)
    #splashscreen()

    m_list = ["Work with Users and Assessments", "Work with Vulnerabilities and Tags"]
    a_list = ["Return", "List all assessments", "List all users", "List assessments for specific user",
              "List users for specific assessment", "Add/Remove a User from an assessment"]
    v_list = ["Return", "List all vulnerabilities", "List all tags", "View all tags for a single vulnerability", "Tag a vulnerability",
              "Tag multiple vulnerabilities by date", "Tag all vulnerabilities in an assessment",
              "List vulnerabilities with a specific tag"]
    selection = 100

    while selection != 2:
        selection = SelectionMenu.get_selection(m_list)
        sub_selection = 100
        if selection == 0:
            while sub_selection >= 1:                                       #WORK WITH USERS/ASSESSMENTS
                sub_selection = SelectionMenu.get_selection(a_list)
                if sub_selection == 1:                                      #LIST ASSESSMENTS
                    try:
                        print("[*] Pulling a list of all assessments with ID, Description, Category, and Status")
                        assessments = get_all_assessments()
                        print("[-] Got Assessment List")
                        for assessment in assessments:
                            title = assessment['description'] or ""
                            title = title.partition("\r\n")[0]
                            title = title.partition("\n")[0]
                            try:
                                codename = codenames[assessment['id']][0]
                            except:
                                codename = "<na>"
                                pass
                            if assessment['active']:
                                active = "Active"
                            else:
                                active = "Inactive"
                            print(assessment['id'], "|", assessment['created_at'], "|",codename, "|'", title, "'|", assessment['category'], "|", active)
                        raw_input("Press any key to continue")
                        print("")
                    except Exception as e:
                        print("[!] Error, exiting...")
                        print(e)
                        exit(0)
                elif sub_selection == 2:                                  #LIST USERS
                    try:
                        print(
                            "[*] Getting a list of all users with ID, Email, Admin:banned status, list of assessments")
                        users = get_all_users()
                        print("[-] Got User List")
                        for user in users:
                            assessment_list = ""
                            for item in user['assessment_ids']:
                                try:
                                    codename = codenames[item][0]
                                except:
                                    codename = "<na>"
                                    pass
                                assessment_list = "%s, %s (%s)" % (assessment_list, codename, item )
                            user_line = "%s,%s,%s:%s,\"%s\"" % (user['id'],user['email'],str(user['admin'])[0],str(user['banned'])[0],assessment_list[2:])
                            print(user_line)
                        user_line=""
                        raw_input("Press any key to continue")
                        print("")
                    except Exception as e:
                        print("[!] Error, [ %s ] ...exiting...", e[0])
                        # print e
                        exit(0)
                elif sub_selection == 3:                                #LIST ASSESSMENTS FOR SPECIFIC USER
                    try:
                        print(
                            "[*] Type a part of the user email, or the full id (i.e. shallbetter@hhs, zxy5jsc), then, press 'Enter'")
                        userqryid = raw_input(PROMPT)
                        get_assessments_per_user(userqryid)
                        raw_input("Press any key to continue")
                        print("")
                    except Exception as e:
                        print("[!] Error, exiting...")
                        # print e
                        exit(0)
                elif sub_selection == 4:                                #LIST USERS FOR SPECIFIC ASSESSMENT
                    '''
                    1: enter codename
                    2: convert codename to idx
                    2: Grab list of users
                    3: check assessment listing of each user for idx
                    4: Save users with access to assessment
                    '''

                    try:
                        print("[*] Please enter an assessment codename or id, then, press 'Enter'")
                        assessment = raw_input(PROMPT).upper()
                        try:
                            print("%s is the Id for %s" % (assessment, codenames[assessment][0]))
                        except:
                            for key, value in codenames.items():
                                if value[0] == assessment:
                                    assessment = key
                                    break
                            pass

                        users = get_all_users()
                        print("[-] Got User List")
                        user_list = ""
                        for user in users:
                            if assessment in user['assessment_ids']:
                                try:
                                    codename = codenames[item][0]
                                except:
                                    codename = "<na>"
                                    pass
                            user_list = "%s,%s,%s:%s" % (user['id'], user['email'],
                                                         str(user['admin'])[0], str(user['banned'])[0])

                        print("Users in %s: " % codenames[assessment].value)
                        print (user_list)
                        raw_input("Press any key to continue")
                        print("")
                    except Exception as e:
                        print("[!] Error, [ %s ] ...exiting...", e[0])
                        # print e
                        exit(0)
                elif sub_selection == 5:                                #ADD/REMOVE USER
                    print("6:" + a_list[sub_selection])
                    raw_input("Press any key to continue")
                    print("")
                elif sub_selection == 6:                                #EXIT
                    exit(0)
        elif selection == 1:
            sub_selection = 100
            if selection == 1:
                while sub_selection >= 1:                               #WORK WITH TAGS/VULNERABILTIES
                    sub_selection = SelectionMenu.get_selection(v_list)
                    if sub_selection == 1:                              #list vulnerabilities
                        try:
                            print(
                                "[*] Pulling a list of all vulnerabilities with ID, Title, CVSS, Date created, and Tags")
                            vulns = get_vulnerabilities()
                            print("[-] Got Vulns")
                            for vuln in vulns:
                                sTags = ""
                                for item in vuln['tag_list']:
                                    sTags = sTags + item['name'] + ","
                                print(vuln['id'], "|", vuln['title'], "|", vuln['cvss_final'], "|",
                                      vuln["vulnerability_status"]["created_at"][0:10], "|", sTags[0:len(sTags) - 1])
                            raw_input("Press any key to continue")
                            print("")
                        except Exception as e:
                            print("[!] Error, exiting...", e)
                            # print e
                            exit(0)
                    elif sub_selection == 2:                          #LIST ALL TAGS
                            print("Getting Tags . . .")
                            tags=get_all_tags()
                            tags = sorted(tags, key=lambda k: k["name"], reverse=False)

                            for tag in tags:
                                print(tag["name"])
                    elif sub_selection == 3:                            #VIEW TAGS FOR SPECIFIC VULNERABILITY
                        try:
                            print("[*] Type the vuln ID (i.e. IRONJUMP-1), then, press 'Enter'")
                            vuln_id = raw_input(PROMPT)
                            vuln = get_single_vuln(vuln_id)
                            if vuln:
                                print("[*] The following tags have been applied to " + vuln_id)
                                for item in vuln['tag_list']:
                                    print_container(item)
                            raw_input("Press any key to continue")
                            print("")
                        except Exception as e:
                            print("[!] Error, exiting...",e)
                            # print e
                            exit(0)
                    elif sub_selection == 4:                            #TAG A SPECIFIC VULNERABILITIY
                        try:
                            print("[*] Type the vuln ID (i.e. IRONJUMP-1), then, press 'Enter'")
                            vuln_id = raw_input(PROMPT)
                            tag_single_vuln(vuln_id)
                            raw_input("Press any key to continue")
                            print("")
                        except Exception as e:
                            print("[!] Error, exiting...",e)
                            # print e
                            exit(0)
                    elif sub_selection == 5:                            #tag multiple vulnerabilities by date
                        try:
                            tag_multiple_vulns()
                            raw_input("Press any key to continue")
                            print("")
                        except Exception as e:
                            print("[!] Error, exiting...",e)
                            # print e
                            exit(0)
                    elif sub_selection == 6:                            #tag all vulnerabilities in an assessment
                        try:
                            tag_vulns_in_assessment()
                            raw_input("Press any key to continue")
                            print("")
                        except Exception as e:
                            print("[!] Error, exiting...",e)
                            # print e
                            exit(0)
                    elif sub_selection == 7:                            #list vulnerabilities with a specific tag
                        try:
                            print("[*] Enter a tag to query for")
                            tag = raw_input(PROMPT)
                            vulns = get_multiple_vulns(tag)
                            print("[*] The following matches were identified:")
                            print_container2(vulns)
                            raw_input("Press any key to continue")
                            print("")
                        except Exception as e:
                            print("[!] Error, exiting...",e)
                            # print e
                            exit(0)
                    elif sub_selection == 8:                            #exit
                        exit(0)


