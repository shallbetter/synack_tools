import csv
import requests
import socket
import warnings
import contextlib
import time
from urllib3.exceptions import InsecureRequestWarning

import os
import sys

'''
input_path = "C:\\bat\synack_python_dev\\"
output_path = os.path.dirname(__file__) + '\logs\"'output_filename = datetime.datetime.today().strftime('%Y%m%d') + "_hhsvdp_scanresults.csv"
log_dir = os.path.dirname(__file__)+'/hhsvdp'
log_file = './hhsvdp_logs/hhsvdp_logs.txt'
'''

CSV_URL = 'https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-federal.csv'

dc_field = "date_collected"
vdp_field = "vdp_policy_status"
timestamp = time.strftime("%Y-%m-%d")
AgencyField = 0
Records = 0

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

def returnpolicystatus(domain):
    urlvdp = '/vulnerability-disclosure-policy'
    url = "https://"+domain
    vdp_test = "/vulnerability-disclosure-policy"
    hostip = "<err>"
    HistoryResponseURL = ""
    ResponseURL = ""

    try:
        hostinfo=socket.gethostbyname_ex(domain)
        hostip = " ".join(hostinfo[2])
        try:
           # with no_ssl_verification():
            response = requests.get(url, timeout=1)
            index = 0
            for hist in response.history:
                HistoryResponseURL = "%i:(%i) %s, %s" % (index, hist.status_code, hist.url,HistoryResponseURL)
                index += 1
            ResponseURL = "(%i) %s" % (response.status_code, response.url)
            if response.status_code == 200:
                if response.history.__len__() != 0:
                    if response.history[0].status_code == 301:
                        if url in response.url:
                            isRedirect = ""
                        else:
                            isRedirect = "Redirects to " + response.url
                    else:
                        if url in HistoryResponseURL:
                            isRedirect=""
                        else:
                            isRedirect = "Redirects to " + HistoryResponseURL
                else:
                    isRedirect = ""

                if vdp_test in response.text.lower():
                    return "VDP Linked"+"|"+hostip + "|" + isRedirect + "|" + ResponseURL + "|" + HistoryResponseURL
                else:
                    return "No VDP"+"|"+hostip + "|" + isRedirect + "|" + ResponseURL + "|" + HistoryResponseURL
            elif response.status_code > 400:
                return "%i Error (%s)|%s|%s|%s" % (response.status_code,response.reason,hostip, ResponseURL,HistoryResponseURL)
            else:
                return "%i Error (%s)|%s|%s|%s" % (response.status_code,url,hostip, ResponseURL,HistoryResponseURL)
        except requests.exceptions.Timeout:
            return "Timeout|%s|%s" % (hostip, "Timeout")
        except requests.exceptions.TooManyRedirects:
            return "Error|%s|%s" % (hostip, "Too Many Redirects")
        except requests.exceptions.ConnectTimeout:
            return "Timeout|%s|%s" % (hostip, "Connection Timeout")
        except requests.exceptions.RequestException as e:
            return "Error|%s|%s" % (hostip, e)
    except socket.gaierror:
        return "<Does Not Resolve>| |Hostname %s does not resolve" % (domain)
    except socket.timeout:
        return "Timeout|%s|%s" % (hostip, "Timeout Error")
    except Exception as e:
        print(e)
        return "Error|%s|%s" % (hostip,"ERROR")

def log_to_file():
    # This is what makes the logs for this script
    if not os.path.exists(log_dir):
        os.mkdir(log_dir)
    logger = logging.getLogger(__name__)
    hdlr = handlers.RotatingFileHandler(log_file, maxBytes=100000, backupCount=10, encoding='UTF-8')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    return logger

def path_leaf(path):
    head, tail = os.path.split(path)
    return tail or os.path.basename(head)

def get_web_csv(url):
    with no_ssl_verification():
        with requests.Session() as s:
            download = s.get(url)
            decoded_content = download.content.decode('utf-8')
            cr = csv.reader(decoded_content.splitlines(), delimiter=',')
            csv_list = list(cr)
            return csv_list

'''
FUNCTION: parse_command_line
ARGUMENTS: reads command line
'''
def parse_commandline():
    global inputfile
    global test_url
    inputfile = ""
    test_url=""


    if len(sys.argv)>1:
        i=1
        while i < len(sys.argv):
            if sys.argv[i] == "-h" or sys.argv[i] == "--help" or sys.argv[i] == "-?":
                print("")
                print("USAGE: hhsvdp_scanner.py -f {inputfilepath}")
                print("     -h | --help         This help statement")
                print("     -f | --file         Full Path to csv of assessments|vulnerability & tag pairs. ")
                print("")
                exit(0)
            elif sys.argv[i].lower() == "-f" or sys.argv[i].lower() == "--file":
                i=i+1
                try:
                    inputfile=sys.argv[i]
                    i=i+1
                except:
                    print("No file name provided after -f flag")
            else:
                test_url = sys.argv[i]
                i = i + 1


if __name__ == '__main__':
    parse_commandline()
    fileout = os.path.dirname(os.path.realpath(__file__))
    fileout = fileout + "hhs_vdpscan_"
    fileout = fileout + time.strftime("%Y%m%d")
    if inputfile != "": fileout = fileout + "_" + path_leaf(inputfile)
    if test_url != "": fileout = fileout + "_" + test_url
    fileout = fileout + ".csv"
    with open(fileout, 'w',newline="") as f:
        writer = csv.writer(f)
        if inputfile != "":
                with open(inputfile) as domains_in:
                    my_csvdata = csv.reader(domains_in,delimiter=',')
                    my_csvdata=list(my_csvdata)
        elif test_url != "":
            my_csvdata=[[test_url]]
        else:
            my_csvdata =  get_web_csv(CSV_URL)

        fields = []
        fields.append("domain")
        fields.append(dc_field)
        fields.append(vdp_field)
        fields.append("ip_resolve")
        fields.append("error_msg")
        fields.append("ResponseURL")
        fields.append("HistoryURL")
        writer.writerow(fields)

        AgencyField = 0
        if inputfile == "":
            for af in fields:
                if af == "Agency":
                        break
                AgencyField=AgencyField+1

        for row in my_csvdata:
            if row[0] != "":
                if row[AgencyField] == "Department of Health and Human Services" or inputfile != "" or test_url !="":
                    row.append(timestamp)
                    retpol = returnpolicystatus(row[0].lower())
                    if "|" in retpol:
                        ret_pols = map(str.strip, retpol.split("|"))
                    else:
                        ret_pols = [retpol]
                    for pol in ret_pols:
                            row.append(pol)
                    writer.writerow(row)
                    Records = Records + 1
                    print("Moving Through Code: %i : %s : Note(%s)" %(Records,row[0].lower(),retpol))
        print()
        print("Wrote %s records to %s" % (Records, fileout))