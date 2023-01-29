import requests
import csv
from synack import synack

# SET VARIABLES
global TOKEN


if __name__ == '__main__':

    outputfile = "/opt/splunk/etc/apps/hhs_crowdtesting/lookups/synack_tags.csv"
    outputfile= "c:\\bat\synack_python_dev\synack_tags.csv"

    tags = synack.get_all_tags(synack.get_api_key())
    hhsopdivs = ["OS","NIH","ACL","ACF","AHRQ","CDC","CMS","HRSA","FDA","IHS","NIH","SAMHSA"]
    hhsorgs = {
        "OASH":"OS",
        "DCIO":"OS",
        "NLM" : "NIH",
        "PSC" : "OS",
        "NCATS":"NIH",
        "BARDA":"OS",
        "ASPA": "OS",
        "ASPE": "OS",
        "ASPR":"OS",
        "CTO":"OS",
        "FOH":"OS"
    }

s
        fields = ["id","tag","opdiv"]
        writer.writerow(fields)
        for tag in tags:
            opdiv = "NONE"
            for op in hhsopdivs:
                if op in tag['name'].upper():
                    opdiv = op
                if opdiv == "NONE":
                    for i in hhsorgs:
                        if i in tag['name'].upper():
                            opdiv = hhsorgs[i]

            row = [tag['id'],tag['name'],opdiv]
            writer.writerow(row)

    print()
    print("Wrote %i items to %s" % (len(tags),outputfile))