import csv
import sys
from synack import synack

if __name__ == '__main__':
    tags = synack.get_all_tags(synack.get_api_key())
    hhsopdivs = ["ACL","ACF","AHRQ","CDC","CMS","HRSA","FDA","IHS","SAMHSA","OS","NIH"]
    hhsorgs = {
        "OASH":"OS",
        "DCIO":"OS",
        "NCI": "NIH",
        "NLM" : "NIH",
        "PSC" : "OS",
        "NCATS":"NIH",
        "BARDA":"OS",
        "ASPA": "OS",
        "ASPE": "OS",
        "ASFR": "OS",
        "ASPR":"OS",
        "CTO":"OS",
        "FOH":"OS"
    }
    stdout = open(sys.__stdout__.fileno(),
                  mode=sys.__stdout__.mode,
                  buffering=1,
                  encoding=sys.__stdout__.encoding,
                  errors=sys.__stdout__.errors,
                  newline='\n',
                  closefd=False)

    writer = csv.writer(stdout)
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