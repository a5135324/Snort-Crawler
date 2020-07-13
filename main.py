import json
import requests
from bs4 import BeautifulSoup

def parse_snort(sid):
    ret = {
        "sid":"",
        "Rule Category":"",
        "Alert Message": "",
        "Rule Explanation": {
            "Description": "",
            "Impact": {
                "Description": "",
                "Base score": "",
                "Impact score": "",
                "Exploitability score": "",
                "Confidentiality": "",
                "Integrity": "",
                "Availability": ""
            },
            "Details": "",
            "Ease of Attack": ""
        },
        "What To Look For": "",
        "Known Usage": "",
        "False Positives": "",
        "Contributors": "",
        "MITRE ATTACK Framework": {
            "Tactic": {
                "Description": "",
                "Link": ""
            },
            "Technique": {
                "Description": "",
                "Link": ""
            }
        },
        "CVE": [],
        "Additional Links": [],
        "Rule Vulnerability": {
            "Vulnerability Name": "",
            "Description": ""
        },
        "CVE Additional Information": []
    }
    ret['sid'] = sid

    res = requests.get('https://www.snort.org/rule_docs/1-{}'.format(sid))
    soup = BeautifulSoup(res.text, 'lxml')

    if soup.title.text == 'Snort.Org':
        #print('sid:{} no rule document.'.format(colored(sid, 'red')))
        #return ('sid:{} no rule document.'.format(sid))
        return 'no'

    ## find snort rule doc
    rule_doc = soup.find("div", {"class":"row ruledoc-row"})

    ## find titles and contents in rule doc
    titles = rule_doc.findChildren("h3")
    contents = rule_doc.findChildren("p")

    ## remove one of empty content to make the amounts of titles and contents are the same
    contents = contents[:6] + contents[7:]

    for i in range(0,len(titles)):
        if i == 2: ## Rule Explanation Field
            temp = contents[i].text.split('\n')
            temp = list(filter(None, temp))
            #print(temp[0])
            for j in range(0, len(temp)):
                if temp[j] == 'Impact:':
                    if j+1 < len(temp) and temp[j+1] != 'Details:' and temp[j+1].find('CVSS base score') == -1:
                        ret['Rule Explanation']['Impact']['Description'] = temp[j+1]
                        j = j+1
                elif temp[j] == 'Details:':
                    if j+1 < len(temp) and temp[j+1] != 'Ease of Attack:':
                        ret['Rule Explanation']['Details'] = temp[j+1]
                        j = j+1
                elif temp[j] == 'Ease of Attack:':
                    if j+1 < len(temp):
                        ret['Rule Explanation']['Ease of Attack'] = temp[j+1]
                        j = j+1
                elif j == 0:
                    #print(temp[j])
                    ret['Rule Explanation']['Description'] = temp[j]

                ## Parse CVSS field and other impact field
                if temp[j].find('CVSS base score') != -1:
                    ret['Rule Explanation']['Impact']['Base score'] = temp[j].split(' base score ')[1]
                elif temp[j].find('CVSS impact score') != -1:
                    ret['Rule Explanation']['Impact']['Impact score'] = temp[j].split(' impact score ')[1]
                elif temp[j].find('CVSS exploitability score') != -1:
                    ret['Rule Explanation']['Impact']['Exploitability score'] = temp[j].split(' exploitability score ')[1]
                elif temp[j].find('confidentialityImpact') != -1:
                    ret['Rule Explanation']['Impact']['Confidentiality'] = temp[j].split('fidentialityImpact ')[1]
                elif temp[j].find('integrityImpact') != -1:
                    ret['Rule Explanation']['Impact']['Integrity'] = temp[j].split('tegrityImpact ')[1]
                elif temp[j].find('availabilityImpact') != -1:
                    ret['Rule Explanation']['Impact']['Availability'] = temp[j].split('ailabilityImpact ')[1]

        elif i == 6: ## Contributor Field
            temp = contents[i].text.replace('\n',' ')
            temp = temp.replace('  ',' ')
            ret[titles[i].text] = temp
        else:
            ret[titles[i].text] = contents[i].text

    ref_doc = soup.find("div", {"id":"tab-references"})

    tactic = ref_doc.find("p", {"class":"mitre-cat"})
    if tactic.a:
        ret['MITRE ATTACK Framework']['Tactic']['Description'] = tactic.a.text
        ret['MITRE ATTACK Framework']['Tactic']['Link'] = tactic.a['href']

    mitre = ref_doc.find("p", {"class":"mitre-subcat"})
    if mitre.a:
        ret['MITRE ATTACK Framework']['Technique']['Description'] = mitre.a.text
        ret['MITRE ATTACK Framework']['Technique']['Link'] = mitre.a['href']

    additional_link = ref_doc.findChildren("div", {"class":"additional-link"})
    if additional_link:
        for i in range(0, len(additional_link)):
            ret['Additional Links'].append(additional_link[i].a['href'])

    cve = ref_doc.findChildren("span", {"class":"cve-entry"})
    if cve:
        for i in range(0, len(cve)):
            ret['CVE'].append(cve[i].a.text)

    vulnerability = ref_doc.find("p", {"class":"rule_vulnerability"})
    if vulnerability:
        ret['Rule Vulnerability']['Vulnerability Name'] = vulnerability.text.strip()

    vulnerability_blurb = ref_doc.find("p", {"class":"rule_vulnerability_blurb"})
    if vulnerability:
        ret['Rule Vulnerability']['Description'] = vulnerability_blurb.text.strip()

    cve_table = ref_doc.find('table', {'class':'table responsive-table'})

    col_id = cve_table.findChildren('td', {'class':'col-id'})
    col_details = cve_table.findChildren('td', {'class':'col-details'})
    for i in range(0, len(col_id)):
        cve_format = {
            "CVE": "",
            "Description": "",
            "Details": {
                "Severity": "",
                "Base Score": "",
                "Impact Score": "",
                "Exploit Score": "",
                "Confidentiality Impact": "",
                "Integrity Impact": "",
                "Availability Impact": "",
                "Access Vector": "",
                "Authentication": "",
                "Ease of Access": ""
            }
        }

        cve_format['CVE'] = col_id[i]['id']
        cve_format['Description'] = col_id[i].text[len(col_id[i]['id']):]

        temp = col_details[i].findChildren('tr')
        for k in range(1, len(temp)):
            td = temp[k].findChildren('td')
            for j in range (0, len(td)):
                if td[j].text == 'Severity':
                    cve_format['Details'][td[j].text] = td[j+1].text
                    j+=1
                elif td[j].text == 'Base Score':
                    cve_format['Details'][td[j].text] = td[j+1].text
                    j+=1
                elif td[j].text == 'Impact Score':
                    cve_format['Details'][td[j].text] = td[j+1].text
                    j+=1
                elif td[j].text == 'Exploit Score':
                    cve_format['Details'][td[j].text] = td[j+1].text
                    j+=1
                elif td[j].text == 'Confidentiality Impact':
                    cve_format['Details'][td[j].text] = td[j+1].text
                    j+=1
                elif td[j].text == 'Integrity Impact':
                    cve_format['Details'][td[j].text] = td[j+1].text
                    j+=1
                elif td[j].text == 'Availability Impact':
                    cve_format['Details'][td[j].text] = td[j+1].text
                    j+=1
                elif td[j].text == 'Access Vector':
                    cve_format['Details'][td[j].text] = td[j+1].text
                    j+=1
                elif td[j].text == 'Authentication':
                    cve_format['Details'][td[j].text] = td[j+1].text
                    j+=1
                elif td[j].text == 'Ease of Access':
                    cve_format['Details'][td[j].text] = td[j+1].text
                    j+=1
        ret['CVE Additional Information'].append(cve_format)
    #print(json.dumps(ret, indent=4))

    return ret
    #print(ret)

parse_snort(12345)
