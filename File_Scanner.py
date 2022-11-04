import requests
import json
import base64
import creds as cr

file_=input("Please enter a file location: ")
url_id = base64.urlsafe_b64encode("{}".format(url_).encode()).decode().strip("=")
url = "https://www.virustotal.com/api/v3/files/scan"
headers = {
    "accept": "application/json",
    "x-apikey": "{}".format(cr.API_Key)
}

response = requests.post(url, headers=headers)

data=response.text

parse_json=json.loads(data)

if 'error' not in parse_json:
    URL_report=parse_json['data']['attributes']['last_analysis_stats']
    harmless_stat=URL_report['harmless']
    undetected_stat=URL_report['undetected']
    suspicious_stat=URL_report['suspicious']
    malicious_stat=URL_report['malicious']

if 'error' in parse_json:
    print("URL is invalid.")
elif malicious_stat > 0:
    print("This URL is a known bad actor.")
elif harmless_stat > 0 and malicious_stat == 0 and suspicious_stat == 0:
    print("This URL is not a known bad actor.")
elif undetected_stat > 0:
    print("The threat level of this URL is currrently unknown.")
else:
    print("This URL is potentially from a bad actor.")