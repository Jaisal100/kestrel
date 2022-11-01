import requests
import json

ip_=input("Please enter an IPv4 address: ")
API_Key=input("Please enter a VirusTotal API key: ")
url = "https://www.virustotal.com/api/v3/ip_addresses/{}".format(ip_)
headers = {
    "accept": "application/json",
    "x-apikey": "{}".format(API_Key)
}

response = requests.get(url, headers=headers)

data=response.text

parse_json=json.loads(data)

if 'error' not in parse_json:
    IPv4_report=parse_json['data']['attributes']['last_analysis_stats']
    harmless_stat=IPv4_report['harmless']
    undetected_stat=IPv4_report['undetected']
    suspicious_stat=IPv4_report['suspicious']
    malicious_stat=IPv4_report['malicious']

if 'error' in parse_json:
    print("IPv4 address is invalid.")
elif malicious_stat > 0:
    print("This IPv4 address is a known bad actor.")
elif harmless_stat > 0 and malicious_stat == 0 and suspicious_stat == 0:
    print("This IPv4 address is not a known bad actor.")
elif undetected_stat > 0:
    print("The threat level of this IPv4 address is currrently unknown.")
else:
    print("This IPv4 address is potentially from a bad actor.")