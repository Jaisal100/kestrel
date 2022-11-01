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
print(parse_json)

IPv4_report=parse_json['data']['attributes']['last_analysis_stats']

harmless_stat=IPv4_report['harmless']
undetected_stat=IPv4_report['undetected']
suspicious_stat=IPv4_report['suspicious']
malicious_stat=IPv4_report['malicious']

if malicious_stat > 0:
    print("This IP is a known bad actor.")
elif harmless_stat > 0 and malicious_stat == 0 and suspicious_stat == 0:
    print("This IP is not a known bad actor.")
elif undetected_stat > 0:
    print("The threat level of this IP is currrently unknown.")
else:
    print("This IP is potentially from a bad actor.")