# ASM Enforce Attack signatures based on a list - Vulnerabilities Spring4Shell and Spring Cloud - https://support.f5.com/csp/article/K24912123
# Ismael Goncalves
import argparse
import csv
import datetime
import getpass
import json
import os
import requests
import urllib3

# global variable - file to save data
dt = datetime.datetime.today()

# signatures ID to be enforced across all policies in blocking mode
# CVE-2022-22965, CVE-2022-22950, and CVE-2022-22963.
# https://support.f5.com/csp/article/K24912123

sigs = ['200003437', '200003438', '200003439', '200003443', '200003444', '200003445', '200004161', '200004453', '200104262', '200104263', '200104796', '200104797', '200104798', '200104799']

def get_token(b, url_base, creds):
    url_auth = '%s/shared/authn/login' % url_base
    try:
        payload = {}
        payload['username'] = creds[0]
        payload['password'] = creds[1]
        payload['loginProviderName'] = 'tmos'
        token = b.post(url_auth, json.dumps(payload)).json()['token']['token']
    except:
        token = '' 
    return token

def audit_asm_policies_high_level(device,token):

    print('Working on ASM policies for device %s - only policies in BLOCKING mode' % device)
 
    # filter policies - obtains policy ID, name, enforcement mode
    url_base_asm = 'https://%s/mgmt/tm/asm/policies/?$select=id,name,enforcementMode,type' % device
    bigip = requests.session()
    bigip.headers.update({'Content-Type': 'application/json'})
    bigip.headers.update({'X-F5-Auth-Token': token})
    bigip.verify = False
    bigip.auth = None
    
    r = bigip.get(url_base_asm)
    json_data = r.json()

    for i in json_data['items']:
        if( i['type']=='parent'):
            continue
        # operation for policies in blocking mode only 
        if(i['enforcementMode']=='blocking'):
            print('Enforcing selected signatures on device %s policy %s' % (device,i['name']))
            asm_policy_apply_sig(i['id'], token)
        
def asm_policy_apply_sig(policy_id, token):
    
    url_apply_pol = 'https://%s/mgmt/tm/asm/tasks/apply-policy' % (device)
    payload_apply = '{"policyReference":{"link":"https://localhost/mgmt/tm/asm/policies/%s"}}' % (policy_id)
    payload_enfor = '{"performStaging":false}'
    
    bigip = requests.session()
    bigip.headers.update({'Content-Type': 'application/json'})
    bigip.headers.update({'X-F5-Auth-Token': token})
    bigip.verify = False
    bigip.auth = None
    
    # enforce each signature
    url_cve_sigs  = 'https://%s/mgmt/tm/asm/policies/%s/signatures?$expand=signatureReference&$filter=inPolicy+eq+true+and+signature/signatureId+in+(\'%s\')' % (device,policy_id, "','".join(sigs))
    r = bigip.patch(url_cve_sigs,payload_enfor)
    print("Status code for enforcement: " + str(r.status_code))
    
    # apply changes    
    r = bigip.post(url_apply_pol, payload_apply)
    print("Status code for apply changes: " + str(r.status_code))

def check_active(device,token):
    
    # obtain device name
    url_base_asm = 'https://%s/mgmt/tm/sys/global-settings?$select=hostname' % device
    bigip = requests.session()
    bigip.headers.update({'Content-Type': 'application/json'})
    bigip.headers.update({'X-F5-Auth-Token': token})
    bigip.verify = False
    bigip.auth = None
    
    r = bigip.get(url_base_asm)
    hostname = r.json()['hostname']
 
    url_base_asm = 'https://%s/mgmt/tm/cm/traffic-group/traffic-group-1/stats?$select=deviceName,failoverState' % device
    bigip = requests.session()
    bigip.headers.update({'Content-Type': 'application/json'})
    bigip.headers.update({'X-F5-Auth-Token': token})
    bigip.verify = False
    bigip.auth = None
    
    r = bigip.get(url_base_asm)
    json_data = r.json()
    
    for i in json_data['entries']:
        devices = json_data['entries'][i]['nestedStats']
        # returns similar to 
        #{'entries': {'deviceName': {'description': '/Common/bigip1.f5labs.net'}, 'failoverState': {'description': 'standby'}}}
        device = devices['entries']['deviceName']['description']
        state = devices['entries']['failoverState']['description']
        
        if (hostname in device) and ('active' in state):
            return True
         
    return False

if __name__ == "__main__":
    urllib3.disable_warnings()

    parser = argparse.ArgumentParser()

    parser.add_argument("device", help='a file containing list of BIG-IP devices separated by line, e.g. devices.txt')
    args = vars(parser.parse_args())

    device = args['device']

    username = input('Enter your username: ') 
    password = getpass.getpass('Enter your password: ')

    with open(device,'r') as a_file:
        for line in a_file:
            device = line.strip()
            # TODO - test connectivity with each device and report on the ones failing 
            url_base = 'https://%s/mgmt' % device
            bigip = requests.session()
            bigip.headers.update({'Content-Type': 'application/json'})
            bigip.auth = (username, password)
            bigip.verify = False
            token = get_token(bigip, url_base, (username, password))
            if (not token):
                print('Unable to obtain token for device ' + device)
                continue 
            if not check_active(device, token): 
                print('Device ' + device + ' is not active, skipping it...')
                continue
            audit_asm_policies_high_level(device,token)
    
