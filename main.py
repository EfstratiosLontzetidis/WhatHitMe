from attackcti import attack_client
from stix2 import TAXIICollectionSource
from taxii2client.v20 import Collection
import urllib.parse
import logging

def intro():
    print("Welcome to ***WhatHitMe***\n\n\n")
    print("This is a python script that offers the visibility to a defender to know the possible"
          " APT groups that targeted"
          " an organization, after understanding the techniques and software used.\n\n\n")
    print("Authors: Efstratios Lontzetidis & Kostantinos Pantazis")

def get_incident_techniques(list,techniques):
    flag1=True
    while flag1:
        technique = input("Give us a technique in the format of T1XXX or T1XXX.XXX. Type exit to continue: ")
        if technique in techniques.keys():
            print("Added to the list!")
            list.append(technique)
        elif technique == "exit":
            flag1 = False
        else:
            print("Not Found")
    return list

def get_incident_software(list, tools):
    flag2=True
    while flag2:
        software = input("Give us a software in the format of SXXXX. Type exit to continue: ")
        if software in tools.keys():
            print("Added to the list!")
            list.append(software)
        elif software == "exit":
            flag2 = False
        else:
            print("Not Found")
    return list

def get_enterprise_attack_techniques(client):
    enterprise_techniques={}
    counter=0
    for technique in client.get_techniques():
        enterprise_techniques[technique['external_references'][0]['external_id']]=technique['name']
        counter=counter+1
    return enterprise_techniques


def get_enterprise_attack_software(client):
    enterprise_sofware={}
    for software in client.get_software():
        enterprise_sofware[software['external_references'][0]['external_id']]=software['name']
    return enterprise_sofware

def identify_groups(lift, techniques_from_incident, software_from_incident):
    match=False
    techniques_from_group=[]
    tools_from_group=[]
    groups = lift.get_groups()
    counter=0
    for group in groups:
        group_techniques = lift.get_techniques_used_by_group(groups[counter])
        group_name=group['name']
        group_id=group['external_references'][0]['external_id']
        group_url = group['external_references'][0]['url']
        for technique in group_techniques:
            techniques_from_group.append(technique['external_references'][0]['external_id'])
        if (all(x in techniques_from_group for x in techniques_from_incident)):
            match=True
        if software_from_incident:
            match=False
            group_software=lift.get_software_used_by_group(groups[counter])
            for tool in group_software:
                tools_from_group.append(tool['external_references'][0]['external_id'])
            if(all(x in tools_from_group for x in software_from_incident)):
                match=True
        if match==True:
            print_results(group_name,group_id,group_url)
        match=False
        counter = counter + 1

def print_results(name,id,url):
    print("...\n")
    print("Possible Group Found: " + name + " " + id + " " + url + " "+ "https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2F"+id+"%2F"+id+"-enterprise-layer.json" + " " +"https://demo.opencti.io/dashboard/search/"+urllib.parse.quote(name) +" " +" \n")
    print("...\n")

intro()

logging.getLogger('taxii2client').setLevel(logging.CRITICAL)
ATTACK_STIX_COLLECTIONS = "https://cti-taxii.mitre.org/stix/collections/"
ENTERPRISE_ATTACK = "95ecc380-afe9-11e4-9b6c-751b66dd541e"
PRE_ATTACK = "062767bd-02d2-4b72-84ba-56caef0f8658"
MOBILE_ATTACK = "2f669986-b40b-4423-b720-4396ca6a462b"
ICS_ATTACK = "02c3ef24-9cd4-48f3-a99f-b74ce24f1d34"
ENTERPRISE_COLLECTION = Collection(ATTACK_STIX_COLLECTIONS + ENTERPRISE_ATTACK + "/")
TC_ENTERPRISE_SOURCE = TAXIICollectionSource(ENTERPRISE_COLLECTION)
PRE_COLLECTION = Collection(ATTACK_STIX_COLLECTIONS + PRE_ATTACK + "/")
TC_PRE_SOURCE = TAXIICollectionSource(PRE_COLLECTION)
MOBILE_COLLECTION = Collection(ATTACK_STIX_COLLECTIONS + MOBILE_ATTACK + "/")
TC_MOBILE_SOURCE = TAXIICollectionSource(MOBILE_COLLECTION)
ICS_COLLECTION = Collection(ATTACK_STIX_COLLECTIONS + ICS_ATTACK + "/")
TC_ICS_SOURCE = TAXIICollectionSource(ICS_COLLECTION)

# incident_techniques=['T1595.002', 'T1588.001', 'T1574.001']
# incident_software=['S0385', 'S0154']
incident_techniques=[]
incident_software=[]

lift = attack_client()

attack_techniques=get_enterprise_attack_techniques(lift)
attack_software=get_enterprise_attack_software(lift)
input_techniques=get_incident_techniques(incident_techniques,attack_techniques)

software_found=input("Do you want to proceed by adding software? Y/N. Default: Y ")
if software_found=="N" or software_found=="n":
    pass
else:
    input_sofware=get_incident_software(incident_software,attack_software)

print("Searching for possible Groups that attacked you...")
identify_groups(lift, incident_techniques, incident_software)


