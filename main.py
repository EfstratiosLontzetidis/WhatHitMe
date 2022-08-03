from attackcti import attack_client
from stix2 import TAXIICollectionSource
from taxii2client.v20 import Collection
from tabulate import tabulate
from datetime import date
import urllib.parse
import logging

# information about the tool and authorship
def intro():
    print("Welcome to ***WhatHitMe***\n\n\n")
    print("This is a python script that offers the visibility to a defender to know the possible"
          " APT groups that targeted"
          " an organization, after understanding the techniques and software used.\n\n\n")
    print("Authors: Efstratios Lontzetidis & Kostantinos Pantazis")

# receive user input about the techniques that were identified in an incident
def get_incident_techniques(techniques):
    # initialize list for storing techniques from an incident
    incident_techniques = []
    flag=True
    while flag:
        # prompt for techniques identified
        technique = input("Give us a technique in the format of T1XXX or T1XXX.XXX. Type exit to continue: ")
        # check if the provided technique exists in att&ck matrix
        if technique in techniques.keys():
            # if it exists in att&ck matrix then import it to a list
            print("Technique added to the list!")
            incident_techniques.append(technique)
        elif technique == "exit":
            # if user types exit then exit the while loop.
            flag = False
        else:
            # if provided input does not exist, loop again
            print("Technique does not exist in ATT&CK")
    # return list with techniques supplied from an incident
    return incident_techniques

# receive user input about the software that were identified in an incident
def get_incident_software(tools):
    # initialize list for storing software from an incident
    incident_software = []
    flag=True
    while flag:
        # prompt for software identified
        software = input("Give us a software in the format of SXXXX. Type exit to continue: ")
        if software in tools.keys():
            # check if the provided software exists in att&ck matrix
            print("Software added to the list!")
            incident_software.append(software)
        elif software == "exit":
            # if user types exit then exit the while loop.
            flag = False
        else:
            # if provided input does not exist, loop again
            print("Software does not exist in ATT&CK")
    # return list with software supplied from an incident
    return incident_software

# pull all the ATT&CK techniques
def get_attack_techniques(client):
    # dictionary initialize to store the techniques
    enterprise_techniques={}
    # loop for all techniques and subtechniques
    for technique in client.get_techniques():
        # in the dictionary store in the key field the technique ID and in the value field the technique name
        enterprise_techniques[technique['external_references'][0]['external_id']]=technique['name']
    # return the dictionary of techniques
    return enterprise_techniques

# pull all the ATT&CK software
def get_attack_software(client):
    # dictionary initialize to store the software
    enterprise_sofware={}
    # loop for all software
    for software in client.get_software():
        # in the dictionary store in the key field the software ID and in the value field the software name
        enterprise_sofware[software['external_references'][0]['external_id']]=software['name']
    # return the dictionary of software
    return enterprise_sofware

def identify_groups(lift, techniques_from_incident, software_from_incident):
    # initialize match flag to catch matched groups
    match=False
    # initialize lists to store the techniques and software used by each group
    techniques_from_group = []
    tools_from_group = []
    # get all the groups from the att&ck client
    groups = lift.get_groups()
    counter=0
    # loop for every group
    for group in groups:
        # get the techniques used for each group through the att&ck client
        group_techniques = lift.get_techniques_used_by_group(groups[counter])
        # store group name, id and att&ck url for printing in variables
        group_name=group['name']
        group_id=group['external_references'][0]['external_id']
        group_url = group['external_references'][0]['url']
        # for every technique in the techniques used from this group
        for technique in group_techniques:
            # store the technique id to a list that stores the techniques for these groups
            techniques_from_group.append(technique['external_references'][0]['external_id'])
            # check if the techniques that were placed as input from an incident are a sublist from the techniques used by this group
        if (all(x in techniques_from_group for x in techniques_from_incident)):
            # if yes, tha flag changes to True
            match=True
        # if the user also gave software as an input
        if software_from_incident:
            # change again the flag to False, since the software should also match
            match=False
            # get the software used by this group through the att&ck client
            group_software=lift.get_software_used_by_group(groups[counter])
            # for every software (tool) in the software used by this group
            for tool in group_software:
                # store the software id
                tools_from_group.append(tool['external_references'][0]['external_id'])
            # check if the software that were placed as input from an incident are a sublist from the software used by this group
            if(all(x in tools_from_group for x in software_from_incident)):
                # if yes, tha flag changes to True
                match=True
        # if this group is a possible group that attacked in this incident
        if match==True:
            # print the results. Also give this function the group name,id,url
            print_results(group_name,group_id,group_url)
        # at the end of the loop, re-initialize the flag, empty lists and increase the loop counter
        techniques_from_group.clear()
        tools_from_group.clear()
        match=False
        counter = counter + 1

# results printing
def print_results(name,id,url):
    # print group infromation about ATT&CK
    print("*****Possible Group Found*****")
    print(tabulate([[name, id, url, 'https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2F'+id+'%2F'+id+'-enterprise-layer.json']],
                   headers=['Name', 'ID', 'ATT&CK URL', 'ATT&CK Navigator URL']))
    print("\n")
    # print searched related with this group
    print("Searches regarding this group:")
    print(tabulate([['OpenCTI (req. login)', 'https://demo.opencti.io/dashboard/search/'+urllib.parse.quote(name)],
                    ['Alienvault OTX (req. login)', 'https://otx.alienvault.com/browse/global/pulses?q='+urllib.parse.quote(name)+'&include_inactive=0&sort=-modified&page=1&limit=10&indicatorsSearch='+urllib.parse.quote(name)],
                    ['Mandiant', 'https://www.mandiant.com/search?search='+urllib.parse.quote(name)],
                    ['IBM X-FORCE (req. login)', 'https://exchange.xforce.ibmcloud.com/search/'+urllib.parse.quote(name)],
                    ['ETDA', 'https://apt.etda.or.th/cgi-bin/listgroups.cgi?c=&v=&s=&m=&x='+urllib.parse.quote(name)],
                    ['Rapid7', 'https://docs.rapid7.com/search/?q='+urllib.parse.quote(name)+'&filters=productname_InsightIDR&page=0'],
                    ['Check Point', 'https://threatpoint.checkpoint.com/ThreatPortal/search?pattern='+urllib.parse.quote(name)+'&type=all&page=0'],
                    ['Broadcom', 'https://www.broadcom.com/site-search?q='+urllib.parse.quote(name)],
                    ['TrendMicro', 'https://www.trendmicro.com/en_us/common/cse.html#?cludoquery='+urllib.parse.quote(name)+'&cludopage=1&cludorefurl=https%3A%2F%2Fwww.trendmicro.com%2Fen_us%2Fbusiness.html&cludorefpt=%231%20in%20Cloud%20Security%20%26%20Endpoint%20Cybersecurity%20%7C%20Trend%20Micro&cludoinputtype=standard'+urllib.parse.quote(name)],
                    ['Hacker News', 'https://hn.algolia.com/?q='+urllib.parse.quote(name)]],
                   headers=['Source', 'Url']))
    print("...\n")
    # also save results
    save_results(name,id,url)

# save results to a file
def save_results(name,id,url):
    f=open("WhatHitMe-"+str(date.today())+".txt", "a")
    f.write("\n")
    f.write("*****Possible Group Found*****")
    f.write("\n")
    f.write("\n")
    f.write(tabulate([[name, id, url,
                     'https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2F' + id + '%2F' + id + '-enterprise-layer.json']],
                   headers=['Name', 'ID', 'ATT&CK URL', 'ATT&CK Navigator URL']))
    f.write("\n")
    f.write("\n")
    # print searched related with this group
    f.write("Searches regarding this group:")
    f.write(tabulate([['OpenCTI (req. login)', 'https://demo.opencti.io/dashboard/search/' + urllib.parse.quote(name)],
                    ['Alienvault OTX (req. login)',
                     'https://otx.alienvault.com/browse/global/pulses?q=' + urllib.parse.quote(
                         name) + '&include_inactive=0&sort=-modified&page=1&limit=10&indicatorsSearch=' + urllib.parse.quote(
                         name)],
                    ['Mandiant', 'https://www.mandiant.com/search?search=' + urllib.parse.quote(name)],
                    ['IBM X-FORCE (req. login)',
                     'https://exchange.xforce.ibmcloud.com/search/' + urllib.parse.quote(name)],
                    ['ETDA', 'https://apt.etda.or.th/cgi-bin/listgroups.cgi?c=&v=&s=&m=&x=' + urllib.parse.quote(name)],
                    ['Rapid7', 'https://docs.rapid7.com/search/?q=' + urllib.parse.quote(
                        name) + '&filters=productname_InsightIDR&page=0'],
                    ['Check Point',
                     'https://threatpoint.checkpoint.com/ThreatPortal/search?pattern=' + urllib.parse.quote(
                         name) + '&type=all&page=0'],
                    ['Broadcom', 'https://www.broadcom.com/site-search?q=' + urllib.parse.quote(name)],
                    ['TrendMicro', 'https://www.trendmicro.com/en_us/common/cse.html#?cludoquery=' + urllib.parse.quote(
                        name) + '&cludopage=1&cludorefurl=https%3A%2F%2Fwww.trendmicro.com%2Fen_us%2Fbusiness.html&cludorefpt=%231%20in%20Cloud%20Security%20%26%20Endpoint%20Cybersecurity%20%7C%20Trend%20Micro&cludoinputtype=standard' + urllib.parse.quote(
                        name)]],
                   headers=['Source', 'Url']))
    f.write("...\n")

# information display
intro()

# variables and collections initialize for taxii2client in order to use att&ck information
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

# for testing
# T1595.002 T1588.001 T1574.001
# S0385 S0154

# initialize att&ck client from taxii2
lift = attack_client()

# get all the techniques from att&ck
attack_techniques=get_attack_techniques(lift)
# get all the software from att&ck
attack_software=get_attack_software(lift)
# get an incident's techniques from user input. Contains also validation on if the technique provided exists in att&ck
input_techniques=get_incident_techniques(attack_techniques)

# prompt for also software input
software_found=input("Do you want to proceed by adding software? Y/N. Default: Y ")
if software_found=="N" or software_found=="n":
    # if no, the list is empty
    input_sofware=[]
    pass
else:
    # get an incident's software from user input. Contains also validation on if the software provided exists in att&ck
    input_sofware=get_incident_software(attack_software)
print("\n")
print("Searching for possible Groups that attacked you...")
print("\n")
# start searching for possible gorups that performed the attack based on the input provided
try:
    identify_groups(lift, input_techniques, input_sofware)
except KeyboardInterrupt:
    print("Closing WhatHitMe..")
    print("Output saved in this folder.")

