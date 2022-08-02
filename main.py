import re
from pyattck import Attck

def get_incident_techniques(list,techniques):
    flag1=True
    while flag1:
        technique = input("Give us a technique in the format of T1XXX or T1XXX.XXX. Type exit to continue: ")
        if technique in techniques.keys():
            print("yes")
            list.append(technique)
        elif technique == "exit":
            flag1 = False
        else:
            print("no")
    return list

def get_incident_software(list, tools):
    flag2=True
    while flag2:
        software = input("Give us a software in the format of SXXXX. Type exit to continue: ")
        if software in tools.keys():
            print("yes")
            list.append(software)
        elif software == "exit":
            flag2 = False
        else:
            print("no")
    return list

def get_enterprise_attack_techniques(client):
    enterprise_techniques={}
    for technique in client.enterprise.techniques:
        enterprise_techniques[technique.external_references[0].external_id]=technique.name
        for subtechnique in technique.techniques:
            enterprise_techniques[subtechnique.external_references[0].external_id]=subtechnique.name
    return enterprise_techniques


def get_enterprise_attack_software(client):
    enterprise_sofware={}
    for software in client.enterprise.tools:
        enterprise_sofware[software.external_references[0].external_id]=software.name
    return enterprise_sofware

#def get_groups_techniques(client):


incident_techniques=[]
incident_sofware=[]
attack = Attck()

attack_techniques=get_enterprise_attack_techniques(attack)
attack_software=get_enterprise_attack_software(attack)
input_techniques=get_incident_techniques(incident_techniques,attack_techniques)

software_found=input("Do you want to proceed by adding softare? Y/N. Default: Y")
if software_found=="Y" or "y" or "":
    input_sofware=get_incident_software(incident_sofware,attack_software)







