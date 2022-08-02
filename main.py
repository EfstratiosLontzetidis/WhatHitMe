import re

def get_incident_techniques(list):
    flag1=True
    while flag1:
        technique = input("Give us a technique in the format of T1XXX or T1XXX.XXX. Type exit to continue: ")
        if re.match("T[0-9]*\.[0-9]+|T[0-9]+", technique, re.IGNORECASE):
            print("yes")
            list.append(technique)
        elif technique == "exit":
            flag1 = False
        else:
            print("no")
    return list

def get_incident_software(list):
    flag2=True
    while flag2:
        software = input("Give us a software in the format of SXXXX. Type exit to continue: ")
        if re.match("S[0-9]+", software, re.IGNORECASE):
            print("yes")
            list.append(software)
        elif software == "exit":
            flag2 = False
        else:
            print("no")
    return list

incident_techniques=[]
incident_sofware=[]

print(get_incident_techniques(incident_techniques))
print(get_incident_software(incident_sofware))






