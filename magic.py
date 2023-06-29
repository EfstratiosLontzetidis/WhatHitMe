import os

import requests
from termcolor import colored
from tabulate import tabulate
import urllib.parse
import pandas as pd


# this is where all the magic happens
class Magic:
    # for testing purpuses use:
    # T1595.002, T1588.001, T1574.001
    # S0385, S0154

    def __init__(self, technique, software, outfile, matrix, version, searches=False, initiate=True):
        self.technique = technique
        self.software = software
        self.outfile = outfile
        self.searches = searches
        self.matrix=matrix[0]
        self.version = version

        if self.matrix=="0":
            self.matrix="enterprise"
        elif self.matrix=="1":
            self.matrix="mobile"
        elif self.matrix=="2":
            self.matrix="ics"
        else:
            print(colored("[-]", 'red') + " Matrix argument is not correct, try again\n")
            exit()


        if os.path.exists("techniques.xlsx"):
            pass
        else:
            print(colored("[!]", 'yellow') + " Downloading the Techniques excel file for the matrix: " + str(self.matrix)+" and version: "+ str(self.version)+"\n")
            try:
                response = requests.get(
                    "https://attack.mitre.org/docs/"+str(self.matrix)+"-attack-v13.1/"+str(self.matrix)+"-attack-v"+str(self.version)+"-techniques.xlsx")
                response.raise_for_status()
                # Save the file
                with open("techniques.xlsx", "wb") as file:
                    file.write(response.content)
            except Exception as e:
                print(colored("[-]",
                              'red') + " HTTP request was not successful. Please check the provided version of the matrix and check again " + "\n")
                exit()

        if os.path.exists("software.xlsx"):
            pass
        else:
            print(colored("[!]", 'yellow') + " Downloading the Software excel file for the matrix: " + str(self.matrix)+" and version: "+ str(self.version)+"\n")
            try:
                response = requests.get(
                    "https://attack.mitre.org/docs/"+str(self.matrix)+"-attack-v13.1/"+str(self.matrix)+"-attack-v"+str(self.version)+"-software.xlsx")
                response.raise_for_status()
                # Save the file
                with open("software.xlsx", "wb") as file:
                    file.write(response.content)
            except Exception as e:
                print(colored("[-]",
                              'red') + " HTTP request was not successful. Please check the provided version of the matrix and check again " + "\n")
                exit()

        if os.path.exists("groups.xlsx"):
            pass
        else:
            print(colored("[!]", 'yellow') + " Downloading the Groups excel file for the matrix: " + str(self.matrix)+" and version: "+ str(self.version)+"\n")
            try:
                response = requests.get(
                    "https://attack.mitre.org/docs/"+str(self.matrix)+"-attack-v13.1/"+str(self.matrix)+"-attack-v"+str(self.version)+"-groups.xlsx")

                # Save the file
                with open("groups.xlsx", "wb") as file:
                    file.write(response.content)
            except Exception as e:
                print(colored("[-]",
                              'red') + " HTTP request was not successful. Please check the provided version of the matrix and try again " + "\n")
                exit()

        if os.path.exists("campaigns.xlsx"):
            pass
        else:
            print(colored("[!]", 'yellow') + " Downloading the Campaigns excel file for the matrix: " + str(self.matrix)+" and version: "+ str(self.version)+"\n")
            try:
                response = requests.get(
                    "https://attack.mitre.org/docs/"+str(self.matrix)+"-attack-v13.1/"+str(self.matrix)+"-attack-v"+str(self.version)+"-campaigns.xlsx")
                # Save the file
                with open("campaigns.xlsx", "wb") as file:
                    file.write(response.content)
            except Exception as e:
                print(colored("[-]",
                              'red') + " HTTP request was not successful. Please check the provided version of the matrix and try again " + "\n")
                exit()

        if initiate:
            self.analyze()


    def analyze(self):
     # get an incident's techniques. Contains also validation on if the technique exists in att&ck
     techniques_sheet = pd.read_excel("techniques.xlsx", sheet_name="techniques")
     attack_techniques=self.get_attack_techniques(techniques_sheet)
     software_sheet = pd.read_excel("software.xlsx", sheet_name="software")
     attack_software=self.get_attack_software(software_sheet)
     input_techniques = self.get_incident_techniques(self.technique, attack_techniques)
     if self.software is None:
         input_sofware = []
         pass
     else:
        # get an incident's software. Contains also validation on if the software exists in att&ck
        input_sofware = self.get_incident_software(self.software, attack_software)
        print("\n")
        print(colored("[!]", 'yellow') + " Searching for possible Groups and Campaigns that attacked you...")
        print("\n")
        # start searching for possible groups that performed the attack based on the input provided
        self.identify_groups(input_techniques, input_sofware)
        print(colored("[!]", 'yellow') + " End of WhatHitMe's execution")


    # receive the techniques that were identified in an incident
    def get_incident_techniques(self, techniques, attack_techniques):
        # initialize list for storing software from an incident
        incident_techniques = []
        for x in techniques:
            # check if the provided software exists in att&ck matrix
            if x in attack_techniques:
                incident_techniques.append(x.strip('\n'))
                print(colored("[+]", 'green') + f" The technique {x.rstrip()} added to the list!")
        return list(set(incident_techniques))


    # receive the software that were identified in an incident
    def get_incident_software(self, software, attack_software):
        # initialize list for storing software from an incident
        incident_software = []
        for x in software:
            # check if the provided software exists in att&ck matrix
            if x in attack_software:
                incident_software.append(x.strip('\n'))
                print(colored("[+]", 'green') + f" The software {x.rstrip()} added to the list!")
        return list(set(incident_software))


    # pull all the ATT&CK techniques
    def get_attack_techniques(self, techniques):
        # initialize dictionary to store the techniques
        enterprise_techniques=[]
        # loop for all techniques and subtechniques
        for index, row in techniques.iterrows():
            technique = row[list(row.keys())[0]]
            enterprise_techniques.append(technique)
        # return the dictionary of techniques
        return enterprise_techniques


    # pull all the ATT&CK software
    def get_attack_software(self, software):
        # dictionary initialize to store the software
        enterprise_sofware=[]
        # loop for all software
        for index, row in software.iterrows():
            software = row[list(row.keys())[0]]
            enterprise_sofware.append(software)
        # return the dictionary of software
        return enterprise_sofware


    def identify_groups(self, techniques_from_incident, software_from_incident):
        campaigns_sheet = pd.read_excel("campaigns.xlsx", sheet_name="campaigns")
        campaigns_software_sheet = pd.read_excel("campaigns.xlsx", sheet_name="associated software")
        campaigns_technique_sheet = pd.read_excel("campaigns.xlsx", sheet_name="techniques used")
        campaigns_groups_sheet = pd.read_excel("campaigns.xlsx", sheet_name="attributed groups")
        counter=0
        groups_sheet = pd.read_excel("groups.xlsx", sheet_name="groups")
        # Get the column names
        for index, row in groups_sheet.iterrows():
            match = False
            group = row[list(row.keys())[0]]
            group_name = row[list(row.keys())[1]]
            group_desc = row[list(row.keys())[2]]
            group_url = row[list(row.keys())[3]]
            group_associated_groups = row[list(row.keys())[8]]

            techniques_used_sheet = pd.read_excel("groups.xlsx", sheet_name="techniques used")
            if software_from_incident:
                associated_software_sheet = pd.read_excel("groups.xlsx", sheet_name="associated software")

            techniques_used_sheet = pd.read_excel("groups.xlsx", sheet_name="techniques used")
            # Loop through the values list
            group_techniques = []
            group_software = []
            # Loop through each row in the first column of the Excel file
            for index2, row2 in techniques_used_sheet.iterrows():
                if row2.iloc[0] == group:
                    group_techniques.append(row2.iloc[4])

            if software_from_incident:
                for index3, row3 in associated_software_sheet.iterrows():
                    if row3.iloc[0] == group:
                        group_software.append(row3.iloc[4])
            confidence = 0
            if (all(x in group_techniques for x in techniques_from_incident)):
                # if yes, tha flag changes to True
                confidence = (len(techniques_from_incident) / len(group_techniques)) * 100
                confidence_final = round(confidence,2)
                match = True
                # print("!!!!!!Matched group: " + str(group))

            # if the user also gave software as an input
            if software_from_incident:
                # change again the flag to False, since the software should also match
                match = False
                # check if the software that were placed as input from an incident are a sublist from the software used by this group
                if (all(x in group_software for x in software_from_incident)):
                    # if yes, tha flag changes to True
                    confidence2 = (len(software_from_incident) / len(group_software)) * 100
                    confidence_final=round((confidence + confidence2)/2,2)
                    match = True

            # if this group is a possible group that attacked in this incident
            if match == True:
                counter+=1
                # print the results. Also give this function the group name,id,url
                self.print_group_results(group_name,group,group_url, confidence_final)
                # CAMPAIGNS CHECK
                self.identify_campaigns(group,techniques_from_incident, software_from_incident, campaigns_sheet,
                                        campaigns_groups_sheet, campaigns_technique_sheet, campaigns_software_sheet)

        if counter==0:
            print(colored("[-]", 'red') + " No groups found with that criteria")


    def identify_campaigns(self, group, techniques, software, campaigns, campaigns_groups, campaigns_techniques, campaigns_software):

        campaigns_list=[]
        for index, row in campaigns_groups.iterrows():
            if row[4] == group:
                campaigns_list.append(row[0])

        for campaign in campaigns_list:
            for index, row in campaigns.iterrows():
                if row[0] == campaign:
                    campaign_name=row[1]
                    campaign_url=row[3]
            match = False
            campaigns_techniques_list = []
            for index2, row2 in campaigns_techniques.iterrows():
                if row2[0] == campaign:
                    campaigns_techniques_list.append(row2[4])
            confidence = 0
            if (all(x in campaigns_techniques_list for x in techniques)):
                # if yes, tha flag changes to True
                confidence = (len(techniques)/len(campaigns_techniques_list))*100
                confidence_final = round(confidence,2)
                match = True

            if software:
                match=False
                campaigns_software_list = []
                for index3, row3 in campaigns_software.iterrows():
                    if row3[0] == campaign:
                        campaigns_software_list.append(row3[4])

                if (all(x in campaigns_software_list for x in software)):
                    # if yes, tha flag changes to True
                    confidence2=(len(software)/len(campaigns_software_list))*100
                    confidence_final=round((confidence + confidence2)/2,2)
                    match = True
            if match==True:
                self.print_campaign_results(group, campaign_name, campaign, campaign_url, confidence_final)

    def print_campaign_results(self, group, name, id, url, confidence):
        # print group infromation about ATT&CK
        print(colored("*****Possible Campaign: "+str(name)+" found from Group: " +str(group)+ " with confidence: "+str(confidence)+"%*****", 'green'))
        print(tabulate([[name, id, url,
                         'https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fcampaigns%2F' + id + '%2F' + id + '-'+self.matrix+'-layer.json']],
                       headers=['Name', 'ID', 'ATT&CK URL', 'ATT&CK Navigator URL']))
        print("\n")
        # save results to the file given with the -o flag, if present
        if self.outfile is not None:
            self.save_campaign_results(group, name, id, url, confidence)



    # results printing
    def print_group_results(self, name, id, url, confidence):
        # print group infromation about ATT&CK
        print(colored("*****Possible Group "+str(name)+ " found with confidence: "+str(confidence)+"%*****", 'green'))
        print(tabulate([[name, id, url, 'https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2F'+id+'%2F'+id+ '-'+self.matrix+'-layer.json']],
                    headers=['Name', 'ID', 'ATT&CK URL', 'ATT&CK Navigator URL']))
        print("\n")
        # show additional info if the -s flag is present
        if self.searches is not False:
           self.searchess(name, id, url)
        # save results to the file given with the -o flag, if present
        if self.outfile is not None:
            self.save_results(name, id, url, confidence)


    # show additional info if the -s flag is present
    def searchess(self, name, id, url):
        # print searched related with this group
        print(colored("[!]", 'yellow') + " Searches regarding this group:")
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


    def save_campaign_results(self, group, name, id, url, confidence):
        path = self.outfile
        f = open(path, "a")
        f.write("\n")
        f.write("*****Possible Campaign: "+str(name)+" found from Group: " +str(group)+ " with confidence: "+str(confidence)+"%*****")
        f.write("\n")
        f.write("\n")
        f.write(tabulate([[name, id, url,
                        'https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fcampaigns%2F' + id + '%2F' + id + '-'+self.matrix+'-layer.json']],
                      headers=['Name', 'ID', 'ATT&CK URL', 'ATT&CK Navigator URL']))
        f.write("\n")
        f.write("\n")

    # save results to the file given with the -o flag, if present
    def save_results(self, name, id, url, confidence):
        path = self.outfile
        f = open(path, "a")
        f.write("\n")
        f.write("*****Possible Group "+str(name)+ " found with confidence: "+str(confidence)+"%*****")
        f.write("\n")
        f.write("\n")
        f.write(tabulate([[name, id, url,
                        'https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2F' + id + '%2F' + id + '-enterprise-layer.json']],
                      headers=['Name', 'ID', 'ATT&CK URL', 'ATT&CK Navigator URL']))
        f.write("\n")
        f.write("\n")
        if self.searches is not False:
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