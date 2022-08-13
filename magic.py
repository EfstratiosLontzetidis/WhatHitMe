from stix2 import TAXIICollectionSource
from taxii2client.v20 import Collection
from attackcti import attack_client
from termcolor import colored
from tabulate import tabulate
import urllib.parse
import logging
import gui


# this is where all the magic happens
class Magic:
    # for testing purpuses use:
    # T1595.002, T1588.001, T1574.001
    # S0385, S0154

    def __init__(self, technique, software, outfile, ui=False, searches=False, initiate=True):
        self.technique = technique
        self.software = software
        self.outfile = outfile
        self.searches = searches
        self.ui = ui

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

        if initiate:
            if self.ui:
                gui.Gui()
            else:
                self.intro()
                self.analyze()
            

    def analyze(self):
        # initialize att&ck client from taxii2
        lift = attack_client()
        # get all the techniques from att&ck
        attack_techniques = self.get_attack_techniques(lift)
        # get all the software from att&ck
        attack_software = self.get_attack_software(lift)
        # get an incident's techniques. Contains also validation on if the technique exists in att&ck
        input_techniques = self.get_incident_techniques(attack_techniques)
        if self.software is None:
            input_sofware = []
            pass
        else:
            # get an incident's software. Contains also validation on if the software exists in att&ck
            input_sofware = self.get_incident_software(attack_software)
            print("\n")
            print(colored("[!]", 'yellow') + " Searching for possible Groups that attacked you...")
            print("\n")
            # start searching for possible groups that performed the attack based on the input provided
            found = self.identify_groups(lift, input_techniques, input_sofware)
            if found == 0:
                print(colored("[-]", 'red') + " No groups found with that criteria")


    # information about the tool
    def intro(self):
     print("This is a python script that offers the visibility to a defender to know the possible"
              " APT groups that targeted"
              " an organization, after understanding the techniques and software used.\n\n\n")


    # receive the techniques that were identified in an incident
    def get_incident_techniques(self, techniques):
        # initialize list for storing the techniques from an incident
        incident_techniques = []
        # check if the provided technique exists in att&ck matrix
        for x in self.technique:
            if x in techniques.keys():    
                # if it exists in att&ck matrix then import it to a list
                print(colored("[+]", 'green') + f" The technique {x} added to the list!")
                incident_techniques.append(x)
            else:
                # if provided input does not exist, loop again
                print(colored("[-]", 'red') + f" The technique {x} does not exist in ATT&CK")
        # return list with techniques supplied from an incident
        return incident_techniques


    # receive the software that were identified in an incident
    def get_incident_software(self, tools):
        # initialize list for storing software from an incident
        incident_software = []
        for x in self.software:
            if x in tools.keys():
                # check if the provided software exists in att&ck matrix
                print(colored("[+]", 'green') + f" The software {x} added to the list!")
                incident_software.append(x)
            else:
                # if provided input does not exist, loop again
                print(colored("[-]", 'red') + f" The software {x} does not exist in ATT&CK")
                # return list with software supplied from an incident
        return incident_software


    # pull all the ATT&CK techniques
    def get_attack_techniques(self, client):
        # initialize dictionary to store the techniques
        enterprise_techniques={}
        # loop for all techniques and subtechniques
        for technique in client.get_techniques():
           # in the dictionary store in the key field the technique ID and in the value field the technique name
           enterprise_techniques[technique['external_references'][0]['external_id']]=technique['name']
        # return the dictionary of techniques
        return enterprise_techniques


    # pull all the ATT&CK software
    def get_attack_software(self, client):
        # dictionary initialize to store the software
        enterprise_sofware={}
        # loop for all software
        for software in client.get_software():
            # in the dictionary store in the key field the software ID and in the value field the software name
            enterprise_sofware[software['external_references'][0]['external_id']]=software['name']
        # return the dictionary of software
        return enterprise_sofware


    def identify_groups(self, lift, techniques_from_incident, software_from_incident):
        count = 0
        # initialize match flag to catch matched groups
        match = False
        # initialize lists to store the techniques and software used by each group
        techniques_from_group = []
        tools_from_group = []
        # get all the groups from the att&ck client
        groups = lift.get_groups()
        counter = 0
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
                match = True
                count = count + 1
            # if the user also gave software as an input
            if software_from_incident:
                # change again the flag to False, since the software should also match
                match = False
                count = count - 1
                # get the software used by this group through the att&ck client
                group_software=lift.get_software_used_by_group(groups[counter])
                # for every software (tool) in the software used by this group
                for tool in group_software:
                   # store the software id
                   tools_from_group.append(tool['external_references'][0]['external_id'])
                # check if the software that were placed as input from an incident are a sublist from the software used by this group
                if(all(x in tools_from_group for x in software_from_incident)):
                    # if yes, tha flag changes to True
                    match = True
                    count = count + 1
            # if this group is a possible group that attacked in this incident
            if match == True:
               # print the results. Also give this function the group name,id,url
               self.print_results(group_name,group_id,group_url)
            # at the end of the loop, re-initialize the flag, empty lists and increase the loop counter
            techniques_from_group.clear()
            tools_from_group.clear()
            match = False
            counter = counter + 1
        return count


    # results printing
    def print_results(self, name, id, url):
        # print group infromation about ATT&CK
        print(colored("*****Possible Group Found*****", 'green'))
        print(tabulate([[name, id, url, 'https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2F'+id+'%2F'+id+'-enterprise-layer.json']],
                    headers=['Name', 'ID', 'ATT&CK URL', 'ATT&CK Navigator URL']))
        print("\n")
        # show additional info if the -s flag is present
        if self.searches is not False:
           self.searchess(name, id, url)
        # save results to the file given with the -o flag, if present
        if self.outfile is not None:
            self.save_results(name, id, url)


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


    # save results to the file given with the -o flag, if present
    def save_results(self, name, id, url):
        path = self.outfile
        f = open(path, "a")
        f.write("\n")
        f.write("*****Possible Group Found*****")
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