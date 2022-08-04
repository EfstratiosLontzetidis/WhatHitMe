[![Python 3](https://img.shields.io/badge/Python-3-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# WhatHitMe

WhatHitMe is a Python3 tool which provides the possible Groups that may have attacked you in an incident, based on specific Techniques and Software you have identified (MITRE ATT&CK). It also provides searches to known sources for these Groups to get a better insight of what you might had been facing! These sources are:

• OpenCTI

• Alienvault OTX

• Mandiant

• IBM X-FORCE

• ETDA

• Rapid7

• Check Point

• Broadcom

• TrendMicro

• HackerNews

• More coming soon!

It runs in Linux/Unix systems but it can run on Windows as well.

# Usage

• You have to have Python3 installed in your system or you can download it from https://www.python.org/downloads/

• You will also need pip which if you don't have just run ```sudo apt install python3-pip``` for linux.

• Download the program or clone the repository in your system `git clone https://github.com/EfstratiosLontzetidis/WhatHitMe.git`

• Go to the WhatHitMe folder ```cd WhatHitMe```

• First run the command ```pip install -r requirements.txt```

• After that you can simply run whathitme to show the help guide with the command ```python3 whathitme.py -h```.

• It is recommended to run the **--update** flag before initiating the tool.

• Techniques are mandatory to be supplied to the tool, seperated by spaces (or lines if it is a file). The software flags are optiona;.

![image](https://user-images.githubusercontent.com/50456183/182891989-07a6060d-0df9-434c-a7d1-9e2dc85c2409.png)

# Examples: 
            
```python3 whathitme.py -t T1059 T1048.003 T1133 -o groups.txt``` -> give to the program specific techniques to search groups for, and save the results to a file

```python3 whathitme.py -t T1059 T1048.003 T1133 -s S0154 S0024 -o groups.txt``` -> include software also

```python3 whathitme.py -t T1059 T1048.003 T1133 -s S0154 S0024 -ss``` -> include searches for the groups identified also.

```python3 whathitme.py -ft techniques.txt -fs software.txt``` -> give to the program specific techniques and software from a file to search groups for

# Sample Results (with searches)

*****Possible Group Found*****

Name     ID     ATT&CK URL                             ATT&CK Navigator URL
-------  -----  -------------------------------------  ----------------------------------------------------------------------------------------------------------------------------------------
Chimera  G0114  https://attack.mitre.org/groups/G0114  https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0114%2FG0114-enterprise-layer.json

Searches regarding this group:Source                       Url
---------------------------  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
OpenCTI (req. login)         https://demo.opencti.io/dashboard/search/Chimera
Alienvault OTX (req. login)  https://otx.alienvault.com/browse/global/pulses?q=Chimera&include_inactive=0&sort=-modified&page=1&limit=10&indicatorsSearch=Chimera
Mandiant                     https://www.mandiant.com/search?search=Chimera
IBM X-FORCE (req. login)     https://exchange.xforce.ibmcloud.com/search/Chimera
ETDA                         https://apt.etda.or.th/cgi-bin/listgroups.cgi?c=&v=&s=&m=&x=Chimera
Rapid7                       https://docs.rapid7.com/search/?q=Chimera&filters=productname_InsightIDR&page=0
Check Point                  https://threatpoint.checkpoint.com/ThreatPortal/search?pattern=Chimera&type=all&page=0
Broadcom                     https://www.broadcom.com/site-search?q=Chimera
TrendMicro                   https://www.trendmicro.com/en_us/common/cse.html#?cludoquery=Chimera&cludopage=1&cludorefurl=https%3A%2F%2Fwww.trendmicro.com%2Fen_us%2Fbusiness.html&cludorefpt=%231%20in%20Cloud%20Security%20%26%20Endpoint%20Cybersecurity%20%7C%20Trend%20Micro&cludoinputtype=standardChimera...
*****Possible Group Found*****

Name           ID     ATT&CK URL                             ATT&CK Navigator URL
-------------  -----  -------------------------------------  ----------------------------------------------------------------------------------------------------------------------------------------
Wizard Spider  G0102  https://attack.mitre.org/groups/G0102  https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0102%2FG0102-enterprise-layer.json

Searches regarding this group:Source                       Url
---------------------------  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
OpenCTI (req. login)         https://demo.opencti.io/dashboard/search/Wizard%20Spider
Alienvault OTX (req. login)  https://otx.alienvault.com/browse/global/pulses?q=Wizard%20Spider&include_inactive=0&sort=-modified&page=1&limit=10&indicatorsSearch=Wizard%20Spider
Mandiant                     https://www.mandiant.com/search?search=Wizard%20Spider
IBM X-FORCE (req. login)     https://exchange.xforce.ibmcloud.com/search/Wizard%20Spider
ETDA                         https://apt.etda.or.th/cgi-bin/listgroups.cgi?c=&v=&s=&m=&x=Wizard%20Spider
Rapid7                       https://docs.rapid7.com/search/?q=Wizard%20Spider&filters=productname_InsightIDR&page=0
Check Point                  https://threatpoint.checkpoint.com/ThreatPortal/search?pattern=Wizard%20Spider&type=all&page=0
Broadcom                     https://www.broadcom.com/site-search?q=Wizard%20Spider
TrendMicro                   https://www.trendmicro.com/en_us/common/cse.html#?cludoquery=Wizard%20Spider&cludopage=1&cludorefurl=https%3A%2F%2Fwww.trendmicro.com%2Fen_us%2Fbusiness.html&cludorefpt=%231%20in%20Cloud%20Security%20%26%20Endpoint%20Cybersecurity%20%7C%20Trend%20Micro&cludoinputtype=standardWizard%20Spider...

# Developers: 

Efstratios Lontzetidis (https://github.com/EfstratiosLontzetidis)

Konstantinos Pantazis   (https://github.com/kostas-pa)

# ⚠️ Common Issues

• WhatHitMe pulls data from ATT&CK's TAXII server which makes it slow. Give it some time! Have a read from the searches related to the already identified groups while WhatHitME is searching Groups for you!

# New Features Coming Soon

• CTI feeds search based on the identified Groups!

• CTI feed production for a specific group that you and WhatHitMe have identified, so the community can stay updated with latest Group activity!

• Do you have any other feature to suggest? Use the issues tab!

# Sidenote

• If you like this project please consider giving it a star
