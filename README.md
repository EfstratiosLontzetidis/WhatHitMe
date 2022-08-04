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

• Go to the LFITester folder

• First run the command ```sudo chmod +x setup.sh```

• Then run ```sudo ./setup.sh``` which will automatically install the required packages  

• After that you can simply run lfitester as a command.

• It is recommended to run the **--update** flag before initiating the tool.

# Examples: 
            


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
