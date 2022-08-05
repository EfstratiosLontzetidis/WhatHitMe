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

• Techniques are mandatory to be supplied to the tool, seperated by spaces (or lines if it is a file). The software flags are optional.

![image](https://user-images.githubusercontent.com/50456183/182891989-07a6060d-0df9-434c-a7d1-9e2dc85c2409.png)

# Examples: 
            
```python3 whathitme.py -t T1595.002 T1588.001 T1574.001 -o groups.txt``` -> give to the program specific techniques to search groups for, and save the results to a file

```python3 whathitme.py -t T1588.001 T1574.001 -s S0385 S0154 -o groups.txt``` -> include software also

```python3 whathitme.py -t T1588.001 T1574.001 -s S0385 S0154 -ss``` -> include searches for the groups identified also.

```python3 whathitme.py -ft techniques.txt -fs software.txt``` -> give to the program specific techniques and software from a file to search groups for

# Sample Results (with searches)

![image](https://user-images.githubusercontent.com/50456183/182895230-939d8acc-cedc-4144-b7ce-d0f138a2d65a.png)

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
