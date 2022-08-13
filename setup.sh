#!/usr/bin/env bash

yellow="\e[1;33m"
boldgreen="\033[1;32m"
nocolor="\033[0m"

echo -e "${yellow}Installing the required packages...${nocolor}"
pip3 install -r requirements.txt

echo -e "${yellow}Making whathitme.py executable...${nocolor}"
chmod +x whathitme.py

echo -e "${yellow}Creating symlink for whathitme.py...${nocolor}"
ln -s $(pwd)/whathitme.py /bin/whathitme

echo -e "${boldgreen}Everything\'s setup! Simply run whathitme to get started!${nocolor}"