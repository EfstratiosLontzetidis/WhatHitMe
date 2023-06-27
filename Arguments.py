from argparse import RawDescriptionHelpFormatter
from termcolor import colored
from sys import platform
import argparse
import pathlib
import git
import os


class Arguments:

    def __init__(self):
        self.parser = self.ConfigureParser()
        args = self.parser.parse_args()

        # check if the --update flag is present
        if args.update:
            self.update()
            exit()

        self.technique = []
        self.software = []

        # check if the -t flag is present
        if args.input_technique:
            for i in args.input_technique:
                self.technique.append(i)
            # Check if the -s flag is present
            if args.input_software:
                for i in args.input_software:
                    self.software.append(i)


        # check if the -ft flag is present
        elif args.file_technique:
            file_techniques = []
            for i in args.file_technique:
                file_techniques.append(i.strip('\n'))
            self.technique = file_techniques

            # Check if the -fs flag is present
            if args.file_software:
                file_software = []
                for i in args.file_software:
                    file_software.append(i.strip('\n'))
                    self.software = file_software

        self.searches = args.searches
        self.outfile = args.outfile
        if args.matrix:
            self.matrix=args.matrix
        else:
            self.matrix = "0"

        if args.matrix:
            self.version = args.version
        else:
            self.version = "13.1"


    def update(self):
        print(colored('[!]', 'yellow', attrs=['bold']) + ' Checking for updates...')
        #get path of the directory of the repo
        repo_path = os.path.dirname(__file__)
        # find the repo of the program
        repo = git.Repo(repo_path)
        # stash any changes done locally so as to not have any problem the pull request
        repo.git.stash()
        # git pull to do the update
        repo.remotes.origin.pull()
        # check if the system is Linux
        if platform == "linux" or platform == "linux2":
            # Give execute permition to the main program after the update
            cmd = '/usr/bin/chmod +x ' + str(repo_path) + '/whathitme.py'
            # execute the command
            os.system(cmd)
        print(colored('[+]', 'green', attrs=['bold']) + ' Updated successfully')


    def ConfigureParser(self):
        parser = argparse.ArgumentParser(prog='whathitme.py', description="""""", epilog= '''Developers: Efstratios Lontzetidis (https://github.com/EfstratiosLontzetidis)
            Konstantinos Pantazis (https://github.com/kostas-pa)''', formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument('-m', '--matrix', default="0",nargs='*', dest="matrix", metavar='Matrix',
                            help='Input the preferred matrix. (default) 0 for Enterprise, 1 for Mobile, 2 for ICS')
        parser.add_argument('-v', '--version', default="13.1", nargs='*', dest="version", metavar='version',
                            help='Input the preferred version. !!Always use the latest as no download occurs from previous versions: (default) 13.1')
        parser.add_argument('-t', '--technique', nargs='*', dest="input_technique", metavar='Technique', help='Input the technique. If there are multiple include them like so "-t T1XXX T1XXX"')
        parser.add_argument('-s', '--software', nargs='*', dest="input_software", metavar='Software', help='Input the software. If there are multiple include them like so "-s S0XXX S0XXX"')
        parser.add_argument('-ft', '--filetech', dest="file_technique", metavar='File techniques', help='Input a file containing the techniques. Supported file formats: txt', type=argparse.FileType('r'))
        parser.add_argument('-fs', '--filesoft', dest="file_software", metavar='File software', help='Input a file containing the software. Supported file formats: txt', type=argparse.FileType('r'))
        parser.add_argument('-ss', '--searches', dest='searches', help="Reveals more info and links about the potential APTs", action='store_true')
        parser.add_argument('-o', '--output', nargs='?', dest="outfile", help='The file to save the results')
        parser.add_argument('--update', dest='update', help="Check for updates", action='store_true')
        return parser