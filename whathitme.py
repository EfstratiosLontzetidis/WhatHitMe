#!/usr/bin/env python3
from Arguments import Arguments
from termcolor import colored
from colorama import init
from pyfiglet import Figlet
import magic
import sys
import os


def main():
	try:
		init()
		# This is just the banner
		ascii_art = Figlet(font='big')
		print(colored(ascii_art.renderText('What Hit Me'), 'blue'))
		# Initialize the arguments
		arguments = Arguments()
		# If no technique is provided with -t or -ft and no --gui flag then exit
		if not arguments.technique and not arguments.ui:
			arguments.parser.print_help(sys.stderr)
			exit(1)

		magic.Magic(arguments.technique, arguments.software, arguments.outfile,  arguments.ui, searches=arguments.searches)

	except KeyboardInterrupt:
		print('\nExiting...\n')
		os._exit(0)


if __name__ == '__main__':
	main()
