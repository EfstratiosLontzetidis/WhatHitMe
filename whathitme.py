#!/usr/bin/env python3

from Arguments import Arguments
from termcolor import colored
from colorama import init
from pyfiglet import Figlet
import magic
import sys
import os
import urlib3


def main():
	try:
		init()
		# This is just the banner
		ascii_art = Figlet(font='big')
		print(colored(ascii_art.renderText('What Hit Me'), 'blue'))
		# Initialize the arguments
		arguments = Arguments()

		# If no technique is provide with -t or -ft then exit
		if not arguments.technique:
			arguments.parser.print_help(sys.stderr)
			exit(1)

		magic.Magic(arguments.technique, arguments.software, arguments.outfile, searches=arguments.searches)

	except KeyboardInterrupt:
		print('\nExiting...\n')
		os._exit(0)
	except urllib3.exceptions.SSLError:
		print('\nToo much traffic generated, please try again in a minute or two\n')
		os._exit(0)


if __name__ == '__main__':
	main()
