from tkinter import filedialog
from tkinter import ttk
from tkinter import *
import tkinter as tk


class Gui:

	def __init__(self):
		# makes a blank window
		window = tk.Tk()
		window_height = 500
		window_width = 700
		# create the frame
		gui_frame = ttk.Frame(window)
		gui_frame.pack(padx=10, pady=10, fill='x', expand=True)
		filetypes = (('text files', '*.txt'), ('All files', '*.*'))

		# configure the grid
		window.columnconfigure(0, weight=6)
		window.columnconfigure(1, weight=9)

		# change the title pf the window
		window.title('WhatHitMe GUI')

		# create the menu bar
		menubar = Menu(window)
		window.config(menu=menubar)
		file_menu = Menu(menubar, tearoff=False)

		# add an exit item to the menu
		file_menu.add_command(label='Exit', command=window.destroy)
		file_menu.add_separator()
		menubar.add_cascade(label='Menu', menu=file_menu)

		# get the screen dimension
		screen_width = window.winfo_screenwidth()
		screen_height = window.winfo_screenheight()
		# find the center point
		center_x = int(screen_width / 2 - window_width / 2)
		center_y = int(screen_height / 2 - window_height / 2)
		# set the position of the window to the center of the screen
		window.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

		# create the technique field
		message_technique = ttk.Label(gui_frame, text="*PLease input the technique(s):")
		# makes the widget visible
		message_technique.grid(column=0, row=0, sticky=tk.NW, padx=5, pady=5)
		# create the text field
		techniquevar = tk.StringVar()
		technique_entry = ttk.Entry(gui_frame, textvariable=techniquevar)
		technique_entry.grid(column=0, row=1, sticky=tk.NW, padx=5, pady=5)
		technique_entry.focus()
		# get the user provided value
		technique = technique_entry.get()

		# create the technique file explorer
		technique_file = filedialog.askopenfile(title='Select a file', filetypes=filetypes)
		button_explore = ttk.Button(gui_frame, text='input file', command=technique_file)
		button_explore.grid(column=0, row=2, sticky=tk.NW, padx=5, pady=5)

		# create the software field
		message_software = ttk.Label(gui_frame, text="PLease input the software:")
		# makes the widget visible
		message_software.grid(column=0, row=3, sticky=tk.NW, padx=5, pady=5)
		# create the text field
		softwarevar = tk.StringVar()
		software_entry = ttk.Entry(gui_frame, textvariable=softwarevar)
		software_entry.grid(column=0, row=4, sticky=tk.NW, padx=5, pady=5)
		# get the user provided value
		software = software_entry.get()

		# create the software file explorer
		software_file = filedialog.askopenfile(title='Select a file', filetypes=filetypes)
		button_explore = ttk.Button(gui_frame, text='input file', command=software_file)
		button_explore.grid(column=0, row=5, sticky=tk.NW, padx=5, pady=5)

		# create searches checkbox
		searchesvar = tk.IntVar()
		searches = ttk.Checkbutton(gui_frame, text='searches', variable=searchesvar, onvalue=1, offvalue=0)
		searches.grid(column=0, row=6, sticky=tk.NW, padx=5, pady=5)

		# create the execution button
		button = ttk.Button(gui_frame, text="run")
		button.grid(column=1, row=7, sticky=tk.SE, padx=5, pady=5)

		message_technique = ttk.Label(gui_frame, text="* = Required Fields!")
		message_technique.grid(column=0, row=8, sticky=tk.SW, padx=5, pady=5)
		# mainloop = keeps the window open on the screen
		window.mainloop()

