#!/usr/bin/env python

import sqlite3
import sys

def create():
	conn = sqlite3.connect('SweetSecurity.db')
	c = conn.cursor()
	# Create table
	c.execute('''CREATE TABLE hosts(hostname text, ip4 integer, mac text, vendor text)''')
	# Save (commit) the changes
	conn.commit()
	conn.close()

def show():
	conn = sqlite3.connect('SweetSecurity.db')
	c = conn.cursor()
	for row in c.execute('SELECT * FROM hosts ORDER BY ip4'):
		print row
	conn.close()

if __name__=="__main__":
	action=str(sys.argv[1])
	#python db.py create
	if (action=="create"):
		create()
	#python db.py show
	elif (action=="show"):
		show()
	else:
		print("The only supported actions are create and show...")
