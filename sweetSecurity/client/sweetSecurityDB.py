#!/usr/bin/env python
import os, sqlite3, sys

dbPath="/opt/sweetsecurity/client/SweetSecurity.db"

def getDfgw():
	dfgw={'dfgw': None, 'dfgwMAC': None}
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	for dfgwRow in c.execute('SELECT * from dfgw'):
		dfgw['dfgw']=dfgwRow[1]
		dfgw['dfgwMAC']=dfgwRow[2]
	conn.close()
	return dfgw

def getWebAddress():
	webAddress=None
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	existsQuery=c.execute('SELECT * from configuration where object = "webAddress"')
	exists=existsQuery.fetchone()
	webAddress=exists[1]
	conn.close()
	return webAddress

def create():
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	c.execute('''CREATE TABLE configuration (object text, value text)''')
	c.execute('''CREATE TABLE hosts(hostname text, nickname text, ip4 integer, mac text, vendor text, ignore integer, active integer, firstSeen text, lastSeen text)''')
	c.execute('''CREATE TABLE dfgw(hostname text, ip4 integer, mac text, vendor text)''')
	conn.commit()
	conn.close()

def show():
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	print "CONFIG TABLE"
	for row in c.execute('SELECT * from configuration'):
		print row
	print "HOSTS TABLE"
	for row in c.execute('SELECT * FROM hosts ORDER BY ip4'):
		print row
	print "DFGW TABLE"
	for row in c.execute('SELECT * FROM dfgw'):
		print row
	conn.close()

def showSpoofed():
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	for row in c.execute('SELECT ip4,mac,vendor FROM hosts where active = 1 and ignore = 0'):
		print row
	conn.close()

def dontSpoof(mac):
	conn = sqlite3.connect(dbPath) 
	c = conn.cursor()
	t = (mac,)
	existsQuery = c.execute('SELECT * FROM hosts WHERE mac=?', t)
	exists=existsQuery.fetchone()
	if (exists==None):
		return 'Invalid MAC Address, issue the show command to find known MAC addresses'
	c.execute("UPDATE hosts SET ignore = 1 where mac=?",t)
	conn.commit()
	conn.close()
	return "Device %s no longer being spoofed" % mac

def spoof(mac):
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	t = (mac,)
	existsQuery = c.execute('SELECT * FROM hosts WHERE mac=?', t)
	exists=existsQuery.fetchone()
	if (exists==None):
		return 'Invalid MAC Address, issue the show command to find known MAC addresses'
	c.execute("UPDATE hosts SET ignore = 0 where mac=?",t)
	conn.commit()
	conn.close()
	return "Device %s is now being spoofed" % mac

def getDeviceSpoofStatus(mac):
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	t = (mac,)
	existsQuery = c.execute('SELECT ignore FROM hosts WHERE mac=?', t)
	exists=existsQuery.fetchone()
	if (exists==None):
		return 'Invalid MAC Address, issue the show command to find known MAC addresses'
	conn.commit()
	conn.close()
	return exists

def changeCert(type):
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	if type=='production':
		c.execute("UPDATE configuration SET value = 'production' where object = 'webCert'")
	elif type == 'development':
		c.execute("UPDATE configuration SET value = 'development' where object = 'webCert'")
	else:
		return None
	conn.commit()
	conn.close()
	return "Updated cert type to %s" % type

def changeInterface(interfaceName):
	t = (interfaceName,)
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	c.execute("UPDATE configuration SET value = ? where object = 'interface'", t)
	conn.commit()
	conn.close()
	return "Updated interface to %s" % interfaceName

def changeServer(serverName):
	t = (serverName,)
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	c.execute("UPDATE configuration SET value = ? where object = 'webAddress'", t)
	conn.commit()
	conn.close()
	return "Updated webAddress to %s" % serverName

def changeWebCreds(username,password):
	tU = (username,)
	tP = (password,)
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	c.execute("UPDATE configuration SET value = ? where object = 'webUser'", tU)
	c.execute("UPDATE configuration SET value = ? where object = 'webPass'", tP)
	conn.commit()
	conn.close()
	return "Updated web credentials"

if __name__=="__main__":
	action=str(sys.argv[1])
	#python db.py create
	if (action=="create"):
		create()
	#python db.py show
	elif (action=="show"):
		show()
	#python db.py showSpoofed
	elif (action=="showSpoofed"):
		showSpoofed()
	elif (action=="ignore"):
		if len(sys.argv) == 2:
			sys.exit('Need to supply a MAC address')
		mac=str(sys.argv[2])
		dontSpoof(mac)
	elif (action=="spoof"):
		if len(sys.argv) == 2:
			sys.exit('Need to supply a MAC address')
		mac=str(sys.argv[2])
		spoof(mac)
	elif (action=="cert"):
		if len(sys.argv) == 2:
			sys.exit('Need to state development or production')
		if sys.argv[2].lower() == 'production':
			print changeCert('production')
		elif sys.argv[2].lower() == 'development':
			print changeCert('development')
		else:
			sys.exit('Unknown cert type, must be development or production')
	elif (action=="interface"):
		if len(sys.argv) == 2:
			sys.exit('Must supply an interface name')
		print changeInterface(sys.argv[2])
	elif (action =="server"):
		if len(sys.argv) == 2:
			sys.exit('Must supply a server name')
		print changeServer(sys.argv[2])
	elif (action =="webCreds"):
		if len(sys.argv) == 2:
			sys.exit('Must supply a username and password. EX sweetSecurityDB.py webCreds user pass')
		elif len(sys.argv) == 3:
			sys.exit('Must supply a username and password. EX sweetSecurityDB.py webCreds user pass')
		print changeWebCreds(sys.argv[2],sys.argv[3])
	else:
		print("The only supported actions are create, show, showSpoofed, spoof, ignore, cert, and interface...")
