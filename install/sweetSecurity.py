import os, shutil, sqlite3

def install(chosenInterface):
	print "Updating MAC Address List for NMAP"
	shutil.move('/usr/share/nmap/nmap-mac-prefixes','/usr/share/nmap/nmap-mac-prefixes_orig')
	shutil.copyfile('nmap/nmap-mac-prefixes','/usr/share/nmap/nmap-mac-prefixes')
	
	#Install SweetSecurity Code
	print "Installing Sweet Security Code"
	#Configure Sweet Security Scripts
	if os.path.exists('/opt/sweetsecurity'):
		shutil.rmtree('/opt/sweetsecurity')
	shutil.copytree('sweetSecurity/','/opt/sweetsecurity')
	if not os.path.isfile('/opt/sweetsecurity/SweetSecurity.db'):
		conn = sqlite3.connect('/opt/sweetsecurity/SweetSecurity.db')
		c = conn.cursor()
		c.execute('''CREATE TABLE configuration (object text, value text)''')
		c.execute('''CREATE TABLE hosts(hostname text, nickname text, ip4 integer, mac text, vendor text, ignore integer, active integer, firstSeen text, lastSeen text)''')
		c.execute('''CREATE TABLE dfgw(hostname text, ip4 integer, mac text, vendor text)''')
		query = "INSERT INTO configuration VALUES ('%s','%s')" % ('interface',str(chosenInterface))
		c.execute(query)
		query = "INSERT INTO configuration VALUES ('webCert','development')"
		c.execute(query)
		conn.commit()
		conn.close()
	
	shutil.copyfile('systemd/sweetsecurity.service','/etc/systemd/system/sweetsecurity.service')
	os.popen('sudo systemctl enable sweetsecurity.service').read()

def addWebCreds(address,user,pwd):
	conn = sqlite3.connect('/opt/sweetsecurity/SweetSecurity.db')
	c = conn.cursor()
	query = "INSERT INTO configuration VALUES ('%s','%s')" % ('webAddress',str(address))
	c.execute(query)
	query = "INSERT INTO configuration VALUES ('%s','%s')" % ('webUser',str(user))
	c.execute(query)
	query = "INSERT INTO configuration VALUES ('%s','%s')" % ('webPass',str(pwd))
	c.execute(query)
	conn.commit()
	conn.close()