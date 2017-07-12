import os, shutil, sqlite3

def installClient(chosenInterface):
	print "Updating MAC Address List for NMAP"
	shutil.move('/usr/share/nmap/nmap-mac-prefixes','/usr/share/nmap/nmap-mac-prefixes_orig')
	shutil.copyfile('nmap/nmap-mac-prefixes','/usr/share/nmap/nmap-mac-prefixes')
	
	#Install SweetSecurity Code
	print "Installing Sweet Security Client"
	#Configure Sweet Security Scripts
	if os.path.exists('/opt/sweetsecurity/client'):
		shutil.rmtree('/opt/sweetsecurity/client')
	shutil.copytree('sweetSecurity/client','/opt/sweetsecurity/client')
	if not os.path.isfile('/opt/sweetsecurity/client/SweetSecurity.db'):
		conn = sqlite3.connect('/opt/sweetsecurity/client/SweetSecurity.db')
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

def installServer():
	print "Installing Sweet Security Server"
	# Configure Sweet Security Scripts
	if os.path.exists('/opt/sweetsecurity/server'):
		shutil.rmtree('/opt/sweetsecurity/server')
	shutil.copytree('sweetSecurity/server', '/opt/sweetsecurity/server')
	if not os.path.isfile('/opt/sweetsecurity/server/SweetSecurity.db'):
		conn = sqlite3.connect('/opt/sweetsecurity/server/SweetSecurity.db')
		c = conn.cursor()
		c.execute('''CREATE TABLE configuration (object text, value text)''')
		query = "INSERT INTO configuration VALUES ('webCert','development')"
		c.execute(query)
		conn.commit()
		conn.close()

	shutil.copyfile('systemd/sweetsecurity_server.service', '/etc/systemd/system/sweetsecurity_server.service')
	os.popen('sudo systemctl enable sweetsecurity_server.service').read()

def addWebCreds(address,user,pwd,location):
	if location == 'client':
		conn = sqlite3.connect('/opt/sweetsecurity/client/SweetSecurity.db')
	elif location == 'server':
		conn = sqlite3.connect('/opt/sweetsecurity/server/SweetSecurity.db')
	c = conn.cursor()
	query = "INSERT INTO configuration VALUES ('%s','%s')" % ('webAddress',str(address))
	c.execute(query)
	query = "INSERT INTO configuration VALUES ('%s','%s')" % ('webUser',str(user))
	c.execute(query)
	query = "INSERT INTO configuration VALUES ('%s','%s')" % ('webPass',str(pwd))
	c.execute(query)
	conn.commit()
	conn.close()