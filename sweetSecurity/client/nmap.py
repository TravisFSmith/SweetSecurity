import fcntl, os, re, socket, sqlite3, struct
import logging
from datetime import datetime
import xml.etree.ElementTree as ET

#Local Scripts
import logs
import server
import sweetSecurityDB

dbPath="/opt/sweetsecurity/client/SweetSecurity.db"

def getSystemDfgw():
	with open("/proc/net/route") as file:
		for line in file:
			fields = line.strip().split()
			if fields[1] != '00000000' or not int(fields[3], 16) & 2:
				continue
			return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def getSpoofingInterface():
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	c.execute('SELECT * FROM configuration where object = "interface"')
	result=c.fetchone()
	device=result[1]
	conn.commit()
	conn.close()
	return device

def getIP(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

def getNetmask(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netmask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, struct.pack('256s',ifname))[20:24])
	netmask = sum([bin(int(x)).count('1') for x in netmask.split('.')])
	return netmask

def convertMac(macAddress):
	if re.match(r"^[A-za-z0-9]{2}-[A-za-z0-9]{2}-[A-za-z0-9]{2}-[A-za-z0-9]{2}-[A-za-z0-9]{2}-[A-za-z0-9]{2}$",macAddress):
		macAddress=macAddress.replace('-','')
	elif re.match(r"^[A-za-z0-9]{2}:[A-za-z0-9]{2}:[A-za-z0-9]{2}:[A-za-z0-9]{2}:[A-za-z0-9]{2}:[A-za-z0-9]{2}$",macAddress):
		macAddress=macAddress.replace(':','')
	return macAddress.upper()

def pingSweep():
	logger = logging.getLogger('SweetSecurityLogger')
	if not os.path.exists('/opt/sweetsecurity/client/nmap_scans'):
		os.makedirs('/opt/sweetsecurity/client/nmap_scans')
	device=str(getSpoofingInterface())
	ip = getIP(device)
	netmask = getNetmask(device)
	dfgwInfo = sweetSecurityDB.getDfgw()
	dfgw = dfgwInfo['dfgw']
	if dfgw is None:
		dfgw=getSystemDfgw()
	webAddress=sweetSecurityDB.getWebAddress()
	logger.info('Beginning Ping Sweep')

	os.popen("sudo nmap -sn %s/%s -e %s -oX /opt/sweetsecurity/client/nmap_scans/pingSweep.xml" % (ip,str(netmask),device)).read()
	file='/opt/sweetsecurity/client/nmap_scans/pingSweep.xml'
	try:
		tree = ET.parse(file)
		root = tree.getroot()
		body=''
		conn = sqlite3.connect(dbPath)
		c = conn.cursor()
		#Set everything to inactive to avoid trying to spoof a missing device
		c.execute("UPDATE hosts SET active = 0")
		conn.commit()
		conn.close()
		#Parse the nmap.xml file
		for host in root.findall("./host"):
			ipaddress=""
			macaddress=""
			hostname=""
			hoststate=""
			macvendor=""
			for status in host.findall("./status"):
				hoststate=status.get('state')
				hoststate=hoststate.rstrip()
			for ip in host.findall("./address"):
				addressType=ip.get('addrtype')
				if (addressType == "mac"):
					macaddress=ip.get('addr')
					macaddress=macaddress.rstrip()
					macaddress=convertMac(macaddress)
					macvendor=ip.get('vendor')
					if (macvendor is None):
						macvendor='Unknown'
					macvendor=macvendor.rstrip()
				if (addressType == "ipv4"):
					ipaddress=ip.get('addr')
					ipaddress=ipaddress.rstrip()
			for hostname in host.findall("./hostnames/hostname"):
				hostname=hostname.get('name')
				hostname=hostname.rstrip()
			#If mac address is missing, it's the local interface, no need to spoof or monitor
			#Also don't spoof the default gateway for obvious reasons
			#Don't spoof the es/kibana/apache server if it's on another device
			if (len(macaddress) > 0 and ipaddress != dfgw and ipaddress != webAddress):
				if (len(hostname) < 1):
					hostname="%s (%s)" % (ipaddress,macaddress)
				conn = sqlite3.connect(dbPath)
				c = conn.cursor()
				t = (macaddress,)
				existsQuery = c.execute('SELECT * FROM hosts WHERE mac=?', t)
				exists=existsQuery.fetchone()
				if (exists==None):
					#Add entry to local DB
					logger.info('New device discovered: hostname=%s, ip=%s, mac=%s, vendor=%s',hostname,str(ipaddress),macaddress,macvendor)
					query = "INSERT INTO hosts VALUES ('%s','%s','%s','%s','%s',0,1,'%s','%s')" % (hostname,hostname,str(ipaddress),macaddress,macvendor,datetime.now().strftime("%Y-%m-%d %H:%M:%S"),datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
					c.execute(query)
				else:
					if hostname != exists[0]:
						logger.info('Update hostname of device %s from %s to %s',macaddress,exists[0],hostname)
						c.execute('UPDATE hosts SET hostname=? WHERE mac=?', (hostname,macaddress))
					if str(ipaddress) != exists[2]:
						logger.info('Update ip of device %s from %s to %s',macaddress,exists[1],ipaddress)
						c.execute('UPDATE hosts SET ip4=? WHERE mac=?', (ipaddress,macaddress))
					logger.info('Device Scanned: %s',macaddress)
					c.execute('UPDATE hosts SET active = 1, lastSeen=? WHERE mac=?', (datetime.now(),macaddress))
				conn.commit()
				conn.close()
				#Change to 0 if you want default action to spoof device
				ignore='1'
				server.addDevice(hostname,str(ipaddress),macaddress,macvendor,ignore)
			elif ipaddress == dfgw:
				conn = sqlite3.connect(dbPath)
				c = conn.cursor()
				t = (macaddress,)
				c.execute('SELECT * FROM dfgw WHERE mac=?', t)
				if (c.fetchone()==None):
					logger.info('New default gateway discovered: %s',str(ipaddress))
					#Add entry to local DB
					query = "INSERT INTO dfgw VALUES ('%s','%s','%s','%s')" % (hostname,str(ipaddress),macaddress,macvendor)
					c.execute(query)
				conn.commit()
				conn.close()
	except:
		logger.info("Invalid Ping Sweep XML File")

def portScan():
	logger = logging.getLogger('SweetSecurityLogger')
	logger.info("Beginning port scan")
	if not os.path.exists('/opt/sweetsecurity/client/nmap_scans'):
		os.makedirs('/opt/sweetsecurity/client/nmap_scans')
	try:
		deviceList=[]
		conn = sqlite3.connect(dbPath)
		c = conn.cursor()
		for row in c.execute('SELECT * FROM hosts where active = 1'):
			deviceInfo={'ip': row[2], 'mac': row[3]}
			deviceList.append(deviceInfo)
		conn.close()
	except Exception,e:
		logger.info("SQL Query Error: %s",str(e))
	for device in deviceList:
		logger.info("Port scanning %s",device['ip'])
		file="/opt/sweetsecurity/client/nmap_scans/portScan_%s_%s.xml" % (datetime.now().strftime('%Y-%m-%d_%H-%M'),device['ip'])
		os.popen("nmap -sV -oX %s %s" % (file,device['ip'])).read()
		#file='/opt/sweetsecurity/client/portScan.xml'
		try:
			tree = ET.parse(file)
			root = tree.getroot()
			#Parse the portScan.xml file
			for port in root.findall("./host/ports/port"):
				portState='filtered'
				for state in port.findall("./state"):
					portState=state.get('state')
				if portState == 'open':
					portNum=str(port.get('portid'))
					proto=port.get('protocol')
					serviceName=''
					serviceProduct=''
					serviceVersion=''
					for service in port.findall("./service"):
							serviceName=service.get('name')
							serviceProduct=service.get('product')
							serviceVersion=service.get('version')
					portInfo={'macAddress': device['mac'],
							'port': portNum,
							'protocol': proto,
							'name': serviceName,
							'version': serviceVersion,
							'product': serviceProduct}
					server.addPort(portInfo)
		except:
			logger.info("Invalid Port Scan XML File")