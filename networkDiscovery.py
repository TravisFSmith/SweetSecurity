#!/usr/bin/env python

import os, sys, fcntl, socket, struct, sqlite3, smtplib, re
import xml.etree.ElementTree as ET
import SweetSecurityDB

def ip2long(ip):
	return struct.unpack("!L", socket.inet_aton(ip))[0]

def long2ip(ip):
	return socket.inet_ntoa(struct.pack('!L', ip))

def getIP(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

def get_netmask(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netmask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, struct.pack('256s',ifname))[20:24])
	netmask = sum([bin(int(x)).count('1') for x in netmask.split('.')])
	return netmask

def stripNewLine(line):
	line = re.sub('\\r|\\n','',line) 
	return line

def sendemail(body):
	fromaddr = 'EMAIL_USER'
	toaddr  = 'EMAIL_USER'
	username = 'EMAIL_USER'
	password = 'EMAIL_PASS'
	subject="New Devices Found on Network"
	message = """\From: %s\nTo: %s\nSubject: %s\n\n%s""" % (fromaddr, ", ".join(toaddr), subject, body)
	server = smtplib.SMTP('SMTP_HOST:SMTP_PORT')
	server.starttls()
	server.ehlo()
	server.login(username,password)
	server.sendmail(fromaddr, toaddr, message)
	server.quit()

if __name__=="__main__":
	device='eth0'
	ip = getIP(device)
	netmask = get_netmask(device)
	os.system("nmap -sn " + ip + "/" + str(netmask) + " -oX nmap.xml")
	file='nmap.xml'
	try:
		tree = ET.parse(file)
		root = tree.getroot()
	except:
		sys.exit("Not a valid XML file")
	
	#If the database doesn't exist, create it
	if not os.path.isfile('SweetSecurity.db'):
		SweetSecurityDB.create()
	
	conn = sqlite3.connect('SweetSecurity.db')
	body=""
	
	for host in root.findall("./host"):
		ipaddress=""
		macaddress=""
		hostname=""
		hoststate=""
		macvendor=""
		for status in host.findall("./status"):
			hoststate=status.get('state')
			hoststate=stripNewLine(hoststate)
		for ip in host.findall("./address"):
			addressType=ip.get('addrtype')
			if (addressType == "mac"):
				macaddress=ip.get('addr')
				macaddress=stripNewLine(macaddress)
				macvendor=ip.get('vendor')
				if (macvendor is None):
					macvendor='Unknown'
				macvendor=stripNewLine(macvendor)
			if (addressType == "ipv4"):
				ipaddress=ip.get('addr')
				ipaddress=stripNewLine(ipaddress)
		for hostname in host.findall("./hostnames/hostname"):
			hostname=hostname.get('name')
			hostname=stripNewLine(hostname)
		#only do stuff if the mac address is found
		if (len(macaddress) > 0):
			#print("Host   Name: " + hostname)
			#print("IP4 Address: " + ipaddress)
			#print("MAC Address: " + macaddress + "(" + macvendor + ")")
			#print("Host Status: " + hoststate)
			c = conn.cursor()
			t = (macaddress,)
			c.execute('SELECT * FROM hosts WHERE mac=?', t)
			if (c.fetchone()==None):
				body=body+"\nHost   Name: " + hostname
				body=body+"\nIP4 Address: " + ipaddress
				body=body+"\nMAC Address: " + macaddress
				body=body+"\nMAC  Vendor: " + str(macvendor) + "\n"
				#print("new device, insert into DB")
				c.execute("INSERT INTO hosts VALUES ('" + hostname + "'," + str(ip2long(ipaddress)) + ",'" + macaddress + "','" + macvendor + "')")
			conn.commit()
	if (len(body)>0):
		emailbody="NEW DEVICES FOUND ON NETWORK:\n\n" + body 
		sendemail(emailbody)
	conn.close()
