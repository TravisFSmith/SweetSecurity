#!/usr/bin/env python

import os, sys, fcntl, socket, struct, sqlite3, smtplib, re, subprocess
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
	smtp_host = 'smtp.gmail.com'
	smtp_port = '587'
	subject="New Devices Found on Network"
	message = """\From: %s\nTo: %s\nSubject: %s\n\n%s""" % (fromaddr, ", ".join(toaddr), subject, body)
	server = smtplib.SMTP(smtp_host + ':' + smtp_port)
	server.starttls()
	server.ehlo()
	server.login(username,password)
	server.sendmail(fromaddr, toaddr, message)
	server.quit()

if __name__=="__main__":
	omp_user='omp_user'
	omp_pass='omp_pass'
	device='eth0'
	ip = getIP(device)
	netmask = get_netmask(device)
	subprocess.check_output("sudo nmap -sn " + ip + "/" + str(netmask) + " -oX nmap.xml",shell=True)
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
	
	#Get Scan Config, use Full and Fast for default scan config
	for ompconfig in subprocess.check_output("omp -u " + omp_user + " -w " + omp_pass + " -g",shell=True).split('\n'):
		if ompconfig.endswith('Full and fast'):
			omp_ScanConfig = re.sub('\s.*','',ompconfig)
	
	#Parse the nmap.xml file
	for host in root.findall("./host"):
		ipaddress=""
		macaddress=""
		hostname=""
		hoststate=""
		macvendor=""
		omp_id="1"
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
			if (len(hostname) < 1):
				hostname=ipaddress+" (" + macaddress + ")"
			c = conn.cursor()
			t = (macaddress,)
			c.execute('SELECT * FROM hosts WHERE mac=?', t)
			if (c.fetchone()==None):
				body=body+"\nHost   Name: " + hostname
				body=body+"\nIP4 Address: " + ipaddress
				body=body+"\nMAC Address: " + macaddress
				body=body+"\nMAC  Vendor: " + str(macvendor) + "\n"
				omp_response=subprocess.check_output("omp -u " + omp_user + " -w " + omp_pass + " --xml='<create_target><name>" + hostname + "</name><hosts>" + ipaddress + "</hosts><comment>" + macaddress + "</comment></create_target>'", shell=True)
				omp_status = re.sub('.*status="','',omp_response) 
				omp_status = re.sub('".*','',omp_status) 
				omp_status = re.sub('\\r|\\n','',omp_status) 
				#201 means it added the target successfully
				if (omp_status == "201"):
					omp_id = re.sub('.*id="','',omp_response) 
					omp_id = re.sub('".*','',omp_id) 
					omp_id = re.sub('\\r|\\n','',omp_id) 
				#400 means we already have the device in OMP, let's try to get the existing OMP ID
				elif (omp_status == "400"):
					for target in subprocess.check_output("omp -u " + omp_user + " -w " + omp_pass + " -T",shell=True).split('\n'):
						if target.endswith(hostname):
							omp_id = re.sub('\s.*','',target) 
				#There are other ID's we could parse, but let's just ignore them for now. 
				else:
					omp_id="Unknown"
				
				#Gather a list of existing tasks to see if we have a match for our hostname
				omp_TaskID=''
				for task in subprocess.check_output("omp -u " + omp_user + " -w " + omp_pass + " -G",shell=True).split('\n'):
					if task.endswith(hostname):
						omp_TaskID = re.sub('\s.*','',task) 
				if (omp_TaskID == ''):
					omp_CreateTaskResponse=subprocess.check_output("omp -u " + omp_user + " -w " + omp_pass + " -C -n \"Scan of " + hostname + "\" -c " + omp_ScanConfig + " --target " + omp_id,shell=True)
					omp_TaskID = re.sub('\\r|\\n','',omp_CreateTaskResponse) 
				
				#Start the Task
				#os.system("omp -u " + omp_user + " -w " + omp_pass + " -S " + omp_TaskID)
				
				#Add entry to local DB
				c.execute("INSERT INTO hosts VALUES ('" + hostname + "'," + str(ip2long(ipaddress)) + ",'" + macaddress + "','" + macvendor + "','" + omp_id + "')")
			conn.commit()
	if (len(body)>0):
		emailbody="NEW DEVICES FOUND ON NETWORK:\n\n" + body 
		sendemail(emailbody)
	conn.close()
