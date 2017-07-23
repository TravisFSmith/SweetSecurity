import os, sys

def install(installType):
	cpuArch=os.uname()[4]
	if cpuArch.startswith('x86'):
		javaVersion=os.popen('java -version  2>&1').read()
		for line in javaVersion.splitlines():
			if line == 'sh: 1: java: not found':
				print "\nNo JRE installed"
				print "\nFor Ubuntu 16: sudo apt-get install default-jre"
				sys.exit("\nPlease install JRE 1.8")
			elif line.startswith('java version "1.7'):
				print "\nInstalled Java Version: %s" % line
				print "\nFor Debian: See https://tecadmin.net/install-java-8-on-debian/ for installation steps"
				print "\nFor Ubuntu 16: sudo apt-get install default-jre"
				sys.exit('\nPlease install JRE 1.8')
	#Install Pre-requisites
	print "Install Pre-requisites"
	os.popen('sudo apt-get update')
	
	if installType=='1':
		#Full Install
		if cpuArch.startswith('x86'):
			os.popen('sudo apt-get -y install curl cmake g++ flex bison libpcap-dev libssl-dev python-dev python-pip python-flask python-scapy apache2 libapache2-mod-wsgi swig nmap tcpdump 2>&1').read()
		else:
			os.popen('sudo apt-get -y install cmake flex bison libpcap-dev libssl-dev python-dev python-pip python-flask python-scapy apache2 libapache2-mod-wsgi swig ant zip git nmap tcpdump 2>&1').read()
			#Some ARM platforms won't have this, moving it here so it won't error on everything else
			os.popen('sudo apt-get -y install oracle-java8-jdk 2>&1')
		os.popen('sudo pip install elasticsearch 2>&1').read()
		os.popen('sudo pip install requests 2>&1').read()
		os.popen('sudo pip install flask-mail 2>&1').read()
		os.popen('sudo pip install flask_wtf 2>&1').read()
		os.popen('sudo pip install cryptography --upgrade 2>&1').read()
		os.popen('sudo pip install pyopenssl --upgrade 2>&1').read()
	elif installType=='2':
		#Sensor Install
		if cpuArch.startswith('x86'):
			os.popen('sudo apt-get -y install curl cmake g++ flex bison libpcap-dev libssl-dev python-dev python-pip python-scapy swig nmap tcpdump 2>&1').read()
		else:
			os.popen('sudo apt-get -y install cmake flex bison libpcap-dev libssl-dev python-dev python-pip python-scapy swig oracle-java8-jdk ant zip git nmap tcpdump texinfo 2>&1').read()
		os.popen('sudo pip install requests 2>&1').read()
	elif installType=='3':
		#Web Server Install
		if cpuArch.startswith('x86'):
			os.popen('sudo apt-get -y install curl python-dev python-pip python-flask python-scapy apache2 libapache2-mod-wsgi 2>&1').read()
		else:
			os.popen('sudo apt-get -y install python-dev python-pip python-flask python-scapy apache2 libapache2-mod-wsgi oracle-java8-jdk 2>&1').read()
		os.popen('sudo pip install elasticsearch 2>&1').read()
		os.popen('sudo pip install flask-mail 2>&1').read()
		os.popen('sudo pip install flask_wtf 2>&1').read()
		os.popen('sudo pip install cryptography --upgrade 2>&1').read()
		os.popen('sudo pip install pyopenssl --upgrade 2>&1').read()