import os, sys

def get_user_input(input_string):
	if sys.version_info[0] > 2:
		return input(input_string)
	else:
		return raw_input(input_string)

def install(csKey):
	#Install Critical Stack
	cpuArch=os.uname()[4]
	print "Installing Critical Stack Agent"
	print "  Downloading Critical Stack Agent"
	if cpuArch == 'x86':
		os.popen('sudo wget http://intel.criticalstack.com/client/critical-stack-intel-i386.deb 2>&1').read()
		if not os.path.isfile('critical-stack-intel-i386.deb'):
			sys.exit('Error downloading critical stack agent')
		print "  Installing Critical Stack Agent"
		os.popen('sudo dpkg -i critical-stack-intel-i386.deb').read()
		print "  Applying Critical Stack API Key"
		os.popen('sudo -u critical-stack critical-stack-intel api %s' % csKey).read()
		print "  Cleaning Up Installation Files"
		os.remove('critical-stack-intel-i386.deb')
	elif cpuArch == 'x86_64':
		os.popen('sudo wget http://intel.criticalstack.com/client/critical-stack-intel-amd64.deb 2>&1').read()
		if not os.path.isfile('critical-stack-intel-amd64.deb'):
			sys.exit('Error downloading critical stack agent')
		print "  Installing Critical Stack Agent"
		os.popen('sudo dpkg -i critical-stack-intel-amd64.deb').read()
		print "  Applying Critical Stack API Key"
		os.popen('sudo -u critical-stack critical-stack-intel api %s' % csKey).read()
		print "  Cleaning Up Installation Files"
		os.remove('critical-stack-intel-amd64.deb')
	else:
		os.popen('sudo wget http://intel.criticalstack.com/client/critical-stack-intel-arm.deb 2>&1').read()
		if not os.path.isfile('critical-stack-intel-arm.deb'):
			sys.exit('Error downloading critical stack agent')
		print "  Installing Critical Stack Agent"
		os.popen('sudo dpkg -i critical-stack-intel-arm.deb').read()
		print "  Applying Critical Stack API Key"
		os.popen('sudo -u critical-stack critical-stack-intel api %s' % csKey).read()
		print "  Cleaning Up Installation Files"
		os.remove('critical-stack-intel-arm.deb')
	print "  Configuring Bro to Restart on Critical Stack Feed Updates"
	os.popen('sudo -u critical-stack critical-stack-intel config --set bro.path=/opt/nsm/bro').read()
	os.popen('sudo -u critical-stack critical-stack-intel config --set bro.restart=true').read()
	os.popen('sudo chown critical-stack  /opt/nsm/bro/share/bro/site/local.bro').read()
	os.popen('sudo -u critical-stack critical-stack-intel config --set bro.broctl.path=/opt/nsm/bro/bin/broctl').read()