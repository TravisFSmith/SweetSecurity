import os, shutil, sys
import hashCheck

def install(chosenInterface,webServer):
	
	broLatest='2.5.1'
	
	cwd=os.getcwd()
	
	broInstalled=False
	if os.path.isfile('/opt/nsm/bro/bin/bro'):
		broVersion=os.popen('sudo /opt/nsm/bro/bin/bro -version  2>&1').read()
		if broLatest == broVersion.split()[2]:
			broInstalled=True
	if broInstalled==False:
		print "Installing Bro IDS"
		print "  Downloading Bro IDS 2.5.1"
		os.popen('sudo wget https://www.bro.org/downloads/bro-2.5.1.tar.gz 2>&1').read()
		if not os.path.isfile('bro-2.5.1.tar.gz'):
			sys.exit('Error downloading Bro')
		if not hashCheck.checkHash('bro-2.5.1.tar.gz'):
			sys.exit('Error downloading Bro, mismatched file hashes')
		print "  Unpacking Bro Code"
		os.popen('sudo tar -xzf bro-2.5.1.tar.gz').read()
		print "  Creating Bro Directory Structures"
		if not os.path.exists('/opt/nsm'):
			os.makedirs('/opt/nsm')
		if not os.path.exists('/opt/nsm/bro'):
			os.makedirs('/opt/nsm/bro')
		os.chdir('bro-2.5.1')
		print "  Configuring Bro Code"
		os.popen('sudo ./configure --prefix=/opt/nsm/bro 2>&1').read()
		print "  Making Bro Code"
		os.popen('sudo make 2>&1').read()
		print "  Installing Bro Code"
		os.popen('sudo make install 2>&1').read()
		print "  Cleaning Up Bro Installation Files"
		os.chdir(cwd)
		os.remove('bro-2.5.1.tar.gz')
		shutil.rmtree("bro-2.5.1/")
		
		#Update node.cfg to listen on chosen interface
		print "  Configuring Bro"
		newInterfaceString='interface=%s\n' % chosenInterface
		shutil.move('/opt/nsm/bro/etc/node.cfg','/opt/nsm/bro/etc/node.orig')
		with open("/opt/nsm/bro/etc/node.orig", "rt") as fileIn:
			with open("/opt/nsm/bro/etc/node.cfg", "wt") as fileOut:
				for line in fileIn:
					if line.rstrip() == "interface=eth0":
						line=newInterfaceString
					fileOut.write(line)
		#ignore communication between sensor and webServer, writes a ton of noise
		if webServer != 'localhost':
			with open("/opt/nsm/bro/etc/broctl.cfg", "a") as broCtlFile:
				broCtlFile.write("\nbroargs = -f 'not host %s'\n" % webServer)
		
		print "  Deploying and Starting Bro"
		os.popen('sudo /opt/nsm/bro/bin/broctl deploy').read()
		os.popen('sudo /opt/nsm/bro/bin/broctl start').read()
	else:
		print "Bro already installed..."