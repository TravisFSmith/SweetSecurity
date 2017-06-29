import os, shutil, sys
import hashCheck

def install(chosenInterfaceIP):
	kibanaLatest='5.4.3'
	
	cpuArch=os.uname()[4]
	cwd=os.getcwd()
	
	#Install Kibana
	kibanaInstalled=False
	if os.path.isfile('/opt/kibana/bin/kibana'):
		kibanaVersion=os.popen('sudo /opt/kibana/bin/./kibana --version').read()
		if kibanaLatest== kibanaVersion.rstrip():
			kibanaInstalled=True
	if kibanaInstalled == False:
		print "Installing Kibana"
		print "  Downloading Kibana 5.4.3"
		if cpuArch == 'x86_64':
			os.popen('sudo wget https://artifacts.elastic.co/downloads/kibana/kibana-5.4.3-linux-x86_64.tar.gz 2>&1').read()
			if not os.path.isfile('kibana-5.4.3-linux-x86_64.tar.gz'):
				sys.exit('Error downloading Kibana')
			if not hashCheck.checkHash('kibana-5.4.3-linux-x86_64.tar.gz'):
				sys.exit('Error downloading kibana, mismatched file hashes')
			print "  Installing Kibana"
			os.popen('sudo tar -xzf kibana-5.4.3-linux-x86_64.tar.gz').read()
			shutil.copytree('kibana-5.4.3-linux-x86_64/','/opt/kibana')
			print "  Cleaning Up Installation Files"
			os.remove('kibana-5.4.3-linux-x86_64.tar.gz')
			shutil.rmtree("kibana-5.4.3-linux-x86_64/")
		else:
			os.popen('sudo wget https://artifacts.elastic.co/downloads/kibana/kibana-5.4.3-linux-x86.tar.gz 2>&1').read()
			if not os.path.isfile('kibana-5.4.3-linux-x86.tar.gz'):
				sys.exit('Error downloading Kibana')
			if not hashCheck.checkHash('kibana-5.4.3-linux-x86.tar.gz'):
				sys.exit('Error downloading kibana, mismatched file hashes')
			print "  Installing Kibana"
			os.popen('sudo tar -xzf kibana-5.4.3-linux-x86.tar.gz').read()
			shutil.copytree('kibana-5.4.3-linux-x86/','/opt/kibana')
			print "  Cleaning Up Installation Files"
			os.remove('kibana-5.4.3-linux-x86.tar.gz')
			shutil.rmtree("kibana-5.4.3-linux-x86/")
		
		#Custom stuff for ARM
		if not cpuArch.startswith('x86'):
			#Remove nodejs on Pi3
			os.popen('sudo apt-get -y remove nodejs-legacy nodejs nodered').read()
			#Install nodejs v6, required for Kibana 5.3.0 and higher
			os.popen('sudo wget https://nodejs.org/download/release/v6.10.2/node-v6.10.2-linux-armv6l.tar.gz').read()
			os.popen('sudo mv node-v6.10.2-linux-armv6l.tar.gz /usr/local/node-v6.10.2-linux-armv6l.tar.gz')
			os.chdir('/usr/local')
			os.popen('sudo tar -xzf node-v6.10.2-linux-armv6l.tar.gz --strip=1').read()
			shutil.move('/opt/kibana/node/bin/node','/opt/kibana/node/bin/node.orig')
			shutil.move('/opt/kibana/node/bin/npm','/opt/kibana/node/bin/npm.orig')
			os.popen('sudo ln -s /usr/local/bin/node /opt/kibana/node/bin/node').read()
			os.popen('sudo ln -s /usr/local/bin/npm /opt/kibana/node/bin/npm').read()
			os.chdir(cwd)
			os.remove('/usr/local/node-v6.10.2-linux-armv6l.tar.gz')

			#The --no-warnings flag is no longer a valid option on ARM, need to remove it
			#kibanaBin="/opt/kibana/bin/kibana"
			#fileContent=open(kibanaBin,'r').readlines()
			#lastLine=('exec "${NODE}" $NODE_OPTIONS "${DIR}/src/cli" ${@}')
			#fileContent[-1]=lastLine
			#open(kibanaBin,'w').writelines(fileContent)

		shutil.copyfile('systemd/kibana.service','/etc/systemd/system/kibana.service')
		os.popen('sudo systemctl enable kibana.service').read()
		
		#Update kibana.yml to listen from local IP
		#newServerString='server.host: "%s"' % chosenInterfaceIP
		#shutil.move('/opt/kibana/config/kibana.yml','/opt/kibana/config/kibana.orig')
		#with open("/opt/kibana/config/kibana.orig", "rt") as fileIn:
		#	with open("/opt/kibana/config/kibana.yml", "wt") as fileOut:
		#		for line in fileIn:
		#			fileOut.write(line.replace('#server.host: "localhost"', newServerString))
		print "Starting Kibana"
		os.popen('sudo service kibana start').read()
	else:
		print "Kibana already installed"
