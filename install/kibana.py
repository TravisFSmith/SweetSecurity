import os, shutil, sys


def install(chosenInterfaceIP):
	kibanaLatest='5.2.2'
	
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
		print "  Downloading Kibana 5.2.2"
		if cpuArch == 'x86_64':
			os.popen('sudo wget https://artifacts.elastic.co/downloads/kibana/kibana-5.2.2-linux-x86_64.tar.gz 2>&1').read()
			if not os.path.isfile('kibana-5.2.2-linux-x86_64.tar.gz'):
				sys.exit('Error downloading Kibana')
			print "  Installing Kibana"
			os.popen('sudo tar -xzf kibana-5.2.2-linux-x86_64.tar.gz').read()
			shutil.copytree('kibana-5.2.2-linux-x86_64/','/opt/kibana')
			print "  Cleaning Up Installation Files"
			os.remove('kibana-5.2.2-linux-x86_64.tar.gz')
			shutil.rmtree("kibana-5.2.2-linux-x86_64/")
		else:
			os.popen('sudo wget https://artifacts.elastic.co/downloads/kibana/kibana-5.2.2-linux-x86.tar.gz 2>&1').read()
			if not os.path.isfile('kibana-5.2.2-linux-x86.tar.gz'):
				sys.exit('Error downloading Kibana')
			print "  Installing Kibana"
			os.popen('sudo tar -xzf kibana-5.2.2-linux-x86.tar.gz').read()
			shutil.copytree('kibana-5.2.2-linux-x86/','/opt/kibana')
			print "  Cleaning Up Installation Files"
			os.remove('kibana-5.2.2-linux-x86.tar.gz')
			shutil.rmtree("kibana-5.2.2-linux-x86/")
		
		#Custom stuff for ARM
		if not cpuArch.startswith('x86'):
			#Remove nodejs on Pi3
			os.popen('sudo apt-get -y remove nodejs-legacy nodejs nodered').read()
			os.popen('sudo wget http://node-arm.herokuapp.com/node_latest_armhf.deb 2>&1').read()
			os.popen('sudo dpkg -i node_latest_armhf.deb').read()
			shutil.move('/opt/kibana/node/bin/node','/opt/kibana/node/bin/node.orig')
			shutil.move('/opt/kibana/node/bin/npm','/opt/kibana/node/bin/npm.orig')
			os.popen('sudo ln -s /usr/local/bin/node /opt/kibana/node/bin/node').read()
			os.popen('sudo ln -s /usr/local/bin/npm /opt/kibana/node/bin/npm').read()
			os.remove('node_latest_armhf.deb')

			#The --no-warnings flag is no longer a valid option on ARM, need to remove it
			kibanaBin="/opt/kibana/bin/kibana"
			fileContent=open(kibanaBin,'r').readlines()
			lastLine=('exec "${NODE}" $NODE_OPTIONS "${DIR}/src/cli" ${@}')
			fileContent[-1]=lastLine 
			open(kibanaBin,'w').writelines(fileContent)

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
