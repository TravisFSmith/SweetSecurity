import getpass, json, os, shutil, sys
from time import sleep

import hashCheck

def get_user_input(input_string):
	if sys.version_info[0] > 2:
		return input(input_string)
	else:
		return raw_input(input_string)

def install(esServer,esUser,esPass):
	print "Installing Logstash"
	logstashLatest='5.5.1'
	
	cpuArch=os.uname()[4]
	cwd=os.getcwd()
	
	#Sometimes it may take awhile to get elastic to first boot up, try a few times to see if we can connect. 
	elasticTryCount=0
	while True:
		elasticTryCount+=1
		elasticVersion=os.popen("curl -u %s:%s -XGET 'https://%s:9201' -k" % (esUser,esPass,esServer)).read()
		try:
			jsonStuff=json.loads(elasticVersion)
			if jsonStuff['tagline'] == "You Know, for Search":
				print "Connected to Elasticsearch..."
				break
			else:
				print "Waiting for Elasticsearch to start...try %d of 10" % elasticTryCount
		except:
			print "Error: Waiting for Elasticsearch to start...try %d of 10" % elasticTryCount
		if elasticTryCount == 10:
			sys.exit('Unable to connect to Elasticsearch')
		else:
			sleep(10)
	
	#Install Logstash
	logstashInstalled=False
	if os.path.isfile('/usr/share/logstash/bin/logstash'):
		logstashVersion=os.popen('sudo /usr/share/logstash/bin/logstash --version').read()
		if logstashLatest== logstashVersion.rstrip().split()[1]:
			logstashInstalled=True
	if logstashInstalled == False:
		#Check if user wants email alerts
		while True:
			logstashEmail = get_user_input("\033[1mConfigure Logstash To Send Email Alerts (Y/n)\033[0m: ")
			if logstashEmail.lower() not in ('y', 'n', ''):
				print("Must choose Y or N.")
			else:
				break
		if logstashEmail.lower()=='y' or len(logstashEmail) == 0:
			smtpHost = get_user_input("    \033[1mEnter SMTP Host (ex: smtp.google.com)\033[0m: ")
			smtpPort = get_user_input("    \033[1mEnter SMTP Port (ex: 587)\033[0m: ")
			smtpUser = get_user_input("    \033[1mEnter Email Address (ex: email@gmail.com)\033[0m: ")
			smtpPass = getpass.getpass("    \033[1mEnter Email Password (ex: P@55word)\033[0m: ")
		print "  Downloading Logstash 5.5.1"
		os.popen('sudo wget https://artifacts.elastic.co/downloads/logstash/logstash-5.5.1.deb 2>&1').read()
		if not os.path.isfile('logstash-5.5.1.deb'):
			sys.exit('Error downloading logstash')
		if not hashCheck.checkHash('logstash-5.5.1.deb'):
			sys.exit('Error downloading logstash, mismatched file hashes')
		print "  Installing Logstash"
		os.popen('sudo dpkg -i logstash-5.5.1.deb').read()
		print "  Cleaning Up Logstash Installation Files"
		os.remove('logstash-5.5.1.deb')
		os.popen('sudo systemctl enable logstash.service').read()
		
		if not cpuArch.startswith('x86'):
			#Get ARM JFFI Code
			os.popen('sudo git clone https://github.com/jnr/jffi.git').read()
			os.chdir('jffi')
			os.popen('sudo ant jar').read()
			shutil.copyfile('build/jni/libjffi-1.2.so', '/usr/share/logstash/vendor/jruby/lib/jni/arm-Linux/libjffi-1.2.so')
			os.chdir('/usr/share/logstash/vendor/jruby/lib')
			os.popen('sudo zip -g jruby-complete-1.7.11.jar jni/arm-Linux/libjffi-1.2.so').read()
			os.chdir(cwd)
			shutil.rmtree("jffi/")
		
		
		#Install Logstash-Filter-Translate Plugin
		print "  Installing Translate Plugin"
		os.popen('sudo /usr/share/logstash/bin/logstash-plugin install logstash-filter-translate').read()
		print "  Copying Configuration Files"
		if not os.path.exists('/etc/logstash/custom_patterns'):
			os.makedirs('/etc/logstash/custom_patterns')
		shutil.copyfile('logstash/rules/bro.rule', '/etc/logstash/custom_patterns/bro.rule')
		shutil.copyfile('logstash/rules/sweetSecurity.rule', '/etc/logstash/custom_patterns/sweetSecurity.rule')
		shutil.copyfile('logstash/rules/iptables.rule', '/etc/logstash/custom_patterns/iptables.rule')
		if not os.path.exists('/etc/logstash/translate'):
			os.makedirs('/etc/logstash/translate')
		shutil.copyfile('logstash/translate/torIP.yaml', '/etc/logstash/translate/torIP.yaml')
		shutil.copyfile('logstash/translate/maliciousIP.yaml', '/etc/logstash/translate/maliciousIP.yaml')
		
		#Configure Logstash
		print "  Configuring Logstash"
		shutil.move('logstash/conf/logstash.conf','logstash/conf/logstash.org')
		with open("logstash/conf/logstash.org", "rt") as fileIn:
			with open("logstash/conf/logstash.conf", "wt") as fileOut:
				for line in fileIn:
					if line.rstrip() == "    hosts => localhost":
						line = '    hosts => "%s:9201"\n' % esServer
						line += '    user => "%s"\n' % esUser
						line += '    password => "%s"\n' % esPass
					if line.rstrip() == "email_block":
						#If user wants alerts, insert their credentials.
						if logstashEmail.lower()=='y' or len(logstashEmail) == 0:
							emailBlock=''
							with open("logstash/conf/email.conf", "rt") as emailIn:
								for emailLine in emailIn:
									
									emailBlockLine=''
									if emailLine.rstrip().endswith('"SMTP_HOST"'):
										emailBlockLine=emailLine.replace('SMTP_HOST', smtpHost)
									elif emailLine.rstrip().endswith('SMTP_PORT'):
										emailBlockLine=emailLine.replace('SMTP_PORT', smtpPort)
									elif emailLine.rstrip().endswith('"EMAIL_USER"'):
										emailBlockLine=emailLine.replace('EMAIL_USER', smtpUser)
									elif emailLine.rstrip().endswith('"EMAIL_PASS"'):
										emailBlockLine=emailLine.replace('EMAIL_PASS', smtpPass)
									else:
										emailBlockLine+=emailLine
									emailBlock+=emailBlockLine
								line=emailBlock
						else:
							line = ''
					fileOut.write(line)
		#Give logstash user access to read kern.log
		os.popen('sudo usermod -a -G adm logstash').read()
		#Delete file with user stuff and put old one back.
		shutil.copyfile('logstash/conf/logstash.conf', '/etc/logstash/conf.d/logstash.conf')
		os.remove('logstash/conf/logstash.conf')
		shutil.move('logstash/conf/logstash.org','logstash/conf/logstash.conf')
		
		print "  Updating Logstash Template for Elasticsearch"
		os.popen('curl -k -u %s:%s -XPUT https://%s:9201/_template/logstash -d \'{"template":"logstash-*","settings":{"index":{"refresh_interval":"5s"}},"mappings":{"_default_":{"dynamic_templates":[{"message_field":{"path_match":"message","mapping":{"norms":false,"type":"text"},"match_mapping_type":"string"}},{"string_fields":{"mapping":{"norms":false,"type":"text","fields":{"keyword":{"type":"keyword"}}},"match_mapping_type":"string","match":"*"}}],"_all":{"norms":false,"enabled":true},"properties":{"@timestamp":{"include_in_all":false,"type":"date"},"geoip_dst":{"dynamic":true,"properties":{"ip":{"type":"ip"},"latitude":{"type":"half_float"},"location":{"type":"geo_point"},"longitude":{"type":"half_float"}}},"geoip_src":{"dynamic":true,"properties":{"ip":{"type":"ip"},"latitude":{"type":"half_float"},"location":{"type":"geo_point"},"longitude":{"type":"half_float"}}},"@version":{"include_in_all":false,"type":"keyword"}}}},"aliases":{}}}\'' % (esUser,esPass,esServer)).read()
		print "  Starting Logstash"
		os.popen('sudo service logstash start').read()
	else:
		print "Logstash already installed"