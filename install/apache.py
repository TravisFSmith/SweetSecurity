import getpass, os, shutil, sys

def get_user_input(input_string):
	if sys.version_info[0] > 2:
		return input(input_string)
	else:
		return raw_input(input_string)

def install(installType,chosenInterface,chosenIP):
	cpuArch = os.uname()[4]
	print "Creating Website"
	#Copy Website Stuff
	if not os.path.exists('/var/www/webapp'):
		os.makedirs('/var/www/webapp')
	else:
		shutil.rmtree('/var/www/webapp')
		os.makedirs('/var/www/webapp')
	shutil.copyfile('apache/flask/webapp.wsgi', '/var/www/webapp/webapp.wsgi')
	shutil.copytree('apache/flask/webapp','/var/www/webapp/webapp')
	shutil.move('/etc/apache2/sites-available/000-default.conf','/etc/apache2/sites-available/000-default_org')
	shutil.copyfile('apache/sites/default-ssl.conf', '/etc/apache2/sites-available/default-ssl.conf')
	shutil.move('/etc/apache2/ports.conf','/etc/apache2/ports.orig')
	shutil.copyfile('apache/conf/ports.conf','/etc/apache2/ports.conf')
	with open("/etc/apache2/sites-enabled/000-default.conf", "wt") as defaultOut:
		defaultOut.write('<VirtualHost *:80>\n')
		defaultOut.write('\tRedirect permanent "/" "https://%s"\n' % chosenIP)
		defaultOut.write('</VirtualHost>')
	
	#Enable proxy mods
	os.popen('sudo a2enmod proxy').read()
	os.popen('sudo a2enmod proxy_http').read()
	
	#enable SSL
	#Using instructions from https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-ubuntu-16-04
	print "  Configuring SSL"
	os.popen('sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -subj "/C=US/ST=OR/L=Portland" -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt').read()
	if cpuArch.startswith('x86'):
		os.popen('sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048').read()
		shutil.copyfile('apache/conf/ssl-params.conf','/etc/apache2/conf-available/ssl-params.conf')
	else:
		shutil.copyfile('apache/conf/ssl-params-raspbian.conf', '/etc/apache2/conf-available/ssl-params.conf')
	os.popen('sudo a2enmod ssl').read()
	os.popen('sudo a2enmod headers').read()
	os.popen('sudo a2ensite default-ssl').read()
	os.popen('sudo a2enconf ssl-params').read()
	
	#Give www-data user access to manage services
	with open("/etc/sudoers", "a") as sudoersFile:
		sudoersFile.write("\nwww-data        ALL = NOPASSWD: /usr/sbin/service elasticsearch *\n")
		sudoersFile.write("www-data        ALL = NOPASSWD: /usr/sbin/service kibana *\n")
		sudoersFile.write("www-data        ALL = NOPASSWD: /usr/sbin/service sweetsecurity_server *\n")
	
	while True:
		apacheEmail = get_user_input("\033[1mConfigure Apache To Send Email Alerts (Y/n)\033[0m: ")
		if apacheEmail.lower() not in ('y', 'n', ''):
			print("Must choose Y or N.")
		else:
			break
	if apacheEmail.lower()=='y' or len(apacheEmail) == 0:
		apacheEmail = 'y'
		smtpHost = get_user_input("    \033[1mEnter SMTP Host (ex: smtp.gmail.com)\033[0m: ")
		smtpPort = get_user_input("    \033[1mEnter SMTP Port (ex: 465)\033[0m: ")
		smtpUser = get_user_input("    \033[1mEnter Email Address (ex: email@gmail.com)\033[0m: ")
		smtpPass = getpass.getpass("    \033[1mEnter Email Password (ex: P@55word)\033[0m: ")
	#Configure Settings
	shutil.move('/var/www/webapp/webapp/__init__.py','/var/www/webapp/webapp/init_org')
	with open("/var/www/webapp/webapp/init_org", "rt") as fileIn:
		with open("/var/www/webapp/webapp/__init__.py", "wt") as fileOut:
			for line in fileIn:
				if line.rstrip() == '__appSettings__':
					line = "    SECRET_KEY = '%s'\n" % os.urandom(24).encode('hex')
					if apacheEmail == 'y':
						line += "    MAIL_USERNAME =           os.getenv('MAIL_USERNAME',        '%s')\n" % smtpUser
						line += "    MAIL_PASSWORD =           os.getenv('MAIL_PASSWORD',        '%s')\n" % smtpPass
						line += "    MAIL_DEFAULT_SENDER =     os.getenv('MAIL_DEFAULT_SENDER',  '%s')\n" % smtpUser
						line += "    MAIL_SERVER =             os.getenv('MAIL_SERVER',          '%s')\n" % smtpHost
						line += "    MAIL_PORT =           int(os.getenv('MAIL_PORT',            '%s'))\n" % smtpPort
						line += "    MAIL_USE_SSL =        int(os.getenv('MAIL_USE_SSL',         True))\n"
				fileOut.write(line)