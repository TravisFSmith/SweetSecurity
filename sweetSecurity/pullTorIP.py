import urllib2

def do():
	response = urllib2.urlopen('https://check.torproject.org/exit-addresses')
	if response.getcode() == 200:
		yamlFile = open('/etc/logstash/translate/torIP.yaml','w')
		for line in response.readlines():
			if line.startswith('ExitAddress'):
				ip = line.split()[1]
				yamlFile.write('"%s": "YES"\n' % ip)
		yamlFile.close
