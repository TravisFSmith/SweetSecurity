import urllib2

def do():
	response = urllib2.urlopen('http://www.malwaredomainlist.com/hostslist/ip.txt')
	if response.getcode() == 200:
		yamlFile = open('/etc/logstash/translate/maliciousIP.yaml','w')
		for line in response.readlines():
			yamlFile.write('"%s": "YES"\n' % line.rstrip())
		yamlFile.close