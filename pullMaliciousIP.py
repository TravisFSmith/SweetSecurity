()#!/usr/bin/env python

import urllib2, re

def writeYAML():
	yamlFile = open('/etc/logstash/translate/maliciousIP.yaml','w')
	url='http://www.malwaredomainlist.com/hostslist/ip.txt'
	html = urllib2.urlopen(url)
	for line in html.readlines():
		line = re.sub('\\r|\\n','',line)
		yamlFile.write("\"" + line + "\": \"YES\"" + "\n")
	yamlFile.close()

if __name__=="__main__":
	writeYAML()
