import json, os, shutil, sys
from time import sleep

import hashCheck

def install(fileCheckKey):
	elasticLatest='5.5.1'
	#Install Elasticsearch
	elasticInstalled=False
	if os.path.isfile('/etc/elasticsearch/elasticsearch.yml'):
		os.popen('sudo service elasticsearch start').read()
		while True:
			elasticVersion=os.popen("curl -XGET 'localhost:9200'").read()
			try:
				jsonStuff=json.loads(elasticVersion)
				if jsonStuff['tagline'] == "You Know, for Search":
					elasticVersion=jsonStuff['version']['number']
					break
				else:
					print "Waiting for Elasticsearch to start..."
			except:
				print "Exception: Waiting for Elasticsearch to start..."
			sleep(10)
		if elasticLatest== elasticVersion.rstrip():
			elasticInstalled=True
	if elasticInstalled == False:
		print "Installing Elasticsearch"
		print "  Downloading Elasticsearch 5.5.1"
		os.popen('sudo wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-5.5.1.deb 2>&1').read()
		if not os.path.isfile('elasticsearch-5.5.1.deb'):
			sys.exit('Error downloading elasticsearch')
		if not hashCheck.checkHash('elasticsearch-5.5.1.deb'):
			sys.exit('Error downloading elasticsearch, mismatched file hashes')
		print "  Installing Elasticsearch"
		os.popen('sudo dpkg -i elasticsearch-5.5.1.deb').read()
		print "  Cleaning Up Installation Files"
		os.remove('elasticsearch-5.5.1.deb')
		os.popen('sudo update-rc.d elasticsearch defaults').read()
		#Change heap size to 500m (1/2 of phyical memory)
		shutil.move('/etc/elasticsearch/jvm.options','/etc/elasticsearch/jvm.orig')
		with open("/etc/elasticsearch/jvm.orig", "rt") as fileIn:
			with open("/etc/elasticsearch/jvm.options", "wt") as fileOut:
				for line in fileIn:
					if line.rstrip() == "-Xms2g":
						fileOut.write('-Xms256m\n')
					elif line.rstrip() == "-Xmx2g":
						fileOut.write('-Xmx256m\n')
					else:
						fileOut.write(line)
		print "  Starting Elasticsearch"
		os.popen('sudo systemctl enable elasticsearch.service').read()
		os.popen('sudo service elasticsearch start').read()
		#Sleeping 10 seconds to begin with to give it time to startup.
		sleep(10)
		while True:
			#writeSsIndex = os.popen(
			#	'curl -XPUT \'localhost:9200/sweet_security?pretty\' -H \'Content-Type: application/json\' -d\' {"mappings" : {"ports" : {"properties" : {"mac" : {"type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "port" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}},"protocol" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}},"name" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}},  "product" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "version" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "lastSeen": { "type" : "date" }}}, "devices" : { "properties" : { "hostname" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "nickname" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "ip4" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "mac" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "vendor" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "ignore" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "active" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "defaultFwAction" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "isolate" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "firstSeen" : { "type" : "date" }, "lastSeen" : { "type" : "date" }}}, "firewallProfiles" : { "properties" : { "mac" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "destination" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, "action" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}}}}}\'').read()
			ssIndex='curl -XPUT \'localhost:9200/sweet_security?pretty\' -H \'Content-Type: application/json\' -d\'' \
					' {"mappings" : {' \
					'   "ports" : {"properties" : {' \
					'     "mac" : {"type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "port" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}},' \
					'     "protocol" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}},' \
					'     "name" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}},  ' \
					'     "product" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "version" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "lastSeen": { "type" : "date" }}}, ' \
					'   "devices" : { "properties" : { ' \
					'     "hostname" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "nickname" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "ip4" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "mac" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "vendor" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "ignore" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "active" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "defaultFwAction" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "isolate" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "firstSeen" : { "type" : "date" }, ' \
					'     "lastSeen" : { "type" : "date" }}}, ' \
					'   "firewallProfiles" : { "properties" : { ' \
					'     "mac" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "destination" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "action" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}}},' \
					'   "sensors" : { "properties" : { ' \
					'     "mac" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "sensorName" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "broHealth" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "logstashHealth" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "diskUsage" : { "type" : "integer"}, ' \
					'     "memAvailable" : { "type" : "integer"}, ' \
					'     "memPercent" : { "type" : "integer"}, ' \
					'     "memConsumed" : { "type" : "integer"}, ' \
					'     "firstSeen" : { "type" : "date" }, ' \
					'     "lastSeen" : { "type" : "date" }}} ' \
					'}}\''
			writeSsIndex = os.popen(ssIndex).read()

			try:
				jsonSS = json.loads(writeSsIndex)
				if jsonSS['acknowledged'] == True:
					print "  sweet_security index created"
					break
				else:
					print "Waiting for Elasticsearch to start, will try again in 10 seconds..."
			except:
				print "Error: Waiting for Elasticsearch to start, will try again in 10 seconds..."
			# Sleep 10 seconds to give ES time to get started
			sleep(10)
		while True:
			ssAlertIndex= 'curl -XPUT \'localhost:9200/sweet_security_alerts?pretty\' -H \'Content-Type: application/json\' -d\'{ ' \
				'  "mappings" : { ' \
				'    "alerts" : { "properties" : {  ' \
				'      "source" : { "type" : "text", "fields": {"raw": {"type": "keyword"}}}, ' \
				'      "message" : { "type" : "text", "fields": {"raw": {"type": "keyword"}}},  ' \
				'      "mac" : {"type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
				'      "firstSeen" : { "type" : "date" }, ' \
				'      "addressedOn" : { "type" : "date" }, ' \
				'      "addressed" : { "type" : "integer"}' \
				'}}}}\''
			writeSsAlertIndex = os.popen(ssAlertIndex).read()
			try:
				jsonSSAlert = json.loads(writeSsAlertIndex)
				if jsonSSAlert['acknowledged'] == True:
					print "  sweet_security_alert index created"
					break
				else:
					print "Waiting for Elasticsearch to start, will try again in 10 seconds..."
			except:
				print "Error: Waiting for Elasticsearch to start, will try again in 10 seconds..."
			# Sleep 10 seconds to give ES time to get started
			sleep(10)
		try:
			try:
				from elasticsearch import Elasticsearch
			except:
				pass
			esService = Elasticsearch()
			if fileCheckKey is None:
				configData = {'defaultMonitor': 0, 'defaultIsolate': 0, 'defaultFW': 1, 'defaultLogRetention': 0}
			else:
				configData = {'defaultMonitor': 0, 'defaultIsolate': 0, 'defaultFW': 1, 'defaultLogRetention': 0,
							  'fileCheckKey': fileCheckKey}
			#Sleep a second to make sure index has fully created in ES
			sleep(1)
			esService.index(index='sweet_security', doc_type='configuration', body=configData)

		except Exception, e:
			print e
			pass
		while True:
			tardisIndex='curl -XPUT \'localhost:9200/tardis?pretty\' -H \'Content-Type: application/json\' -d\'' \
					' {"mappings" : {' \
					'   "known_dnsqueries" : {"properties" : {' \
					'     "mac" : {"type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "query" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}}},' \
					'   "known_websites" : { "properties" : { ' \
					'     "mac" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "server_name" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}}}, ' \
					'   "firewallProfiles" : { "properties" : { ' \
					'     "mac" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "ip" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}, ' \
					'     "port" : { "type" : "text", "fields": {"keyword": {"type": "keyword"}}}}}' \
					'}}\''
			writeTardisIndex = os.popen(tardisIndex).read()
			#writeTardisIndex = os.popen('curl -XPUT \'localhost:9200/tardis?pretty\' -H \'Content-Type: application/json\' -d\' {"mappings" : {"known_hosts" : {"properties" : { "mac" : { "type" : "text", "fields": {"raw": {"type": "keyword"}}},"destination" : { "type" : "text", "fields": {"raw": {"type": "keyword"}}},"port" : { "type" : "text", "fields": {"raw": {"type": "keyword"}}}}}}}\'').read()
			try:
				jsonSS = json.loads(writeTardisIndex)
				if jsonSS['acknowledged'] == True:
					print "  tardis index created"
					break
				else:
					print "Waiting for Elasticsearch to start, will try again in 10 seconds..."
			except:
				print "Error: Waiting for Elasticsearch to start, will try again in 10 seconds..."
			# Sleep 10 seconds to give ES time to get started
			sleep(10)
	else:
		print "Elasticsearch already installed"
