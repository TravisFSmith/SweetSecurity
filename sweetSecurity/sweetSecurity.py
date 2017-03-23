import json, os, threading
import logging.handlers
from time import sleep

#Local Scripts
import logs
import sweetSecurityDB
import nmap
import spoof
import server
import pullMaliciousIP
import pullTorIP
import healthCheck

#configure sweetSecurity.log
logger = logs.setup()

def startGetConfig():
	while 1:
		serverConfig=json.loads(server.getConfig())
		for device in serverConfig['deviceList']:
			localConfig=sweetSecurityDB.getDeviceSpoofStatus(device['mac'])
			if str(localConfig[0]) != str(device['ignore']):
				if device['ignore'] == '1':
					logger.info('Stop Spoofing %s' % device['mac'])
					result=sweetSecurityDB.dontSpoof(device['mac'])
				elif device['ignore'] == '0':
					logger.info('Start Spoofing %s' % device['mac'])
					result=sweetSecurityDB.spoof(device['mac'])
				logger.info(result)
		sleep(5)

def startPingSweep():
	while 1:
		nmap.pingSweep()
		sleep(20)

def startPortScan():
	while 1:
		#Port Scan Every Hour, sleeping first to let first ping sweep finish
		sleep(60)
		nmap.portScan()
		sleep(3540)

def startLsTi():
	while 1:
		#Pull New Info Every Hour
		logger.info('Downloading malicious IP list')
		pullMaliciousIP.do()
		logger.info('Downloading TOR Exit node list')
		pullTorIP.do()
		#If Critical Stack is installed, pull feeds
		if os.path.isfile('/usr/bin/critical-stack-intel'):
			os.popen('sudo -u critical-stack critical-stack-intel pull').read()
		sleep(3600)

def startHealthCheck():
	while 1:
		#get info every 5 minutes
		healthCheck.check()
		sleep(300)

def doStuff():
	logger.info('Starting up SweetSecurity')
	#Make sure we can forward data...
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
	
	#Start Bro
	os.popen('sudo /opt/nsm/bro/bin/broctl deploy').read()
	
	healthCheckThread = threading.Thread(target=startHealthCheck)
	healthCheckThread.start()
	getConfigThread = threading.Thread(target=startGetConfig)
	getConfigThread.start()
	pingSweepThread = threading.Thread(target=startPingSweep)
	pingSweepThread.start()
	portScanThread = threading.Thread(target=startPortScan)
	portScanThread.start()
	spoofThread = threading.Thread(target=spoof.start())
	spoofThread.start()
	#For Logstash Threat Intel Translate Filters and Critical Stack Updates
	lsTiThread = threading.Thread(target=startLsTi)
	lsTiThread.start()


doStuff()

