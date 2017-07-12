import hashlib, json, os, shutil, threading
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
import iptables

#configure sweetSecurity.log
logger = logs.setup()

def startGetConfig():
	while 1:
		try:
			serverConfig=json.loads(server.getConfig())
			iptables.writeHeader()
			allowedTrafficRules=[]
			dropTrafficRules=[]
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
				if device['isolate'] == '1':
					spoofingInterface=str(nmap.getSpoofingInterface())
					sensorIP=nmap.getIP(spoofingInterface)
					sensorMask=nmap.getNetmask(spoofingInterface)
					localSubnet='%s/%s' % (sensorIP,sensorMask)
					logger.info('Isolating device: blocking %s/%s',sensorIP,sensorMask)
					trafficRule={'type': 'full', 'action': 'DROP', 'source': device['ip'], 'destination': localSubnet}
					dropTrafficRules.append(trafficRule)
					#iptables.addFull(device['ip'],localSubnet,'DROP')
				for entry in device['firewall']:
					trafficRule={'type': 'None', 'action': entry['action'], 'source': device['ip'], 'destination': 'None'}
					if entry['destination'] == "*":
						trafficRule['type']='simple'
						#iptables.addSimple(device['ip'],entry['action'])
					elif len(entry['destination']) > 0:
						trafficRule['type']='full'
						trafficRule['destination']=entry['destination']
						#iptables.addFull(device['ip'],entry['destination'],entry['action'])
					if entry['action'] == 'DROP':
						dropTrafficRules.append(trafficRule)
					else:
						allowedTrafficRules.append(trafficRule)
			#Apply dropped traffic first
			for rule in dropTrafficRules:
				if rule['type'] == 'simple':
					iptables.addSimple(rule['source'],rule['action'])
				else:
					iptables.addFull(rule['source'],rule['destination'],rule['action'])
			for rule in allowedTrafficRules:
				 if rule['type'] == 'simple':
                                        iptables.addSimple(rule['source'],rule['action'])
                                 else:
                                        iptables.addFull(rule['source'],rule['destination'],rule['action'])
			iptables.writeFooter()
			if os.path.isfile('/opt/sweetsecurity/client/iptables_existing.sh'):
				#Check if it changed to see if we need to apply it or not...
				existingHash=hashlib.md5(open('/opt/sweetsecurity/client/iptables_existing.sh','rb').read()).hexdigest()
				newHash=hashlib.md5(open('/opt/sweetsecurity/client/iptables_new.sh','rb').read()).hexdigest()
				if newHash != existingHash:
					os.remove('/opt/sweetsecurity/client/iptables_existing.sh')
					shutil.move('/opt/sweetsecurity/client/iptables_new.sh','/opt/sweetsecurity/client/iptables_existing.sh')
					os.chmod('/opt/sweetsecurity/client/iptables_existing.sh',755)
					os.popen('sudo /opt/sweetsecurity/client/iptables_existing.sh').read()
					logger.info('applying new firewall config')
				else:
					os.remove('/opt/sweetsecurity/client/iptables_new.sh')
			else:
				shutil.move('/opt/sweetsecurity/client/iptables_new.sh','/opt/sweetsecurity/client/iptables_existing.sh')
				os.chmod('/opt/sweetsecurity/client/iptables_existing.sh',755)
				os.popen('sudo /opt/sweetsecurity/client/iptables_existing.sh').read()
				logger.info('applying new firewall config')
		except Exception, e:
			logger.info(str(e))
			pass
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

