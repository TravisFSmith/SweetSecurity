import os, socket
import logging, server, spoof

def check():
	logger = logging.getLogger('SweetSecurityLogger')
	#Check Logstash Health
	if os.path.isfile('/usr/share/logstash/bin/logstash'):
		logstashHealth=os.popen('service logstash status').read()
		for line in logstashHealth.splitlines():
			if line.lstrip().startswith('Active: '):
				if line.lstrip().startswith('Active: active (running)'):
					logstashHealth='Started'
				else:
					logstashHealth='Stopped'
	else:
		logstashHealth='Not Installed'
	#print 'Logstash Health="%s"' % logstashHealth
	logger.info('Logstash Health="%s"' % logstashHealth)
	#Check Bro Health
	if os.path.isfile('/opt/nsm/bro/bin/broctl'):
		broStatus='Stopped'
		broHealth=os.popen('sudo /opt/nsm/bro/bin/broctl status').read()
		broLine=0
		for line in broHealth.splitlines():
			if broLine == 1:
				broStatus=line.split()[3]
			broLine+=1
	else:
		broStatus="Not Installed"
	#print 'Bro Health = "%s"' % broStatus
	logger.info('Bro Health = "%s"' % broStatus)
	
	#Check System resources
	diskUsage=0
	diskUsageCommand=os.popen('df -k "/"').read()
	for line in diskUsageCommand.splitlines():
		line = line.split()
		if line[0] != 'Filesystem':
			diskUsage=int(line[4][:-1])
	#print 'Disk Percentage Available: %d' % diskUsage
	logger.info('Disk Percentage Available: %d' % diskUsage)
	
	memUsage={'available': 0, 'consumed': 0, 'percentUsed': 0}
	memInfo=os.popen('free -t -m').read()
	for line in memInfo.splitlines():
		if line.rstrip().startswith('Mem:'):
			memUsage['available']=line.split()[1]
			memUsage['consumed']=line.split()[2]
			memUsage['percentUsed']=int(round((float(line.split()[2]) / float(line.split()[1])) * 100,0))
	#print 'Memory Available = "%s", Memory Consumed = "%s", Percent Used = "%d"' % (memUsage['available'],memUsage['consumed'],memUsage['percentUsed'])
	logger.info('Memory Available = "%s", Memory Consumed = "%s", Percent Used = "%d"' % (memUsage['available'],memUsage['consumed'],memUsage['percentUsed']))
	healthInfo={'sensorMac': spoof.getMac(), #done
		    'sensorName': socket.gethostname(), #done
		    'broHealth': broStatus, #done
		    'logstashHealth': logstashHealth, #done
		    'diskUsage': diskUsage, #done
		    'memAvailable': memUsage['available'], #done
		    'memConsumed': memUsage['consumed'], #done
		    'memPercent': memUsage['percentUsed']} #done
	server.healthCheck(healthInfo)
