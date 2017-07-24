import datetime, logging, os, time
import alert, es

from elasticsearch import Elasticsearch
esService = Elasticsearch()

def getNumIndices():
	return len(esService.indices.get('logstash-*'))

def putSSConfig():
	config={'defaultIsolate': 0, 'defaultLogRetention': 0, 'defaultMonitor': 0, 'defaultFW': 0}
	config['lastModified']= str(int(round(time.time() * 1000)))
	es.write(esService,config,'sweet_security','configuration')
	return "done"

def getSSConfig():
	config={'defaultIsolate': 0, 'defaultLogRetention': 30, 'defaultMonitor': 0, 'defaultFW': 0}
	matchAll = {"query": {"match_all": {}}}
	ssConfigData=es.search(esService,matchAll,'sweet_security','configuration')
	if ssConfigData is not None:
		for entry in ssConfigData['hits']['hits']:
			config=entry['_source']
	return config

def checkDisk():
	diskUsage=0
	diskUsageCommand=os.popen('df -k "/"').read()
	for line in diskUsageCommand.splitlines():
		line = line.split()
		if line[0] != 'Filesystem':
			diskUsage=int(line[4][:-1])
	return diskUsage

def deleteOldLogs():
	logger = logging.getLogger('SweetSecurityServerLogger')
	logger.info('Checking local disk space')
	diskUsage=checkDisk()
	#Warn user if disk storage is above 85%
	if diskUsage > 84:
		message='Server disk usage is at %d%%' % diskUsage
		response=alert.send('Disk Check',message,None,None)
	logger.info('Cleaning up logs')
	ssConfig=getSSConfig()
	defaultLogRetention=ssConfig['defaultLogRetention']
	if defaultLogRetention == 0:
		logger.info('System configured to never delete logs')
		return 'Logs configured to never delete'
	else:
		logger.info('System is configured to delete logs older than %d days' % defaultLogRetention)
	matchAll = {"query": {"match_all": {}}}
	logsDeleted=0
	today=datetime.datetime.now()
	indices=[]
	for index in esService.indices.get('logstash-*'):
		indices.append(index)
	logger.info("There are %d days worth of logs" % len(indices))
	indices=sorted(indices)
	for index in indices:
		indexData=es.search(esService, matchAll, index, 'logs')
		logCount=indexData['hits']['total']
		indexDate=datetime.datetime.strptime(index[-10:],"%Y.%m.%d")
		indexDaysOld=today-indexDate
		indexDaysOld=indexDaysOld.days
		logger.info("%s is %d days old and has %d logs" % (index,indexDaysOld,logCount))
		if indexDaysOld > defaultLogRetention:
			logger.info("Deleting index %s" % index)
			#esService.indices.delete(index=index)
			logsDeleted+=logCount
	logger.info("Deleted %d logs" % logsDeleted)
	return "Deleted %d logs" % logsDeleted

#print checkDisk()
#print deleteOldLogs()

