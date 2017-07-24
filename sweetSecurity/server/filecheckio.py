import alert, es, logging
import urllib, urllib2, ssl, json
from elasticsearch import Elasticsearch
esService = Elasticsearch()

def putKey(apiKey):
	matchAll = {"query": {"match_all": {}}}
	ssConfig = es.search(esService, matchAll, 'sweet_security', 'configuration')
	if ssConfig is not None:
		for config in ssConfig['hits']['hits']:
			body = {'doc' : {'fileCheckKey': apiKey}}
			es.update(esService, body, 'sweet_security', 'configuration', config['_id'])

def getKey():
	# Get Configuration Settings
	apiKey=None
	matchAll = {"query": {"match_all": {}}}
	ssConfig = es.search(esService, matchAll, 'sweet_security', 'configuration')
	if ssConfig is not None:
		for config in ssConfig['hits']['hits']:
			if 'fileCheckKey' in config['_source']:
				apiKey=config['_source']['fileCheckKey']
	return apiKey

def check(apiKey, fileName=None, fileSize=None, fileVersion=None, md5=None, sha1=None, sha256=None, sha512=None):
	ctx = ssl.create_default_context()
	url = "https://filecheck.io/api"
	parameters = {"fileName": fileName or "",
	"size": fileSize or "",
	"version": fileVersion or "",
	"md5": md5 or "",
	"sha1": sha1 or "",
	"sha256": sha256 or "",
	"sha512": sha512 or "",
	"key": apiKey}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req, context=ctx)
	return response

def getLogData():
	files=[]
	#timestamp is 10m to make sure we don't miss anything, will skip the check if the file was already checked
	fileQuery={"query": {
			"bool":{
				"must":[
					{"match_phrase": { "path": "/opt/nsm/bro/logs/current/files.log" }},
					{"range" : { "@timestamp" : {"gt" : "now-10m"}}}]
				}
			}
		}
	fileData=es.search(esService, fileQuery, 'logstash-*', 'logs', 10000)
	logTotal=fileData['hits']['total']
	for log in fileData['hits']['hits']:
		files.append(log)
	return files

def run():
	logger = logging.getLogger('SweetSecurityServerLogger')
	logger.info('Checking Files Against FileCheck.io')
	fileData=getLogData()
	apiKey=getKey()
	if apiKey is None:
		logger.info('FileCheckIO Key Not Configured')
		return None
	else:
		logger.info('Checking Files Against FileCheck.IO')
	logger.info("Parsing %d files" % len(fileData))
	for file in fileData:
		if '_grokparsefailure' not in file['_source']['tags']:
			#Size and Version are optional
			fileVersion=''
			fileSize=''
			#One or More of the Following Are Required
			fileName=''
			md5=file['_source']['md5']
			if file['_source']['sha1'] != '-':
				sha1=file['_source']['sha1']
			else:
				sha1=''
			sha256=''
			sha512=''
			if file['_source']['filename'] != '-':
				fileName=file['_source']['filename']
			if 'filecheckscore' not in file['_source']:
				fileStatus=check(apiKey, fileName, fileSize, fileVersion, md5, sha1, sha256, sha512)
				fileCheckJson=json.loads(fileStatus.read())
				try:
					if fileCheckJson['status']==400:
						logger.info("Exceeded FileCheck.io api requests")
						return None
				except: pass
				filecheckScore=fileCheckJson['validation']
				filecheckScore=fileCheckJson['validation']
				body = {'doc' : {'filecheckscore': filecheckScore}}
		                es.update(esService, body, file['_index'], 'logs', file['_id'])
				if filecheckScore not in [0,404]:
					logger.info("ALERT: FileCheck.io found a malicious file!")
					message='FileCheck.io Found a Malicious File\nFile Name: %s\nFile MD5: %s\nFile SHA1: %s\nFileCheckIO Reputation Score: %s' % (fileName,md5,sha1,filecheckScore)
					alert.send('FileCheckIO',message,file['_id'],file['_index'])
					print "Sending Message"

