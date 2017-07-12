import base64, json, sqlite3, ssl, urllib, urllib2, requests

dbPath='/opt/sweetsecurity/server/SweetSecurity.db'

def getCreds():
	creds={'user': None, 'pass': None}
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	for httpUserData in c.execute('SELECT * from configuration where object = "webUser"'):
		creds['user']=httpUserData[1]
	for httpPassData in c.execute('SELECT * from configuration where object = "webPass"'):
		creds['pass']=httpPassData[1]
	conn.close()
	return creds

def send(alertType,alertMessage,logID,logIndex):
	userCreds=getCreds()
	username=userCreds['user']
	password=userCreds['pass']
	data={'alertType': alertType,
	      'alertMessage': alertMessage,
	      'logID': logID,
	      'logIndex': logIndex}
	url = 'https://localhost/alerts/add'
	csrfUrl = 'https://localhost/csrf'
	session = requests.Session()
	session.auth = (username, password)
	auth = session.get(csrfUrl, verify=False)
	data['csrf_token']=auth.content
	response=session.post(url,data=data, verify=False, headers={"referer": url})
	return response

fileName='Malware.exe'
md5='md5md5md5md5md5'
sha1='sha1sha1sha1sha1sha1'
fileCheckScore='666'
internalNickname='Ring Doorbell'
externalIP='1.2.3.4'
alert='FileCheck.io Found a Malicious File\nFile Name: %s\nFile MD5: %s\nFile SHA1: %s\nFileCheckIO Reputation Score: %s' % (fileName,md5,sha1,fileCheckScore)
#response=send('filecheck',alert,'AV0uJIO23T9D9HeOSUtW','logstash-2017.07.10')
#print response.status_code
#print response.text


alert='Disk usage above 85%'
#response=send('diskcheck',alert,None,None)
#print response.status_code
#print response.text
