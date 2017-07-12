import base64, json, sqlite3, ssl, urllib, urllib2, requests

dbPath="/opt/sweetsecurity/client/SweetSecurity.db"

def getCreds():
	creds={'address': None, 'user': None, 'pass': None, 'webCert': 'development'}
	conn = sqlite3.connect(dbPath)
	c = conn.cursor()
	for httpAddressData in c.execute('SELECT * from configuration where object = "webAddress"'):
		creds['address']=httpAddressData[1]
	for httpUserData in c.execute('SELECT * from configuration where object = "webUser"'):
		creds['user']=httpUserData[1]
	for httpPassData in c.execute('SELECT * from configuration where object = "webPass"'):
		creds['pass']=httpPassData[1]
	for httpCertData in c.execute('SELECT * from configuration where object = "webCert"'):
		creds['webCert']=httpCertData[1]
	conn.close()
	return creds

def addDevice(hostname,ip,mac,vendor,ignored):
	userCreds=getCreds()
	address=userCreds['address']
	username=userCreds['user']
	password=userCreds['pass']
	webCert=userCreds['webCert']
	data={'hostname': hostname, 
			'ip': ip,
			'macAddress': mac, 
			'vendor': vendor, 
			'ignored': ignored}
	url = 'https://%s/addDevice' % address
	csrfUrl = 'https://%s/csrf' % address
	session = requests.Session()
	session.auth = (username, password)
	if webCert == 'development':
		auth = session.get(csrfUrl, verify=False)
		data['csrf_token']=auth.content
		response=session.post(url,data=data, verify=False, headers={"referer": url})
	else:
		auth = session.get(csrfUrl, verify=False)
		data['csrf_token']=auth.content
		response=session.post(url ,data=data, verify=False, headers={"referer": url })
	return response

def addPort(portInfo): 
	userCreds=getCreds()
	address=userCreds['address']
	username=userCreds['user']
	password=userCreds['pass']
	webCert=userCreds['webCert']
	url = 'https://%s/addPort' % address
	csrfUrl = 'https://%s/csrf' % address
	session = requests.Session()
	session.auth = (username, password)
	if webCert == 'development':
		auth = session.get(csrfUrl, verify=False)
		portInfo['csrf_token']=auth.content
		response=session.post(url,data=portInfo, verify=False, headers={"referer": url})
	else:
		auth = session.get(csrfUrl, verify=False)
		portInfo['csrf_token']=auth.content
		response=session.post(url ,data=portInfo, verify=False, headers={"referer": url })
	return response

def getConfig(): 
	userCreds=getCreds()
	address=userCreds['address']
	username=userCreds['user']
	password=userCreds['pass']
	webCert=userCreds['webCert']
	url = 'https://%s/getConfig' % address
	req = urllib2.Request(url)
	base64string = base64.b64encode('%s:%s' % (username, password))
	req.add_header("Authorization", "Basic %s" % base64string)   
	if webCert == 'development':
		context = ssl._create_unverified_context()
		response = urllib2.urlopen(req, context=context)
	else:
		response = urllib2.urlopen(req)
	result=response.read()
	return result

def healthCheck(healthInfo):
	userCreds=getCreds()
	address=userCreds['address']
	username=userCreds['user']
	password=userCreds['pass']
	webCert=userCreds['webCert']
	url = 'https://%s/sensorHealth' % address
	csrfUrl = 'https://%s/csrf' % address
	session = requests.Session()
	session.auth = (username, password)
	if webCert == 'development':
		auth = session.get(csrfUrl, verify=False)
		healthInfo['csrf_token']=auth.content
		response=session.post(url,data=healthInfo, verify=False, headers={"referer": url})
	else:
		auth = session.get(csrfUrl, verify=False)
		healthInfo['csrf_token']=auth.content
		response=session.post(url ,data=healthInfo, verify=False, headers={"referer": url })
	return response
