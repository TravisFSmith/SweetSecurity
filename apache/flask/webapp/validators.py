import re

def convertMac(macAddress):
	if re.match(r"^[A-za-z0-9]{2}-[A-za-z0-9]{2}-[A-za-z0-9]{2}-[A-za-z0-9]{2}-[A-za-z0-9]{2}-[A-za-z0-9]{2}$",macAddress):
		macAddress=macAddress.replace('-','')
	elif re.match(r"^[A-za-z0-9]{2}:[A-za-z0-9]{2}:[A-za-z0-9]{2}:[A-za-z0-9]{2}:[A-za-z0-9]{2}:[A-za-z0-9]{2}$",macAddress):
		macAddress=macAddress.replace(':','')
	return macAddress.upper()

def macAddress(macAddress):
	dashMatch = re.match(r"^[A-Fa-f0-9]{2}-[A-Fa-f0-9]{2}-[A-Fa-f0-9]{2}-[A-Fa-f0-9]{2}-[A-Fa-f0-9]{2}-[A-Fa-f0-9]{2}$",macAddress)
	colonMatch = re.match(r"^[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}$",macAddress)
	alphaMatch =  re.match(r"^[A-Fa-f0-9]{12}$",macAddress)
	if dashMatch or colonMatch or alphaMatch:
		return True
	else:
		return False

def url(url):
	urlMatch= re.match(r"^([a-zA-Z0-9][a-zA-Z0-9\-\_]+[a-zA-Z0-9]\.)+([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-\_])+[A-Za-z0-9]$",url)
	ipMatch= re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",url)
	if urlMatch or ipMatch:
		return True
	else:
		return False

def hostname(hostname):
	hostnameMatch= re.match(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-\_]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-\_]*[A-Za-z0-9])$",hostname)
	noHostnameMatch = re.match(r"^(\d+\.\d+\.\d+\.\d+\s\(\w{12}\))",hostname)
	if hostnameMatch or noHostnameMatch:
		return True
	else:
		return False

def ipAddress(ipAddress):
	ipMatch= re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",ipAddress)
	if ipMatch:
		return True
	else:
		return False

def ignoreStatus(ignored):
	ignoreMatch = re.match(r"^[0-1]$",ignored)
	if ignoreMatch:
		return True
	else:
		return False
