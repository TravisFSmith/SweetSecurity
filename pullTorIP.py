import urllib2, os

url = 'https://check.torproject.org/exit-addresses'

def GetExit(url):
	response = urllib2.urlopen(url)
	if response.getcode() == 200:
		yamlFile = open('/etc/logstash/translate/torIP.yaml','w')
		for line in response.readlines():
			if line.startswith('ExitAddress'):
				ip = line.split()[1]
				yamlFile.write("\"" + ip + "\": \"YES\"" + "\n")
		yamlFile.close
#Main 
def main():
	GetExit(url)

# call main
if __name__ == '__main__':
	main()