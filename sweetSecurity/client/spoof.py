import sqlite3
import logging
from time import sleep
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

import sweetSecurityDB
dbPath="/opt/sweetsecurity/client/SweetSecurity.db"

def convertMAC(mac):
	newMac="%s%s:%s%s:%s%s:%s%s:%s%s:%s%s" % (mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],mac[6],mac[7],mac[8],mac[9],mac[10],mac[11])
	return newMac

def getMac():
	myMac = [get_if_hwaddr(i) for i in get_if_list()]
	for mac in myMac:
		if(mac != "00:00:00:00:00:00"):
			return mac

def start():
	logger = logging.getLogger('SweetSecurityLogger')
	while 1:
		try:
			dfgwInfo=sweetSecurityDB.getDfgw()
			dfgw=dfgwInfo['dfgw']
			dfgwMAC=dfgwInfo['dfgwMAC']
			dfgwMAC=convertMAC(dfgwMAC)
			conn = sqlite3.connect(dbPath)
			c = conn.cursor()
			for row in c.execute('SELECT * FROM hosts where active = 1 and ignore = 0'):
				logger.info("Spoofing Device: ip=%s, mac=%s",row[2],row[3])
				#Spoof the things...
				victimMac=convertMAC(row[3])
				packet = Ether()/ARP(op="who-has",hwdst=dfgwMAC,pdst=dfgw,psrc=row[2])
				sendp(packet)
				packet = Ether()/ARP(op="who-has",hwdst=victimMac,pdst=row[2],psrc=dfgw)
				sendp(packet)
			conn.close()
			sleep(1)
		except Exception,e: 
			logger.info("Error spoofing device: %s" % str(e))