import threading
import logging.handlers
from time import sleep

import baseliner
import logs
import logRetention
import filecheckio

logger = logs.setup()

def startLogRetention():
	while 1:
		#Check every hour
		logRetention.deleteOldLogs()
		sleep(3600)

def startFileCheckIO():
	while 1:
		#Check every 5 minutes
		filecheckio.run()
		sleep(300)

def startBaseliner():
	while 1:
		#Check every 5 minutes
		baseliner.run()
		sleep(300)

def doStuff():
	logger.info('Starting up SweetSecurity Server')

	logger.info('Starting log retention thread')
	logRetentionThread = threading.Thread(target=startLogRetention)
	logRetentionThread.start()

	logger.info('Starting FileCheckIO thread')
	fcioThread = threading.Thread(target=startFileCheckIO)
	fcioThread.start()

	logger.info('Starting Baseliner thread')
	baselinerThread = threading.Thread(target=startBaseliner)
	baselinerThread.start()


doStuff()


