import logging

def setup():
	LOG_FILENAME='/var/log/sweetsecurity_server.log'
	logger = logging.getLogger('SweetSecurityServerLogger')
	logger.setLevel(logging.INFO)
	handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=20000000, backupCount=5)
	handler.setFormatter(logging.Formatter("%(asctime)s: %(message)s"))
	logger.addHandler(handler)
	return logger

