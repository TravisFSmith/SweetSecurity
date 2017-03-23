#!/usr/bin/python
import os,sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/webapp/")

from webapp import create_app
application = create_app()
