# Aruba MM,Controller,AP upgrade with pre,post check

import os
import logging
from logging.handlers import RotatingFileHandler
import yaml # From pyyaml
import cerberus
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests_toolbelt import MultipartEncoder
import pprint
from urllib.parse import urljoin
from cerberus import Validator
import datetime
import signal
import time
import re
import xlsxwriter # Import and check to prevent runtime panda error
import pandas
import textfsm


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.adapters.DEFAULT_RETRIES = 0

exe_logs = os.path.join(os.getcwd(),"logs")
logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(os.path.join(exe_logs,"logs"), maxBytes=50000000, backupCount=1)
formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = True

logger.info("Starting Aruba Wireless Upgrade module")

class main_model():

	def __init__(self):
		#Saving ssh session
		logger.info("Starting main model")

	def main_run():
		try:

			pass;


		except Exception:
			logger.exception("main_run")




if __name__ == '__main__':
	print("Direct call not supported...")