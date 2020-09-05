from flask import Flask, render_template, request , send_file
from flask import jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename


import os
import time
import json
import logging
from logging.handlers import RotatingFileHandler
from logging.handlers import SysLogHandler


import urllib.parse
import datetime

from threading import Thread
import Aruba_Wireless_Upgrade_APP





logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(os.path.join(os.getcwd(),"webserver_log.log"), maxBytes=5000000, backupCount=25)
formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.info("\n ==> Starting WEB server ...\n")



app = Flask(__name__,static_url_path='/static')
app.config['CONF_FILES'] = os.path.join(os.getcwd(),"conf_files")
app.config['DB_FILES'] = os.path.join(os.getcwd(),"db")
app.config['CONF_TEMPLATES'] = os.path.join(os.getcwd(),"conf_templates")
app.config['LOG_FILES'] = os.path.join(os.getcwd(),"logs")
CORS(app)


print(os.getcwd())

# Create dummy thread
global main_thread
main_thread = Thread(target="",name="No")
main_thread.run()
main_thread.isAlive()

@app.route('/')
def main():
	 return render_template('index.html')

@app.route('/portal/status')
def status():
	 return "API IS UP :"+str(datetime.datetime.utcnow())


@app.route('/portal/post_config',methods = ['POST'])
def email_agent_post():
	try:
		if request.method == 'POST':
			result = request.form
			
			agentname = result.get("agentname")
			agent_type = result.get("agent_type")
			data = result.get("data")

			return jsonify({"results":"success","DB":"","message":"DB response"})

	except Exception :
		logger.exception("post_config")
		return jsonify({"results":"error","message":"Check server log"})


@app.route('/portal/start_execution',methods = ['POST'])
def start_execution():
	try:
		global main_thread
		if request.method == 'POST':
			result = request.form
			
			file_name = result.get("file_name")

			filename = secure_filename(file_name)
			full_path = os.path.join(app.config['CONF_FILES'], filename)

			if os.path.isfile(full_path):

				if main_thread.isAlive() == False:
						main_thread = Thread(target=aruba_wireless.main_run,name = "wireless_upgrade", args=(full_path,))
						main_thread.start()
						return jsonify({"results":"success","message":"Job Started"})
				else:
					return jsonify({"results":"failed","message":"ExistingJobRunning"})

			return jsonify({"results":"failed","message":"File not found: "+str(filename)})

	except Exception:
		logger.exception("start_execution")
		return jsonify({"results":"error","message":"Check server log"})


def validate_create_yaml(json_data):
	"""
	---
Upgrade:
  - hostname: NaaS-MM-1
    type: MM
    image_file_name: ArubaOS_MM_8.6.0.5_75979
    host: 10.17.84.220:4343

  - hostname: NaaS-VMC-1
    type: MD
    image_file_name: ArubaOS_VMC_8.6.0.5_75979
    host: 10.17.84.221:4343


default:
  AOS Source:
    type: ftp
    ftp_host: 10.17.84.225
    ftp_username: admin
    ftp_password: admin123456
    ftp_path: /

  MM:
    image_file_name: ArubaOS_MM_8.6.0.5_75979
    image_version: 8.6.0.5
    image_build: 75979
    upgrade_disk: Auto
    CheckList_MM:
      - show: show clock
      - show: show version
      - show: show image version
      - show: show storage
      - show: show cpuload
      - show: show memory
      - show: show boot
      - show: show switches
      - show: show switchinfo
      - show: show boot history

      - show: show crypto Ipsec sa
      - show: show master-redundancy
      - show: show database synchronize
      - show: show license
      - show: show running-config


  MD:
    image_file_name: ArubaOS_MM_8.6.0.5_75979
    image_version: 8.6.0.5
    image_build: 75979
    upgrade_disk: Auto
    Pre_image_AP: True
    max_ap_image_load: 10
    CheckList_MD:
      - show: show clock
      - show: show version
      - show: show image version
      - show: show storage
      - show: show cpuload
      - show: show memory
      - show: show boot
      - show: show switches
      - show: show switchinfo
      - show: show boot history

      - show: show user
      - show: show ap database long 
      - show: show ap bss-table 
      - show: show ap essid
      - show: show ap active counters
      - show: show ap debug counters
      - show: show lc-cluster group-membership
      - show: show switches
      - show: show license
      - show: show running-config
      - show: show boot
      - show: show version

  Authentication:
    username: admin
    password: Aruba@123$


  Validate Image before upgrade: True
  Validate controller sync before upgrade: True
  Validate controller up before upgrade: True




	"""
	try:
		#conf_yaml = yaml.load(config_file,Loader=yaml.Loader)
		



	except Exception:
		logger.exception("validate_create_yaml")
		return jsonify({"results":"error","message":"Check server log"})

@app.route('/portal/excell_to_json',methods = ['POST'])
def excell_to_json():
	try:
		global main_thread
		if request.method == 'POST':
			xlfile = request.files['file']
			#override = request.form.get('override')
			content = xlfile.stream.read()
			print(str(content))




	except Exception:
		logger.exception("start_execution")
		return jsonify({"results":"error","message":"Check server log"})



# if __name__ == '__main__':
# 	app.run()
if __name__ == '__main__':
	aruba_wireless = Aruba_Wireless_Upgrade_APP.main_model()
	app.run(host="0.0.0.0", port=int("88888"), debug=True)
