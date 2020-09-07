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
import config_file_generator
import yaml




logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(os.path.join(os.getcwd(),"log","webserver_log.log"), maxBytes=5000000, backupCount=25)
formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.info("\n ==> Starting WEB server ...\n")



app = Flask(__name__,static_url_path='/static')
app.config['CONF_FILES'] = os.path.join(os.getcwd(),"conf_files")
app.config['DB_LOCATION'] = os.path.join(os.getcwd(),"db","job_history.db")
app.config['CONF_TEMPLATES'] = os.path.join(os.getcwd(),"conf_templates")
#app.config['LOG_FILES'] = os.path.join(os.getcwd(),"log")
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


@app.route('/portal/manage_file',methods = ['GET'])
def manage_file():
	try:
		if request.method == 'GET':
			f_type = request.args.get('type')
			#download = request.args.get('download')

			if f_type == "download" or f_type == "delete":
				f_name = request.args.get('file_name')
				
				check_file = os.path.join(app.config['CONF_FILES'],f_name)
				file_status = os.path.isfile(check_file)

				if file_status == True:
					if f_type == "delete":

						try:
							os.remove(check_file)
							name = os.listdir(app.config['CONF_FILES'])
							return jsonify({"status":"success","current_files":name})
						except:
							return jsonify({"status":"failed","message":"not deleted"})

					if f_type == "download":
						return send_file(check_file, as_attachment=True)

				else:
					return jsonify({"results":"error","message":"File not exist","config_name":str(f_type)})
			else:
				name = os.listdir(app.config['CONF_FILES'])
				return jsonify({"status":"success","current_files":name})

			return jsonify({"results":"failed"})

	except Exception :
		logger.exception("read_config")
		return jsonify({"results":"error","message":"Check server log"})

@app.route('/portal/read_config',methods = ['GET'])
def read_config():
	try:
		if request.method == 'GET':
			config_name = request.args.get('config_name')
			#download = request.args.get('download')

			check_file = os.path.join(app.config['CONF_FILES'],config_name)
			file_status = os.path.isfile(check_file)

			if file_status == True:
				print(check_file)
				config = open(check_file,"r").read()
				config_json = yaml.load(config,Loader=yaml.Loader)
				return jsonify({"results":"success","data":config_json})
			else:
				return jsonify({"results":"error","message":"Config not exist...","config_name":str(config_name)})

	except Exception :
		logger.exception("read_config")
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



@app.route('/portal/save_configuration',methods = ['POST'])
def save_configuration():
	try:
		if request.method == 'POST':
			json_config = request.form.get('config')
			config_name = request.form.get('config_name')
			override = request.form.get('override')

			check_file = os.path.join(app.config['CONF_FILES'],config_name)
			file_status = os.path.isfile(check_file)
			
			if file_status == True and override == "yes":
				pass;
			elif file_status == False:
				pass;
			else:
				return jsonify({"results":"error","message":"Configuration name already exist (Enable override to override the existing file)"})
			
			if type(json_config) == dict:
				yaml_config = yaml.safe_dump(json_config,default_flow_style=False)
				config = config_file_generator.validate_create_yaml(yaml_config)
				if type(config) == dict:
					if config.get("status") == "success":
						config_yaml = config.get("config_yaml")
						open(check_file,"w").write(config_yaml)
						return jsonify({"results":"success","message":"Configuration Saved"})
					else:
						return jsonify({"results":"failed","data":config.get("error")})
				else:
					return jsonify({"results":"error","message":"Check Server log..."})
			else:
				return jsonify({"results":"error","message":"Configuration not json"})
	except Exception:
		logger.exception("save_configuration")
		return jsonify({"results":"error","message":"validate_configuration - Check server log"})



# if __name__ == '__main__':
# 	app.run()
if __name__ == '__main__':
	aruba_wireless = Aruba_Wireless_Upgrade_APP.main_model()
	app.run(host="0.0.0.0", port=int("88888"), debug=True)
