from flask import Flask, render_template, request , send_file
from flask import jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename


import os
import time
import json
import logging
from logging.handlers import RotatingFileHandler
#from logging.handlers import SysLogHandler


import urllib.parse
import datetime

from threading import Thread
import Aruba_Wireless_Upgrade_APP
import config_file_generator
import yaml

import db_management




logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(os.path.join(os.getcwd(),"log","webserver_log.log"), maxBytes=5000000, backupCount=25)
formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.info("\n ==> Starting WEB server ...\n")


app = Flask(__name__,static_url_path='/static')
app.config['CONF_FILES'] = os.path.join(os.getcwd(),"conf_files")
app.config['JOBS_FILES'] = os.path.join(os.getcwd(),"jobs")
app.config['DB_LOCATION'] = os.path.join(os.getcwd(),"db")
app.config['CONF_TEMPLATES'] = os.path.join(os.getcwd(),"conf_templates")
#app.config['LOG_FILES'] = os.path.join(os.getcwd(),"log")
CORS(app)


print(os.getcwd())

# Create dummy thread
global main_thread
main_thread = Thread(target="",name="No")
main_thread.run()
main_thread.isAlive()


#Creating the table JOB HISTORY if not exist
db_management.create_history_db(os.path.join(app.config['DB_LOCATION'],"job_history.db"))

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
				#print(check_file)
				config = open(check_file,"r").read()
				config_json = yaml.load(config,Loader=yaml.Loader)
				return jsonify({"results":"success","data":config_json})
			else:
				return jsonify({"results":"error","message":"Config not exist...","config_name":str(config_name)})

	except Exception :
		logger.exception("read_config")
		return jsonify({"results":"error","message":"Check server log"})


def get_last_job():
	try:

		history_db = os.path.join(app.config['DB_LOCATION'],"job_history.db")
		#print(history_db)
			
		last_job = db_management.get_last_job(history_db)
		last_job_name = None

		if type(last_job) == tuple:
			if len(last_job) > 0:
				return last_job
		else:
			return None

	except Exception:
		logger.exception("get_last_job")

def get_all_jobs():
	try:

		history_db = os.path.join(app.config['DB_LOCATION'],"job_history.db")
		#print(history_db)
			
		last_job = db_management.get_all_jobs(history_db)
		last_job_name = None

		if type(last_job) == list:
			if len(last_job) > 0:
				return last_job
		else:
			return None

	except Exception:
		logger.exception("get_all_jobs")

@app.route('/portal/read_last_events',methods = ['GET'])
def read_last_events():
	try:
		if request.method == 'GET':
			#config_name = request.args.get('config_name')
			#download = request.args.get('download')

			last_job = get_last_job()

			if last_job == None:
				return jsonify({"results":"failed","message":"No last Job found"})

			job_name = last_job[1]

			events_db = os.path.join(app.config['JOBS_FILES'],str(job_name),"event.db")

			if os.path.isfile(events_db) == False:

				return jsonify({"results":"failed","msg":"no events for: "+str(job_name)})

			all_events = db_management.get_all_events(events_db)

			if type(all_events) == list:
				return jsonify({"results":"success","data":all_events})
			else:
				return jsonify({"results":"failed","msg":"no events for: "+str(job_name)})

	except Exception :
		logger.exception("read_last_events")
		return jsonify({"results":"error","message":"Check server log"})


@app.route('/portal/read_last_job',methods = ['GET'])
def read_last_job():
	try:
		if request.method == 'GET':
			#config_name = request.args.get('config_name')
			#download = request.args.get('download')

			last_job = get_last_job()

			if last_job == None:
				return jsonify({"results":"failed","message":"No last Job found"})

			
			job_name = last_job[1]
			job_file = last_job[2]
			job_status = last_job[3]
			job_s_date = last_job[4]
			job_e_date = last_job[5]
			job_msg = last_job[6]

			job_summary = {"job_name":job_name,"job_file":job_file,"job_status":job_status,"job_start_date":job_s_date,"job_end_date":job_e_date,"job_msg":job_msg}

			upgrade_db = os.path.join(app.config['JOBS_FILES'],str(job_name),"upgrade.db")

			if os.path.isfile(upgrade_db) == False:

				return jsonify({"results":"failed","msg":"no events for: "+str(job_name)})

			all_upgrade = db_management.get_upgrade_details(upgrade_db)

			if type(all_upgrade) == list:
				job_summary.update({"results":"success","data":all_upgrade})
				return jsonify(job_summary)
			else:
				return jsonify({"results":"failed","msg":"no events for: "+str(job_name)})

	except Exception :
		logger.exception("read_last_job")
		return jsonify({"results":"error","message":"Check server log"})

@app.route('/portal/read_all_jobs',methods = ['GET'])
def read_all_jobs():
	try:
		if request.method == 'GET':
			config_name = request.args.get('config_name')
			#download = request.args.get('download')

			all_jobs = get_all_jobs()

			if all_jobs == None:
				return jsonify({"results":"failed","message":"No Jobs found"})
			else:
				return jsonify({"results":"success","data":all_jobs})

	except Exception :
		logger.exception("read_all_jobs")
		return jsonify({"results":"error","message":"Check server log"})

@app.route('/portal/start_execution',methods = ['POST'])
def start_execution():
	try:
		global main_thread
		if request.method == 'POST':
			result = request.get_json()
			
			filename = result.get("file_name")
			job_list = result.get("job_list")

			if all(item in ["precheck","all"] for item in job_list) == False:
				return jsonify({"results":"failed","message":"Job list not valid"})

			
			full_path = os.path.join(app.config['CONF_FILES'], filename)

			if os.path.isfile(full_path):

				last_job = get_last_job()

				#print(last_job)
				print(last_job[3])
				if type(last_job) == tuple:
					if last_job[3] != "COMPLETED" and last_job[3] != "TERMINATED":
						return jsonify({"results":"failed","message":"Last Job {} not completed".format(str(last_job[2]))})

				S_DATE = str(datetime.datetime.now()).split(".")[0]
				job_name = str(time.time()).replace(".","_")
				data = {"NAME":job_name,"CONF_FILE":filename,"STATUS":"STARTING","S_DATE":S_DATE,"E_DATE":"","MSG":""}
				history_db = os.path.join(app.config['DB_LOCATION'],"job_history.db")
				status = db_management.insert_if_lastjob_completed(history_db,data)

				#main_thread.isAlive() == False
				if status == True:
					main_thread = Thread(target=aruba_wireless.main_run,name = "wireless_upgrade", args=(job_name,filename,job_list,))
					main_thread.start()
					return jsonify({"results":"success","message":"Job Started"})
				else:
					return jsonify({"results":"failed","message":"Existing Job Running"})

			return jsonify({"results":"failed","message":"File not found: "+str(filename)})

	except Exception:
		logger.exception("start_execution")
		return jsonify({"results":"error","message":"Check server log"})



@app.route('/portal/job_manage',methods = ['POST'])
def job_manage():
	try:
		if request.method == 'POST':
			result = request.get_json()
			#download = request.args.get('download')
			name = result.get("job_name")
			status = result.get("status")

			if status not in ["TERMINATED","PAUSED","RUNNING"]:
				return jsonify({"results":"failed","message":"Not valid job manage"})

			history_db = os.path.join(app.config['DB_LOCATION'],"job_history.db")

			if os.path.isfile(history_db) == False:
				return jsonify({"results":"failed","message":"History DB not available"})

			db_status = db_management.update_job_status_by_name(history_db,status,name,status+" by user","")

			if db_status != True:
				return jsonify({"results":"failed","message":"user request failed"})
			else:
				return jsonify({"results":"success","message":status})

	except Exception :
		logger.exception("job_manage")
		return jsonify({"results":"error","message":"Check server log"})


@app.route('/portal/yes_or_no',methods = ['POST'])
def yes_or_no():
	try:
		if request.method == 'POST':
			result = request.get_json()
			#download = request.args.get('download')
			e_id = result.get("e_id")
			name = result.get("name")
			msg = result.get("input")

			event_db_loc = os.path.join(os.getcwd(),"jobs",name,"event.db")

			if os.path.isfile(event_db_loc) == False:
				return jsonify({"results":"failed","message":"Updating user input (yes or no)"})

			status = db_management.update_event_db(event_db_loc,name,msg,e_id)

			if status != True:
				return jsonify({"results":"failed","message":"Updating user input failed"})
			else:
				return jsonify({"results":"success"})

	except Exception :
		logger.exception("yes_or_no")
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
