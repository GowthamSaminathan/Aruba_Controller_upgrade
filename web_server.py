from flask import Flask, render_template, request , send_file
from flask import jsonify
from flask_cors import CORS


import os
import time
import json
import logging
from logging.handlers import RotatingFileHandler
from logging.handlers import SysLogHandler


import urllib.parse
import datetime





logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(os.path.join(os.getcwd(),"webserver_log.log"), maxBytes=5000000, backupCount=25)
formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.info("\n ==> Starting WEB server ...\n")



app = Flask(__name__,static_url_path='/static')
CORS(app)


print(os.getcwd())

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

	except Exception as e:
		return jsonify({"results":"error","message":str(e)})


@app.route('/portal/get_config',methods = ['GET'])
def email_agent_get():
	try:
		if request.method == 'GET':

			#find_email = email_collection.find_one({"_id":1},{"_id":0})

			return jsonify({"results":"success","type":"email_agent","data":""})

	except Exception as e:
		return jsonify({"results":"error","message":str(e)})



# if __name__ == '__main__':
# 	app.run()
if __name__ == '__main__':
	app.run(host="0.0.0.0", port=int("88888"), debug=True)
