import sqlite3
import datetime
import os
import logging
from logging.handlers import RotatingFileHandler

logger = logging.getLogger("db_management")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(os.path.join(os.getcwd(),"log","db_management.log"), maxBytes=5000000, backupCount=25)
formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.info("DB Managenet imported")


def create_history_db(db_path):
	conn = sqlite3.connect(db_path)
	cmd = "ID INTEGER PRIMARY KEY AUTOINCREMENT,NAME TEXT NOT NULL,CONF_FILE NAME TEXT NOT NULL,STATUS TEXT NOT NULL,S_DATE TEXT,E_DATE TEXT,MSG TEXT NOT NULL"
	try:
		conn.execute('''CREATE TABLE IF NOT EXISTS HISTORY({});'''.format(cmd))
		print("HISTORY table created successfully")
		#print(conn)
		#return conn
		conn.close()
		return True
	except Exception:
		logger.exception("create_history_db")

def create_job_db(db_path):
	conn = sqlite3.connect(db_path)
	cmd = "ID INTEGER PRIMARY KEY AUTOINCREMENT,NAME TEXT NOT NULL,DEVICE_TYPE NAME TEXT NOT NULL,HOST_NAME TEXT NOT NULL,HOST TEXT NOT NULL,"
	cmd = cmd+"UPGRADE_VERSION TEXT NOT NULL,STATUS TEXT NOT NULL,CONF_FILE TEXT NOT NULL,MSG TEXT NOT NULL,S_DATE TEXT,E_DATE TEXT"
	try:
		conn.execute('''CREATE TABLE JOBS({});'''.format(cmd))
		print("JOBS table created successfully")
		#return conn
		conn.close()
		return True
	except Exception:
		logger.exception("create_job_db")


def create_event_db(db_path):
	conn = sqlite3.connect(db_path)
	cmd = "ID INTEGER PRIMARY KEY AUTOINCREMENT,NAME TEXT NOT NULL,E_DATE NAME TEXT NOT NULL,MSG TEXT NOT NULL,E_ID TEXT"
	try:
		conn.execute('''CREATE TABLE EVENTS({});'''.format(cmd))
		print("EVENT table created successfully")
		#return conn
		conn.close()
		return True
	except Exception:
		logger.exception("create_event_db")

def get_event_update_by_eid(db_path,e_id):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		evnt = conn.execute("SELECT ID,NAME,E_DATE,MSG,E_ID FROM EVENTS WHERE E_ID='{}'".format(e_id))
		evnt = evnt.fetchall()
		conn.close()
		return evnt
	except Exception:
		logger.exception("get_event_update_by_eid")

def get_event_update_by_name(db_path,NAME):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		evnt = conn.execute("SELECT ID,NAME,E_DATE,MSG,E_ID FROM EVENTS WHERE NAME='{}'".format(NAME))
		evnt = evnt.fetchall()
		conn.close()
		return evnt
	except Exception:
		logger.exception("get_event_update_by_name")

def update_job_status_by_name(db_path,status,job_name,msg=None):
	try:
		conn = sqlite3.connect(db_path)
		cursor = conn.cursor()
		if msg != None:
			logger.info("UPDATE HISTORY set STATUS='{}' where NAME='{}'".format(status,job_name))
			cursor.execute("UPDATE HISTORY set STATUS='{}' where NAME='{}'".format(status,job_name))
		else:
			logger.info("UPDATE HISTORY set STATUS='{}' where NAME='{}'".format(status,job_name))
			cursor.execute("UPDATE HISTORY set STATUS='{}',MSG='{}' where NAME='{}'".format(status,msg,job_name))


		conn.commit()
		
		if cursor.rowcount == 1:
			return True
		else:
			return False
		
	except Exception:
		logger.exception("update_job_status_by_name")


def get_last_job(db_path):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		cursor = conn.cursor()
		cursor.execute("SELECT ID,NAME,CONF_FILE,STATUS,S_DATE,E_DATE,STATUS FROM HISTORY ORDER BY ID DESC LIMIT 1")
		result = cursor.fetchone()
		conn.close()
		return result
	except Exception:
		logger.exception("get_last_job")

def get_all_jobs(db_path):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		cursor = conn.cursor()
		cursor.execute("SELECT ID,NAME,CONF_FILE,STATUS,S_DATE,E_DATE,STATUS FROM HISTORY ORDER BY ID DESC")
		result = cursor.fetchall()
		conn.close()
		return result
	except Exception:
		logger.exception("get_all_jobs")


def update_event_db(db_path,job_name,msg,e_id):
	try:
		conn = sqlite3.connect(db_path)
		E_DATE = str(datetime.datetime.now()).split(".")[0]
		conn.execute("INSERT INTO EVENTS (NAME,E_DATE,MSG,E_ID) VALUES ('{}','{}','{}','{}')".format(job_name,E_DATE,msg,e_id))
		conn.commit()
		conn.close()
		return True
	except Exception:
		logger.exception("update_event_db",conf_file)

def insert_to_upgrade(db_path,job_name,conf_file,data):
	try:
		device_type = data.get("device_type")
		host = data.get("host")
		hostname = data.get("hostname")
		image_version = data.get("image_version")
		image_build = data.get("image_build")
		up_version = str(image_version)+":"+str(image_build)

		status = "PENDING"
		s_date = str(datetime.datetime.now()).split(".")[0]
		e_date = "-"
		msg = "Precheck"

		conn = sqlite3.connect(db_path)
		cursor = conn.cursor()
		cmd = "INSERT INTO JOBS (NAME,DEVICE_TYPE,HOST_NAME,HOST,UPGRADE_VERSION,STATUS,CONF_FILE,MSG,S_DATE,E_DATE) "
		cmd = cmd+"VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}')".format(job_name,device_type,hostname,host,up_version,status,conf_file,msg,s_date,e_date)
		cursor.execute(cmd)
			
		
		conn.commit()
		conn.close()

		if cursor.lastrowid > 0:
			return True
		else:
			return False
	except Exception:
		logger.exception("insert_to_upgrade")


def get_all_events(db_path):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		cursor = conn.cursor()
		cursor.execute("SELECT ID,NAME,E_DATE,MSG,E_ID FROM EVENTS")
		result = cursor.fetchall()
		conn.close()
		return result
	except Exception:
		logger.exception("get_all_events")

def get_upgrade_details(db_path):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		cursor = conn.cursor()
		#ID,NAME,DEVICE_TYPE,HOST_NAME,HOST,UPGRADE_VERSION,STATUS,CONF_FILE,MSG,S_DATE,E_DATE
		cursor.execute("SELECT ID,DEVICE_TYPE,HOST_NAME,HOST,UPGRADE_VERSION,STATUS,MSG FROM JOBS")
		result = cursor.fetchall()
		conn.close()
		return result
	except Exception:
		logger.exception("get_upgrade_details")

def insert_if_lastjob_completed(db_path,data):
	try:
		
		
		NAME = data.get("NAME")
		CONF_FILE = data.get("CONF_FILE")
		STATUS = data.get("STATUS")
		S_DATE = data.get("S_DATE")
		E_DATE = data.get("E_DATE")
		MSG = data.get("MSG")

		query = "INSERT INTO HISTORY (NAME,CONF_FILE,STATUS,S_DATE,E_DATE,MSG) SELECT '{}','{}','{}','{}','{}','{}'".format(NAME,CONF_FILE,STATUS,S_DATE,E_DATE,MSG)
		query = query + " WHERE NOT EXISTS (SELECT * FROM HISTORY WHERE ID = (SELECT MAX(ID) FROM HISTORY) AND (STATUS='RUNNING' OR STATUS='STARTING'));"

		query = query.format(NAME,CONF_FILE,STATUS,S_DATE,E_DATE,MSG)
		conn = sqlite3.connect(db_path)
		cursor = conn.cursor()

		cursor.execute(query)
		conn.commit()
		conn.close()
		if cursor.lastrowid > 0:
			return True
		else:
			return False
	except Exception:
		logger.exception("insert_if_lastjob_completed")



#data = {"NAME":"test","CONF_FILE":"fff","STATUS":"running","S_DATE":"dddd","E_DATE":"dsdsd","MSG":"ok"}

#print(insert_if_lastjob_completed("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\db\\job_history.db",data))

#create_event_db("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\jobs\\12345\\event.db")
#create_history_db("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\db\\job_history.db")
#print(get_event_update_by_eid("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\jobs\\12345\\event.db"))
#print(get_last_job("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\db\\job_history.db"))

#print(get_all_events("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\jobs\\12345\\event.db"))