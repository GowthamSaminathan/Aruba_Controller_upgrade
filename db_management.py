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
	cmd = "ID INTEGER PRIMARY KEY AUTOINCREMENT,NAME TEXT NOT NULL,CONF_FILE NAME TEXT NOT NULL,STATUS TEXT NOT NULL,S_DATE TEXT,E_DATE TEXT,MSG TEXT NOT NULL,JOB_TYPE TEXT NOT NULL"
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

def async_create_event_db(db_path):
	conn = sqlite3.connect(db_path)
	cmd = "ID INTEGER PRIMARY KEY AUTOINCREMENT,NAME TEXT NOT NULL,E_DATE NAME TEXT NOT NULL,MSG TEXT NOT NULL,E_ID TEXT"
	try:
		conn.execute('''CREATE TABLE EVENTS({});'''.format(cmd))
		print("EVENT table created successfully")
		#return conn
		conn.close()
		return True
	except Exception:
		logger.exception("create_async_event_db")

def create_pre_post_db(db_path):
	conn = sqlite3.connect(db_path)
	cmd = "ID INTEGER PRIMARY KEY AUTOINCREMENT,host NAME TEXT NOT NULL,hostname NAME TEXT NOT NULL,"
	cmd = cmd + "device_type NAME TEXT NOT NULL,validation NAME TEXT,value NAME TEXT,status NAME TEXT,report_name NAME TEXT"

	try:
		conn.execute('''CREATE TABLE CHECKLIST({});'''.format(cmd))
		print("CHECKLIST table created successfully")
		#return conn
		conn.close()
		return True
	except Exception:
		logger.exception("create_event_db")

def checklist_update(db_path,all_data,report_name):
	try:
		conn = sqlite3.connect(db_path)
		cursor = conn.cursor()

		for data in all_data:

			host_type = data.get("device_type")
			hostname = data.get("hostname")
			host = data.get("host")
			validation = data.get("validation")
			status = data.get("status")
			value = data.get("value")
			#report_name = data.get("report_name")

			cmd = "INSERT INTO CHECKLIST (host,hostname,device_type,validation,value,status,report_name) VALUES ('{}','{}','{}','{}','{}','{}','{}')"
			cmd = cmd.format(host,hostname,host_type,validation,value,status,report_name)
			logger.info(cmd)
		
			cursor.execute(cmd)
		
		conn.commit()
		
		#print(cursor.rowcount)
		if cursor.rowcount == 1:
			conn.close()
			return True
		else:
			conn.close()
			return False
		
	except Exception:
		logger.exception("checklist_update")





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


def async_get_event_update_by_eid(db_path,e_id):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		#print("SELECT ID,NAME,E_DATE,MSG,E_ID FROM EVENTS WHERE E_ID='{}'".format(e_id))
		evnt = conn.execute("SELECT ID,NAME,E_DATE,MSG,E_ID FROM EVENTS WHERE E_ID='{}' ORDER BY ID DESC LIMIT 1".format(e_id))
		evnt = evnt.fetchall()
		conn.close()
		return evnt
	except Exception:
		logger.exception("async_get_event_update_by_eid")

def async_get_event_update_by_name(db_path,NAME):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		evnt = conn.execute("SELECT ID,NAME,E_DATE,MSG,E_ID FROM EVENTS WHERE NAME='{}'".format(NAME))
		evnt = evnt.fetchall()
		conn.close()
		return evnt
	except Exception:
		logger.exception("async_get_event_update_by_name")

def update_job_status_by_name(db_path,status,job_name,msg,e_date):
	try:
		conn = sqlite3.connect(db_path)
		cursor = conn.cursor()

		logger.info("UPDATE HISTORY set STATUS='{}',MSG='{}',E_DATE='{}' where NAME='{}'".format(status,msg,e_date,job_name))
		cursor.execute("UPDATE HISTORY set STATUS='{}',MSG='{}',E_DATE='{}' where NAME='{}'".format(status,msg,e_date,job_name))


		conn.commit()
		
		if cursor.rowcount == 1:
			conn.close()
			return True
		else:
			conn.close()
			return False
		
	except Exception:
		logger.exception("update_job_status_by_name")


def update_upgrade_status_by_device_host(db_path,host,status,msg):
	try:
		conn = sqlite3.connect(db_path)
		cursor = conn.cursor()
		cursor.execute("UPDATE JOBS set STATUS='{}', MSG='{}' where HOST='{}'".format(status,msg,host))

		conn.commit()
		
		if cursor.rowcount == 1:
			conn.close()
			return True
		else:
			conn.close()
			return False
		
	except Exception:
		logger.exception("update_upgrade_status_by_device_host")


def get_last_job(db_path):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		cursor = conn.cursor()
		cursor.execute("SELECT ID,NAME,CONF_FILE,STATUS,S_DATE,E_DATE,MSG,JOB_TYPE FROM HISTORY ORDER BY ID DESC LIMIT 1")
		result = cursor.fetchone()
		conn.close()
		return result
	except Exception:
		logger.exception("get_last_job")

def get_job_by_name(db_path,name):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		cursor = conn.cursor()
		cursor.execute("SELECT ID,NAME,CONF_FILE,STATUS,S_DATE,E_DATE,MSG,JOB_TYPE FROM HISTORY WHERE NAME='{}'".format(name))
		result = cursor.fetchone()
		conn.close()
		return result
	except Exception:
		logger.exception("get_job_by_name")


def get_all_jobs(db_path):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		cursor = conn.cursor()
		cursor.execute("SELECT ID,NAME,CONF_FILE,STATUS,S_DATE,E_DATE,MSG,JOB_TYPE FROM HISTORY ORDER BY ID DESC")
		result = cursor.fetchall()
		conn.close()
		return result
	except Exception:
		logger.exception("get_all_jobs")


def update_event_db(db_path,job_name,msg,e_id):
	try:
		conn = sqlite3.connect(db_path)
		cursor = conn.cursor()
		E_DATE = str(datetime.datetime.now()).split(".")[0]
		logger.info("INSERT INTO EVENTS (NAME,E_DATE,MSG,E_ID) VALUES ('{}','{}','{}','{}')".format(job_name,E_DATE,msg,e_id))
		cursor.execute('INSERT INTO EVENTS (NAME,E_DATE,MSG,E_ID) VALUES (?,?,?,?)',(job_name,E_DATE,msg,e_id))
		conn.commit()
		conn.close()

		if cursor.lastrowid > 0:
			return True
		else:
			return False
	except Exception:
		logger.exception("update_event_db")


def async_update_event_db(db_path,job_name,msg,e_id,update=False):
	try:
		conn = sqlite3.connect(db_path)
		cursor = conn.cursor()
		E_DATE = str(datetime.datetime.now()).split(".")[0]
		if update == False:
			logger.info("INSERT INTO EVENTS (NAME,E_DATE,MSG,E_ID) VALUES ('{}','{}','{}','{}')".format(job_name,E_DATE,msg,e_id))
			cursor.execute('INSERT INTO EVENTS (NAME,E_DATE,MSG,E_ID) VALUES (?,?,?,?)',(job_name,E_DATE,msg,e_id))
		else:
			logger.info("UPDATE EVENTS set MSG='{}' WHERE E_ID='{}' AND MSG LIKE '{}%' ".format(msg,e_id,"ASYNC_IN"))
			cursor.execute("UPDATE EVENTS set MSG='{}' WHERE E_ID='{}' AND MSG LIKE '{}%' ".format(msg,e_id,"ASYNC_IN"))
		
		conn.commit()
		conn.close()

		if cursor.lastrowid > 0:
			return True
		else:
			return False
	except Exception:
		logger.exception("async_update_event_db")

def insert_to_upgrade(db_path,job_name,conf_file,data):
	try:
		device_type = data.get("device_type")
		host = data.get("host")
		hostname = data.get("hostname")
		image_version = data.get("image_version")
		image_build = data.get("image_build")
		up_version = str(image_version)+" Build:"+str(image_build)

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

def async_get_all_events(db_path):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		cursor = conn.cursor()
		cursor.execute("SELECT ID,NAME,E_DATE,MSG,E_ID FROM EVENTS")
		result = cursor.fetchall()
		conn.close()
		return result
	except Exception:
		logger.exception("async_get_all_events")

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
		job = data.get("JOB_TYPE")

		query = "INSERT INTO HISTORY (NAME,CONF_FILE,STATUS,S_DATE,E_DATE,MSG,JOB_TYPE) SELECT '{}','{}','{}','{}','{}','{}','{}'".format(NAME,CONF_FILE,STATUS,S_DATE,E_DATE,MSG,job)
		query = query + " WHERE NOT EXISTS (SELECT * FROM HISTORY WHERE ID = (SELECT MAX(ID) FROM HISTORY) AND (STATUS='RUNNING' OR STATUS='STARTING'));"

		logger.info(query)

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


def get_checklist(db_path,report_name):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		evnt = conn.execute("SELECT device_type,hostname,host,validation,value,status,report_name FROM CHECKLIST WHERE report_name='{}'"
			.format(report_name))
		evnt = evnt.fetchall()
		conn.close()
		return evnt
	except Exception:
		logger.exception("get_checklist")

def get_checklist_by_val(db_path,qry):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		qry = "SELECT device_type,hostname,host,validation,value,status,report_name FROM CHECKLIST WHERE "+qry
		print(qry)
		evnt = conn.execute(qry)
		evnt = evnt.fetchall()
		conn.close()
		return evnt
	except Exception:
		logger.exception("get_checklist")


#data = {"NAME":"test","CONF_FILE":"fff","STATUS":"running","S_DATE":"dddd","E_DATE":"dsdsd","MSG":"ok"}

#print(insert_if_lastjob_completed("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\db\\job_history.db",data))

#create_event_db("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\jobs\\12345\\event.db")
#create_history_db("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\db\\job_history.db")
#print(get_event_update_by_eid("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\jobs\\1600176186_475276\\async_event.db","1600176289.7434554"))
#print(get_last_job("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\db\\job_history.db"))

#print(get_all_events("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\jobs\\12345\\event.db"))

#q = "report_name='Precheck' AND validation='running version' AND host='10.17.84.220:4343' "
#db_path = "D:\\scripts\\GIT\\Aruba_Controller_upgrade\\jobs\\1603888935_475258\\validation.db"
#o = get_checklist_by_val(db_path,q)
#print(o)




#create_pre_post_db("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\jobs\\1599965269_565146\\validation.db")
#data = {"device_type":"MM","host_name":"h1","host":"10.1.1.1","validation":"show clock","precheck":"12PM","precheck_remark":"remark 1","precheck_note":"note 1"}
#checklist_update("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\jobs\\1599965269_565146\\validation.db",data,"Precheck")
