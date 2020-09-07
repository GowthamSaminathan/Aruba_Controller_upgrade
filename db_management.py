import sqlite3
import datetime


def create_history_db(db_path):
	conn = sqlite3.connect(db_path)
	cmd = "ID INTEGER PRIMARY KEY AUTOINCREMENT,NAME TEXT NOT NULL,CONF_FILE NAME TEXT NOT NULL,STATUS TEXT NOT NULL,S_DATE TEXT,E_DATE TEXT,MSG TEXT NOT NULL"
	try:
		conn.execute('''CREATE TABLE HISTORY({});'''.format(cmd))
		print("HISTORY table created successfully")
		#print(conn)
		#return conn
		conn.close()
		return True
	except Exception as e:
		print("create_history_db: "+str(e))

def create_job_db(db_path):
	conn = sqlite3.connect(db_path)
	cmd = "NAME TEXT NOT NULL,DEVICE_TYPE NAME TEXT NOT NULL,HOST_NAME TEXT NOT NULL,HOST TEXT NOT NULL,"
	cmd = cmd+"UPGRADE_VERSION TEXT NOT NULL,STATUS TEXT NOT NULL,CONF_FILE TEXT NOT NULL,MSG TEXT NOT NULL,S_DATE TEXT,E_DATE TEXT"
	try:
		conn.execute('''CREATE TABLE JOBS({});'''.format(cmd))
		print("JOBS table created successfully")
		#return conn
		conn.close()
		return True
	except Exception as e:
		print("create_job_db: "+str(e))


def create_event_db(db_path):
	conn = sqlite3.connect(db_path)
	cmd = "NAME TEXT NOT NULL,E_DATE NAME TEXT NOT NULL,MSG TEXT NOT NULL,E_ID TEXT"
	try:
		conn.execute('''CREATE TABLE EVENTS({});'''.format(cmd))
		print("EVENT table created successfully")
		#return conn
		conn.close()
		return True
	except Exception as e:
		print("create_event_db: "+str(e))

def get_event_update_by_eid(db_path,e_id):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		evnt = conn.execute("SELECT NAME,E_DATE,MSG,E_ID FROM EVENTS WHERE E_ID='{}'".format(e_id))
		evnt = evnt.fetchall()
		conn.close()
		return evnt
	except Exception as e:
		print("get_event_update_by_eid: "+str(e))

def get_event_update_by_name(db_path,NAME):
	try:
		conn = sqlite3.connect(db_path)
		#E_DATE = str(datetime.datetime.now()).split(".")[0]
		evnt = conn.execute("SELECT NAME,E_DATE,MSG,E_ID FROM EVENTS WHERE NAME='{}'".format(NAME))
		evnt = evnt.fetchall()
		conn.close()
		return evnt
	except Exception as e:
		print("get_event_update_by_name: "+str(e))

def update_event_db(db_path,job_name,msg,e_id):
	try:
		conn = sqlite3.connect(db_path)
		E_DATE = str(datetime.datetime.now()).split(".")[0]
		conn.execute("INSERT INTO EVENTS (NAME,E_DATE,MSG,E_ID) VALUES ('{}','{}','{}','{}')".format(job_name,E_DATE,msg,e_id))
		conn.commit()
		conn.close()
		return True
	except Exception as e:
		print(e)


#create_event_db("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\jobs\\12345\\event.db")
#create_history_db("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\db\\job_history.db")
print(get_event_update_by_eid("D:\\scripts\\GIT\\Aruba_Controller_upgrade\\jobs\\12345\\event.db"))