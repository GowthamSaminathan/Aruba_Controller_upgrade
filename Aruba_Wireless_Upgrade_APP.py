# Aruba MM,Controller,AP upgrade with pre,post check

import os
import logging as clogging
from logging.handlers import RotatingFileHandler as cRotatingFileHandler
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
import sqlite3
import db_management
import config_file_generator
import time
import pprint


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.adapters.DEFAULT_RETRIES = 0



class Aruba_Wireless_upgrade():

	def __init__(self,conf):
		self.api_show_cmd = "https://{}/v1/configuration/showcommand?command={}&UIDARUBA={}"
		self.mm_image_upload = "https://{}/screens/wms/wms-os-upload.html"
		self.controller_save_reload = "https://{}/v1/configuration/object/reload_save_pending?UIDARUBA={}"
		self.ap_image_preload = "https://{}/v1/configuration/object/ap_image_preload?UIDARUBA={}"
		self.copy_flash_tftp = "https://{}/v1/configuration/object/copy_flash_tftp?UIDARUBA={}"
		self.backup_flash_local = "https://{}/v1/configuration/object/flash_backup?UIDARUBA={}"
		self.copy_tftp_system = "https://{}/v1/configuration/object/copy_tftp_system?UIDARUBA={}"
		self.copy_tftp_system_web = "https://{}/screens/cmnutil/ncftp.html"

		self.login_sessions = dict()
		self.final_status = conf.final_status
		self.user_pause_terminate = conf.user_pause_terminate
		self.upgrade_db = conf.upgrade_db
		self.event_db = conf.event_db
		self.async_event_db = conf.async_event_db
		self.validation_db = conf.validation_db
		self.job_path = conf.job_path
		self.gen_config = conf.gen_config
		self.job_history_db = conf.job_history_db
		self.job_name = conf.job_name
		self.logger = conf.logger
		self.get_user_input = conf.get_user_input
		self.get_user_input_async = conf.get_user_input_async
		self.eprint = conf.eprint
		self.local_aos_file_path = os.path.join(os.getcwd(),"aos")

		self.print = pprint.PrettyPrinter(indent=4)

	def get_session(self,single_host,new_session=False):
		try:
			self.user_pause_terminate()
			try:
				# Try to use previous session
				host_ip = single_host.get("host")
				if new_session == False:
					session = self.login_sessions.get(host_ip)
					if session == None:
						# Session not there for host_ip
						pass;
					else:
						# Session already present
						# Validating session live status
						if session[0] == True:
							r_session = session[1]
							UIDARUBA = session[2]
							get_clock = self.api_show_cmd.format(host_ip,"show clock",UIDARUBA)
							res = r_session.get(get_clock,verify=False)
							if res.status_code == 200:
								# Session valid
								self.eprint("info","Session Valid : {}".format(host_ip))
								return True,r_session,UIDARUBA
			except Exception:
				self.logger.exception("get_session:")

			login_url = "https://{}/v1/api/login".format(host_ip)

			auth = single_host.get("Authentication")
			username = auth.get("username")
			password = auth.get("password")

			login_post = {"username":username ,"password": password}
			#print(_info+" "*120+"=> Trying Login => {}".format(host_ip))

			r_session = requests.Session()
			res = r_session.post(login_url, data = login_post,verify=False)
			res = res.json()
			login_status = res.get("_global_result").get("status")
			login_msg = res.get("_global_result").get("status_str")
			UIDARUBA = res.get("_global_result").get("UIDARUBA")
			
			if login_status == "0":
				self.eprint("info","Login Success => {}".format(host_ip))
			else:
				self.eprint("error","Login Failed : {} => {}".format(host_ip,login_msg))
				return False,login_status


			self.login_sessions.update({host_ip:[True,r_session,UIDARUBA]})
			return True,r_session,UIDARUBA
		
		except requests.exceptions.ConnectTimeout:
			self.eprint("error","Login request timeout : {}".format(host_ip))
			self.logger.exception("Login request timeout : ".format(str(host_ip)))
			return None,None

		except Exception:
			self.eprint("error","Login error : {}".format(host_ip))
			self.logger.exception("Login error:{} ".format(str(host_ip)))
			return None,None

	def logout(self,session,host_ip):
		try:
			#print("Trying logout => {}".format(host_ip))
			url = "https://{}".format(host_ip)
			url = urljoin(url,"v1/api/logout")
			res = session.get(url,verify=False)
			#print(res.content)
		except Exception:
			self.logger.exception("Logout error:".format(str(host_ip)))

	def validating_pre_check(self,single_host,host_output):
		# 1) Validate current image version
		# 2) Validate the current disk image
		
		try:

			new_image = single_host.get("image_file_name")
			new_disk = single_host.get("disk")
			upload_type = single_host.get("upload_type")
			device_type = single_host.get("type")
			hostname = single_host.get("hostname")
			host_ip = single_host.get("host")
			summary = dict()
			summary.update({"Host":hostname+":"+host_ip,"Type":device_type})


			
			if host_output.get("show switchinfo") != None:
				try:
					result = host_output.get("show switchinfo")
					out = result.get("_data")[0]
					re_table = textfsm.TextFSM(open(os.path.join(os.getcwd(),"text_fsm","show_switchinfo.txt")))
					fsm_results = re_table.ParseTextToDicts(out)
					for res in fsm_results[0].items():
						#xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":res[0],"VALUE":res[1]})
						summary.update({res[0]:res[1]})
				except Exception:
					self.logger.exception("validating_pre_check : show switchinfo")

			if host_output.get("show image version") != None:
				try:
					result = host_output.get("show image version")
					out = result.get("_data")[0]
					part_1 = re.findall(r'Partition.*',out)[0]
					re.findall(r'Partition.*',part_1)[0]

					part_1 = re.findall(r'Partition.*',out)[0]
					v1 = re.findall(r'Software Version.*',out)[0].split("ArubaOS")[1]
					build_1 = re.findall(r'Build number.*',out)[0]
					#xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":part_1,"VALUE":v1})
					#xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"BUILD","VALUE":build_1})

					part_2 = re.findall(r'Partition.*',out)[1]
					v2 = re.findall(r'Software Version.*',out)[1].split("ArubaOS")[1]
					build_2 = re.findall(r'Build number.*',out)[1]
					#xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":part_2,"VALUE":v2})
					#xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"BUILD","VALUE":build_2})

				except Exception:
					self.logger.exception("validating_pre_check : show image version")

			if host_output.get("show storage") != None:
				try:
					result = host_output.get("show storage")
					out = result.get("_data")[0]
					all_disk = ""
					for t in re.findall(r'/.*%',out):
						used_disk = t.split(" ")[-1]
						#xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"Disk usage","VALUE":used_disk})
						all_disk = all_disk + used_disk

					summary.update({"used_disk":all_disk})
				except Exception:
					self.logger.exception("validating_pre_check : show storage")

			if host_output.get("show cpuload") != None:
				try:
					result = host_output.get("show cpuload")
					out = result.get("_data")[0]
					o = re.findall(r'idle.*',out)[0]
					#xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"Free CPU","VALUE":o})
					summary.update({"free_cpu":o})
				except Exception:
					self.logger.exception("validating_pre_check : show cpuload")

			if host_output.get("show memory") != None:
				try:
					result = host_output.get("show memory")
					out = result.get("_data")[0]
					o = re.findall(r'free.*',out)[0]
					#xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"Free Memory","VALUE":o})
					summary.update({"free_memory":o})
				except Exception:
					self.logger.exception("validating_pre_check : show memory")

			for cm in ["show master-l3redundancy","show master-redundancy"]:
				try:
					result = host_output.get(cm)
					out = result.get("_data")[0]
					o = re.findall("current state is.*",out)
					if len(out) > 0:
						pass;
						#xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"Redundancy","VALUE":o[0]})
				except Exception:
					pass;
					#logger.exception("validating_pre_check : redundancy")


			if upload_type == "local":
				if os.path.isfile(os.path.join(os.getcwd(),new_image)) == False:
					self.eprint("warning","Failed => Image file {} not present for {}".format(new_image,single_host.get("hostname")))
			#_new_image = ""
			#new_image = re.findall(r'\d+', new_image)
			#for i in new_image:
			#	_new_image = _new_image + str(i)

			#Validate the current disk image
			running_disk = host_output.get("show boot")
			running_disk = str(running_disk).split("PARTITION ")[1]
			running_disk = int(running_disk[0])

			return summary

			#print(_info+yaml.dump(summary, default_flow_style=False))
			#if int(new_disk) == running_disk:
			#	print(" ** Failed => Running Disk ({}) Upgrade Disk ({}) are same".format(running_disk,new_disk))
		except Exception:
			self.eprint("error","Validation failed for: "+str(hostname))
			self.logger.exception("validating_pre_check")

	def find_alternative_partition(self):
		self.user_pause_terminate()
		hosts = self.gen_config.get("Upgrade")
		for single_host in hosts:
			try:

				self.user_pause_terminate()
				host_type = single_host.get("device_type")
				host_name = single_host.get("hostname")
				host_ip = single_host.get("host")
				upgrade_disk =  single_host.get("upgrade_disk")

				db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"RUNNING","Finding alternative partition")

				disk = None

				if upgrade_disk != "Auto":
					self.eprint("info","Installation Disk {} provided by user for host {} , Skiping auto detect".format(upgrade_disk,host_ip))
					single_host.update({"disk":upgrade_disk})
					continue
				else:
					self.eprint("info","Installation Disk {} not provided for {} , Trying to auto detect".format(upgrade_disk,host_ip))

					self.user_pause_terminate()
					cmd_out = self.execute_cmd(single_host,["show boot"])
					
					
					out = cmd_out.get("show boot")
					out = out.get("_data")[0]
					out = re.findall(r'PARTITION\s*.*',out)[0][-1]
					out = int(out)
					if out == 1:
						disk = 0
					elif out == 0:
						disk = 1

					if disk != None:
						single_host.update({"disk":disk})
						_status = "COMPLETED"
					else:
						_status = "FAILED"

					self.eprint("info","{}-{} :Auto detect alternative partition: {}".format(host_name,host_ip,disk))
			
			except Exception:
				_status = "FAILED"
				db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,_status,"Auto detect alternative disk")
				self.eprint("error","{}-{} : Auto detect alternative partition failed".format(host_name,host_ip))
				self.logger.exception("Auto detect alternative partition failed")

			finally:
				data = {"device_type":host_type,"host_name":host_name,"host":host_ip,"validation":"Alternative Disk","precheck":str(disk),"precheck_remark":_status,"precheck_note":_status}
				db_management.checklist_update(self.validation_db,data,"Precheck")
				db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,_status,"Auto detected alternative disk {}".format(disk))

				self.user_pause_terminate()





	def Pre_Post_check(self,check_type):
		try:
			# Add all the errors in this list
			#pre_status = []
			c_date = str(datetime.datetime.now().strftime('%b_%d_%H_%M_%S'))

			self.eprint("info","Executing "+check_type)
			hosts = self.gen_config.get("Upgrade")
			summary_data = []

			self.user_pause_terminate()
			
			if check_type == "Precheck":
				# Precheck - Only for precheck
				_pre_status = self.find_alternative_partition()
				#pre_status.append(_pre_status)

			
			#_pre_status = self.phase_one_check()
			#pre_status.append(_pre_status)


			# Phase 2 Precheck
			for single_host in hosts:
				try:
					self.user_pause_terminate()
					_status = None
					host = single_host.get("host")
					db_management.update_upgrade_status_by_device_host(self.upgrade_db,host,"RUNNING PRECHECK",check_type)
					hostname = single_host.get("hostname")
					device_type = single_host.get("device_type").strip()
					cmds = single_host.get("CheckList")
					self.eprint("info",check_type+" started for : ({}) {}:{}".format(device_type,hostname,host))
					_host = host.split(":")[0]
					log_file = open(os.path.join(self.job_path,check_type,_host+".txt"),"w")
					#pyobj_file = open(os.path.join(log_file_path,check_type,_host+".pyobj"),"wb")
					
					session = None
					login_status = self.get_session(single_host)

					if login_status[0] == True:
						session = login_status[1]
						UIDARUBA = login_status[2]
						host_output = dict()
						_len_cmds = str(len(cmds))
						db_management.update_upgrade_status_by_device_host(self.upgrade_db,host,"RUNNING PRECHECK","Completed 0/"+_len_cmds)
						for _count,cmd in enumerate(cmds):
							self.user_pause_terminate()
							db_management.update_upgrade_status_by_device_host(self.upgrade_db,host,"RUNNING PRECHECK","Status "+str(_count+1)+"/"+_len_cmds)
							if cmd.get("show") != None:
								cmd = cmd.get("show")
								cmd = cmd.lower().strip()
								self.eprint("info","Executing {} - {} => {}".format(hostname,host,cmd))
								req_url = self.api_show_cmd.format(host,cmd,UIDARUBA)
								res = session.get(req_url,verify=False)
								#print(res.headers.get("content-type"))

								if len(res.text) < 1:
									# Aruba API JSON Bug (empty string)
									res_json = {}
								else:
									res_json = res.json()
								
								
								host_output.update({cmd:res_json})
								out = self.print.pformat(res_json)
								log_file.write("\n\n"+"==="*20+">")
								log_file.write(cmd+"\n")
								log_file.write(out)

							elif cmd.get("copy_flash_tftp") != None:
								cp = cmd.get("copy_flash_tftp")
								cp = re.split("\s+",cp)
								dst_file = host.replace(".","_")
								dst_file = host.replace(":","_")
								self.file_copy_flash_tftp(host,cp[0],cp[1],dst_file+"_"+cp[2])

							elif cmd.get("backup_flash") != None:

								dst_file_name = cmd.get("backup_flash").strip()
								self.backup_flash_to_disk(host,session,UIDARUBA,dst_file_name)
							
							else:
								self.eprint("warning","Not Implemented for: "+str(cmd))
						
						
						s_data = self.validating_pre_check(single_host,host_output)
						summary_data.append(s_data)
						
					else:
						_status = "LOGIN FAILED"
						self.eprint("error","Precheck failed for => {}:{}".format(hostname,host))
				except Exception:
					_status = "FAILED"
					self.eprint("error","Precheck failed for => {}:{}".format(hostname,host))
					self.logger.exception("Error host pre_post_check")
				finally:
					if _status == None:
						_status = "COMPLETED"
					db_management.update_upgrade_status_by_device_host(self.upgrade_db,host,_status,check_type)
					self.user_pause_terminate()

					#self.logout(session,host)

		except Exception:
			self.eprint("error","Check execution error")
			self.logger.exception("Pre_Post_check")
		finally:
			self.eprint("info",check_type+" Completed")

	def validate_image_upload(self,single_host):
		try:
			self.user_pause_terminate()
			host_ip = single_host.get("host")
			host_name = single_host.get("hostname")
			host_type = single_host.get("device_type")
			version = single_host.get("image_version")
			disk = single_host.get("disk")
			build = single_host.get("image_build")


			out = self.execute_cmd(single_host,["show image version"])
			valid_image = False
			
			if out != None:
				_data = out.get("show image version")
				_data = _data.get("_data")
				part = _data[0].split("\n")
				
				first_partition = part[1]
				first_partition = first_partition.split(" : ")[1].split(" ")[0].split(":")[1]
				first_version = part[2]
				first_build = part[3].split(" : ")[1].split(" ")[0]

				second_partition = part[7]
				second_partition = second_partition.split(" : ")[1].split(" ")[0].split(":")[1]
				second_version = part[8]
				second_build = part[9].split(" : ")[1].split(" ")[0]

				if int(disk) == int(first_partition):
					if first_version.find(str(version)) != -1:
						if str(first_build) == str(build):
							valid_image =  True

				if int(disk) == int(second_partition):
					if second_version.find(str(version)) != -1:
						if str(second_build) == str(build):
							valid_image = True

				if valid_image == True:
					self.eprint("success","New Image Installed for ({}) Host:{}:{} Disk:{} Version:{} Build:{}"
						.format(host_type,host_name,host_ip,disk,version,build))
					return True
				else:
					self.eprint("warning","Required image version for ({}) Host:{}:{} = Disk:{} Version:{} Build:{}"
						.format(host_type,host_name,host_ip,disk,version,build))
					return False
				

			else:
				return None
		except Exception:
			self.logger.exception("validate_image_upload")

	def execute_cmd(self,single_host,cmds):
		try:
			self.user_pause_terminate()
			out_cmd = {}
			host_ip = single_host.get("host")
			login_status = self.get_session(single_host)
			print(login_status)
			if login_status[0] == True:
				session = login_status[1]
				UIDARUBA = login_status[2]
				for cmd in cmds:
					#print(cmd)
					req_url = self.api_show_cmd.format(host_ip,cmd,UIDARUBA)
					res = session.get(req_url,verify=False)
					#print(res.headers.get("content-type"))
					if len(res.text) < 1:
						# Aruba API JSON Bug (empty string)
						res_json = {}
						out_cmd.update({cmd:res_json})
					else:
						res_json = res.json()
						out_cmd.update({cmd:res_json})

				#self.logout(session,host_ip)
				return out_cmd
		except Exception:
			self.logger.exception("get_image_details: ")

	def upload_image_http(self,single_host):
		try:
			self.user_pause_terminate()
			login_status = self.get_session(single_host)

			headers = {}
			img_file = single_host.get("image_file_name")
			host_ip = single_host.get("host")
			upgrade_disk = single_host.get("disk")

			if login_status[0] == True:
				session = login_status[1]
				UIDARUBA = login_status[2]
				file_path = os.path.join(self.local_aos_file_path,img_file)
				file_data = open(file_path,'rb')
				
				data = {'.osimage_handle': (img_file,file_data,"application/octet-stream")}
				data.update({"fpartition":str(disk),"UIDARUBA":UIDARUBA})
				url = self.mm_image_upload.format(host_ip)
				#print(url)
				#print(UIDARUBA)
				mp = MultipartEncoder(fields=data)
				headers.update({'Content-Type': mp.content_type})
				
				#prepared = requests.Request('POST', url,data=mp,headers=headers).prepare()
				
				self.eprint("info","Uploading image file: {} AOS: {}".format(host_ip,img_file))
				#print(prepared.headers)
				#print(session.cookies.get_dict())
				
				#url = "https://10.17.84.221:4343/v1/configuration/showcommand?command=show%20version&UIDARUBA="+UIDARUBA
				#prepared = requests.Request('GET', url).prepare()
				
				res = session.post(url,data=mp,headers=headers,verify=False)
				#print(res.content)
				db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"COMPLETED: UPLOADED IMAGE TO DISK {}".format(disk),"Image:"+str(img_file))
				self.eprint("success","Completed Upload image file to: {} AOS: {}".format(host_ip,img_file))
				
				#self.logout(session,host_ip)
		except Exception:
			self.logger.exception("upload_image_http: ")

	def upload_image_from_server(self,single_host,aos_source,server_type):
		# Copy file using TFTP , webUI API method
		try:
			self.user_pause_terminate()
			login_status = self.get_session(single_host)
			host_ip = single_host.get("host")
			host_name = single_host.get("hostname")
			disk = single_host.get("disk")
			img_file = single_host.get("image_file_name")


			db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"RUNNING: UPLOADING IMAGE TO DISK {}".format(disk),"Image:"+str(img_file))
			
			if login_status[0] == True:
				session = login_status[1]
				UIDARUBA = login_status[2]
				partition = "partition"+str(disk)

				if server_type == "ftp":
					username = aos_source.get("ftp_username")
					password = aos_source.get("ftp_password")
					server_ip = aos_source.get("ftp_host")
				elif server_type == "scp":
					username = aos_source.get("scp_username")
					password = aos_source.get("scp_password")
					server_ip = aos_source.get("scp_host")
				else:
					server_type = "tftp"
					server_ip = aos_source.get("tftp_host")
					username = "zz"
					password = "zz"

				
				web_data = {'method': 'im'+server_type,'args':server_type+','+server_ip+','+username+','+password+','+img_file+','+partition.upper()+',unknown_host,none'}
				web_data.update({'UIDARUBA': UIDARUBA})

				#print(web_data)

				self.eprint("info","{}:{}- Installing AOS: {} from {} server:{}".format(host_name,host_ip,img_file,server_type,server_ip))
				url = self.copy_tftp_system_web.format(host_ip)
				res = session.post(url,data=web_data,verify=False)
				
				try:
					response = res.json()
				except:
					response = res.content

				self.eprint("debug",str(response))

				if str(response).find("SUCCESS") != -1:
					db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"COMPLETED: UPLOADED IMAGE TO DISK {}".format(disk),"Image:"+str(img_file))
					self.eprint("info","File copy completed "+str("COMPLETED: UPLOADED IMAGE TO DISK {} {}".format(disk,img_file)))
					self.logger.info(response)
					return True
				else:
					db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"FAILED: UPLOADING IMAGE TO DISK {}".format(disk),"Image:"+str(img_file))
					self.eprint("warning","File copy completed "+str("Failed: UPLOADED IMAGE TO DISK {} {}".format(disk,img_file)))
					self.logger.error(response)
			else:
				db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"FAILED: UPLOADING IMAGE","Login failed")


		except Exception:
			self.logger.exception("upload_image_from_server")

	def MM_MD_Upload(self,single_host):
		upload_not_required = False
		img_file = single_host.get("image_file_name")
		host_ip = single_host.get("host")
		hostname = single_host.get("hostname")
		upgrade_disk = single_host.get("disk")
		aos_source = single_host.get("AOS_Source")
		
		upload_type = aos_source.get("device_type")
		
		image_build = single_host.get("image_build")
		image_version = single_host.get("image_version")
		host_type = single_host.get("type")

		msg = "Do you want to install: "
		self.user_pause_terminate()
		if self.get_user_input("{}Image Version:{}-{} on Disk:{} Host:{}:{}".format(msg,image_version,image_build,upgrade_disk,hostname,host_ip),["yes","no"]) == "no":
			db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"FAILED: UPLOADING IMAGE","User Aborted")
		else:
			db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"RUNNING: VALIDADING PRESENT IMAGE","")
			a = "{}Image Version:{}-{} on Disk:{} Host:{}:{}".format(msg,image_version,image_build,upgrade_disk,hostname,host_ip)
			self.eprint("warning","User aborted to install : "+a)
			
		upload_not_required = False
		while upload_not_required == False:
			self.user_pause_terminate()
			if self.validate_image_upload(single_host) != True:

				#print("=> Starting MM Upgrade for {}".format(host_ip))
				a = "{}Image Version:{}-{} on Disk:{} Host:{}:{}".format(msg,image_version,image_build,upgrade_disk,hostname,host_ip)
				self.eprint("info","User accepted : "+a)
				if upload_type == "local":
					upload_status = self.upload_image_http(single_host,aos_source)
				elif upload_type == "tftp":
					upload_status = self.upload_image_from_server(single_host,aos_source,"tftp")
				elif upload_type == "ftp":
					upload_status = self.upload_image_from_server(single_host,aos_source,"ftp")
				elif upload_type == "scp":
					upload_status = self.upload_image_from_server(single_host,aos_source,"scp")
				else:
					self.eprint("error","No valid file upload type found"+str(upload_type))
				
				if upload_status == True:
					db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"COMPLETED: NEW IMAGE PRESENT","{} Build:{} in Disk:{}"
						.format(image_version,image_build,upgrade_disk))
					upload_not_required = True
				else:
					self.user_pause_terminate()
					msg = "Retry Image Upload, "
					if self.get_user_input("{}Image Version:{}-{} on Disk:{} Host:{}:{}".format(msg,image_version,image_build,upgrade_disk,hostname,host_ip),["yes","no"]) == "no":
						self.eprint("warning","User aborted for retry image upload")
						upload_not_required = True

			else:
				db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"COMPLETED: NEW IMAGE PRESENT","{} Build:{} in Disk:{}"
					.format(image_version,image_build,upgrade_disk))
				upload_not_required = True


	def AP_IMAGE_PRELOAD(self,single_host):
		try:
			self.user_pause_terminate()
			global last_skip
			upload_not_required = False
			img_file = single_host.get("image_file_name")
			host_ip = single_host.get("host")
			host_name = single_host.get("hostname")
			upgrade_disk = single_host.get("disk")
			image_build = single_host.get("image_build")
			image_version = single_host.get("image_version")
			max_ap_image_load = single_host.get("max_ap_image_load")

			msg = "Do You want to preimage AP's for :"
			if self.get_user_input("{} {} - {} from Disk {}".format(msg,host_name,host_ip,upgrade_disk),["yes","no"]) == "no":
				self.eprint("warning","Skipping AP's preimage....")
				return False
			
			self.eprint("info","STARTING AP IMAGE PRELOAD FOR {}-{} FROM DISK:{} MAX AP:{}".format
				(host_name,host_ip,upgrade_disk,max_ap_image_load))

			db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"PENDING","AP Pre-Imaging")
			
			# Execute the pre-image command
			valid_state = False
			eid = str(time.time())
			self.get_user_input_async("Press yes to skip",eid,get=None)
			while valid_state == False:
				try:
					self.user_pause_terminate()
					self.get_user_input_async("Press yes to skip",eid,get=True)
					db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"PENDING","AP Pre-Imaging request")
					upload_not_required = True
					login_status = self.get_session(single_host)
					if login_status[0] == True:
						session = login_status[1]
						UIDARUBA = login_status[2]
						url = self.ap_image_preload.format(host_ip,UIDARUBA)
						data = {"ap_info":"all-aps","partition":int(upgrade_disk),"max-downloads":int(max_ap_image_load)}
						res = session.post(url,json=data,verify=False)
						try:
							response = res.json()
						except:
							response = res.content

						if type(response) != dict:
							raise TypeError("Response is not JSON")
						else:
							response = response.get("ap_image_preload")
							if response != None:
								if response.get("_result").get("status") == 0:
									p = response.get("_result").get("status_str")
									db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"COMPLETED","AP Pre-Imaging request success")
									self.eprint("success","AP Pre-load Executed:{}-{} => {}".format(host_name,host_ip,p))
									valid_state = True
									#self.logout(session,host_ip)
								else:
									p = response.get("_result").get("status_str")
									db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"FAILED","AP Pre-Imaging")
									self.eprint("error","AP Pre-load Failed:{}-{} => {}".format(host_name,host_ip,p))
							else:
								raise TypeError("Response not having 'ap_image_preload' field")
				except TypeError:
					#self.logout(session,host_ip)
					db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"FAILED","AP Pre-Imaging response failed")
					self.eprint("error","AP image response failed")
					self.logger.exception("AP_IMAGE_PRELOAD:")

				except Exception:
					#self.logout(session,host_ip)
					db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"FAILED","AP Pre-Imaging response failed")
					self.eprint("error","AP image Failed")
					self.logger.exception("AP_IMAGE_PRELOAD POST: ")
				finally:
					#Sleep for some time before retry
					#self.eprint("debug","Retry in 3 - AP Pre-Imaging")
					time.sleep(3)


			# Validate the pre-load
			valid_state = False
			eid = str(time.time())
			self.get_user_input_async("Press yes to skip",eid,get=None)
			while valid_state == False:
				try:
					self.user_pause_terminate()
					self.get_user_input_async("Press yes to skip",eid,get=True)
					#self.get_user_input("{}Image Version:{}-{} on Disk:{} Host:{}:{}".format(msg,image_version,image_build,upgrade_disk,hostname,host_ip),["yes","no"])
					db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"RUNNING","AP Pre-Imaging Validation")
					res = self.execute_cmd(single_host,["show ap image-preload status summary","show ap image-preload status list"])
					if res != None:
						try:
							out = res.get("show ap image-preload status list")
							itm = out.get("AP Image Preload AP Status")
							#self.print.pprint(itm)
						except:
							pass;
							#print(out)

						try:
							self.eprint("info","Validating AP Preload status for:{} - {}".format(host_name,host_ip))
							out = res.get("show ap image-preload status summary")
							itm = out.get("AP Image Preload AP Status Summary")
							#self.print.pprint(itm)
							#*** Need to print preload status
							#print(_info+yaml.dump(itm, default_flow_style=False))
						except Exception:
							self.logger.exception("Validating AP Preload status: ")
					else:
						db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"FAILED","AP Pre-Imaging Validation")
						self.eprint("error","AP Preload status check failed:{}-{}".format(host_name,host_ip))
				except Exception:
					self.eprint("error","AP Pre-Imaging Validation")
					self.logger.exception("AP_IMAGE_PRELOAD POST: ")
				finally:
					# Sleep for some time before retry
					self.eprint("info","Retry in 3 - AP Pre-Image validation")
					time.sleep(3)



		except Exception:
			self.logger.exception("AP_IMAGE_PRELOAD: ")


	def Upload_Images(self):
		try:
			#Read upgrade host details from configuration
			upgrade_hosts = self.gen_config.get("Upgrade")
			self.eprint("info","Total upgrade hosts:{}".format(len(upgrade_hosts)))

			# Uploading Images to MM and MD
			for host in upgrade_hosts:
				host_name = host.get("hostname")
				host_ip = host.get("host")
				upgrade_disk = host.get("disk")
				image_build = host.get("image_build")
				image_version = host.get("image_version")
				upload_device_type = host.get("device_type")

				#db_management.update_upgrade_status_by_device_host(self.upgrade_db,host_ip,"RUNNING: UPLOADING IMAGE","From:"+str(upload_device_type).upper())

				if host.get("device_type") == "MM":
					# Start the MM Upgrade
					self.eprint("info","MM: Preparing for host {} IP: {}".format(host_name,host_ip))
					#self.validate_image_upload(host_ip,disk,image_version,image_build)
					self.MM_MD_Upload(host)
					#self.validate_running_image(host_ip,image_version,image_build)
					
				elif host.get("device_type") == "MD":
					self.eprint("info","MD: Preparing for host {} IP: {}".format(host_name,host_ip))
					self.MM_MD_Upload(host)
				else:
					self.eprint("error","Upgrade type invalid ({})".format(host.get("type")))

			#Pre-Uploading images to AP
			for host in upgrade_hosts:
				host_name = host.get("hostname")
				host_ip = host.get("host")
				upgrade_disk = host.get("disk")
				image_build = host.get("image_build")
				image_version = host.get("image_version")

				if host.get("device_type") == "MD" :
					# Pre-Upload images to this MD
					self.AP_IMAGE_PRELOAD(host)

		except Exception:
			self.eprint("error","Upload Image Error For : {} - {}".format(host_name,host_ip))
			self.logger.exception("Upgrade Error: ")



class main_model():

	def __init__(self):
		pass;
		#Saving ssh session
		#logger.info("Starting main model")

	def start_upgrade(self):
		pass;

	def eprint(self,print_level,msg):

		msg = print_level.upper()+":"+str(msg)
		if print_level == "warning":
			self.logger.warning(msg)
			db_management.update_event_db(self.event_db,self.job_name,msg,None)
		if print_level == "error":
			self.logger.error(msg)
			db_management.update_event_db(self.event_db,self.job_name,msg,None)
		if print_level == "info":
			self.logger.info(msg)
			db_management.update_event_db(self.event_db,self.job_name,msg,None)
		else:
			self.logger.debug(msg)
			db_management.update_event_db(self.event_db,self.job_name,msg,None)	
	
	def user_pause_terminate(self):
		# Check user send terminate or pause
		try:
			job_status = db_management.get_job_by_name(self.job_history_db,self.job_name)
			if type(job_status) == tuple:
				if job_status[3] == "TERMINATED":
					self.eprint("warning","Job Terminated by user")
					self.final_status = ["TERMINATED","Terminated by user"]
					self.finish_upgrade("TERMINATED","Terminated by user")
					exit(0)
				elif job_status[3] == "PAUSED":
					self.eprint("warning","Job Paused by user")
					pause = True
					while pause == True:
						time.sleep(2)
						job_status = db_management.get_job_by_name(self.job_history_db,self.job_name)
						if job_status[3] == "PAUSED":
							pass;
						elif job_status[3] == "TERMINATED":
							self.eprint("warning","Job Terminated by user")
							self.final_status = ["TERMINATED","Terminated by user"]
							self.finish_upgrade("TERMINATED","Terminated by user")
							exit(0)
						else:
							pause = False

			else:
				self.eprint("warning","user_pause_terminate (Bug), Job not in DB , Job name:"+str(self.job_name))

		except Exception:
			self.logger.exception("user_pause_terminate")



	def get_user_input(self,msg,expected=None):
		# Ask User conformation using event DB
		try:
			msg = "IN:"+msg
			while True:
				e_id = str(time.time())
				db_management.update_event_db(self.event_db,self.job_name,msg,e_id)
				while True:
					user_input = db_management.get_event_update_by_eid(self.event_db,e_id)
					if type(user_input) == list:
						if len(user_input) > 1:
							user_conformation = user_input[1]
							user_input = user_conformation[3]
							if expected == None:
								return user_input
							elif user_input in expected:
								return user_input
							else:
								self.eprint("error","User Input not stasfied: "+str(expected)+"Expected , Provided Input:"+str(user_input))
								break
					time.sleep(2)
		except Exception:
			self.logger.error("get_user_input")

	def get_user_input_async(self,msg,e_id,get):
		# Ask User conformation using event DB
		try:
			msg = "ASYNC_IN:"+msg
			if get == None:
				db_management.async_update_event_db(self.async_event_db,self.job_name,msg,e_id)
			else:
				user_input = db_management.async_get_event_update_by_eid(self.event_db,e_id)
				if type(user_input) == list:
					if len(user_input) > 1:
						user_conformation = user_input[1]
						user_input = user_conformation[3]
						return user_input
				else:
					return None
		except Exception:
			self.logger.error("get_user_input_async")


	def insert_hosts_details_to_db(self):
		try:

			self.logger.info("Inserting upgrade list to upgrade.db")
			upgrade = self.gen_config.get("Upgrade")

			for host in upgrade:
				db_management.insert_to_upgrade(self.upgrade_db,self.job_name,self.config_file_name,host)

		except Exception:
			self.logger.exception("insert_hosts_details_to_db")


	def validate_configuration(self):
		try:
			try:
				yaml_config_file = open(self.config_file).read()
			except Exception:
				self.eprint("error","Opening config file failed")
				self.logger.exception("Opening Config file failed:"+str(self.config_file))
				return False

			try:
				open(os.path.join(self.job_path,"configuration.yaml"),"w").write(yaml_config_file)
			except Exception:
				self.logger.exception("Writing configuration.yaml failed")


			config = config_file_generator.validate_create_yaml(yaml_config_file,self.logger)
			if type(config) == dict:
					if config.get("status") == "success":
						self.gen_config = config.get("config_json")
						self.insert_hosts_details_to_db()
						try:
							open(os.path.join(self.job_path,"gen_configuration.yaml"),"w").write(config.get("config_yaml"))
						except Exception:
							self.logger.exception("Writing gen_config.yaml failed")

						return True
					else:
						self.eprint("error","validate_configuration failed")
						return False

			else:
				self.eprint("error","validate_configuration not dict")
				return False


		except Exception:
			self.logger.exception("validate_configuration")


	def init_upgrade(self):
		try:
			# Update the DB
			job_db_status = db_management.create_job_db(self.upgrade_db)
			event_db_status = db_management.create_event_db(self.event_db)
			async_create_event_db = db_management.async_create_event_db(self.async_event_db)
			validation_db_status = db_management.create_pre_post_db(self.validation_db)

			if job_db_status == True and event_db_status == True and validation_db_status == True:

				self.logger.info("Starting Job")
				E_DATE = str(datetime.datetime.now()).split(".")[0]
				status = db_management.update_job_status_by_name(self.job_history_db,"RUNNING",self.job_name,"",E_DATE)
				if status == False:
					self.eprint("warning","Running status not updated in DB (Bug)")
				
				
				if status == True:
					self.eprint("info","Running: "+str(self.job_name)+" Type:"+str(",".join(self.job_list)))
					return True
				else:
					self.eprint("error","Terminating Job , DB update failed...")
					return False
				
			else:
				self.eprint("error","DB Creation failed (Terminating)")
				return None

		except Exception:
			self.logger.exception("init_upgrade")

	def finish_upgrade(self,status,msg):
		try:
			E_DATE = str(datetime.datetime.now()).split(".")[0]
			db_management.update_job_status_by_name(self.job_history_db,status,self.job_name,msg,E_DATE)
			self.eprint("info","==== Completed ====")
		except Exception:
			self.logger.exception("finish_upgrade")


	def main_run(self,job_name,config_file,job_list):
		try:
			self.final_status = ["COMPLETED",""]
			self.job_name = str(job_name)
			self.config_file_name = config_file
			self.config_file = os.path.join(os.getcwd(),"conf_files",config_file)
			self.job_list = job_list

			job_path = os.path.join(os.getcwd(),"jobs",self.job_name)
			self.job_path = job_path

			if not os.path.exists(job_path):
				os.makedirs(job_path)
				os.makedirs(os.path.join(job_path,"Precheck"))
				os.makedirs(os.path.join(job_path,"Postcheck"))
				os.makedirs(os.path.join(job_path,"Upgrade"))
			else:
				print("Job Path already exist (terminating job): "+str(job_path))
				return None

			log_path = os.path.join(os.getcwd(),"jobs",self.job_name,"log.txt")
			self.logger = clogging.getLogger("upgrade_logger")
			self.logger.setLevel(clogging.DEBUG)
			handler = cRotatingFileHandler(log_path, maxBytes=50000000, backupCount=1)
			formatter = clogging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
			handler.setFormatter(formatter)
			self.logger.addHandler(handler)
			self.logger.propagate = True

			self.logger.info("JOBNAME:"+str(self.job_name))
			self.logger.info("CONFIG FILE:"+str(self.config_file))

			self.job_history_db = os.path.join(os.getcwd(),"db","job_history.db")
			self.upgrade_db = os.path.join(os.getcwd(),"jobs",self.job_name,"upgrade.db")
			self.event_db = os.path.join(os.getcwd(),"jobs",self.job_name,"event.db")
			self.async_event_db = os.path.join(os.getcwd(),"jobs",self.job_name,"async_event.db")
			self.validation_db = os.path.join(os.getcwd(),"jobs",self.job_name,"validation.db")

			if self.init_upgrade() == True:
				self.eprint("info","Starting Configuration {} Validation".format(config_file))
				config_status = self.validate_configuration()
			else:
				self.eprint("error","Init failed")
				return False

			if config_status == True:
				ar_upgrade = Aruba_Wireless_upgrade(self)

				# Start the precheck
				self.user_pause_terminate()
				res = self.get_user_input("Are you sure want to start the precheck",["yes","no"])
				self.logger.info(res)
				pre_check_valid = False
				if res == "yes":
					self.eprint("info","Starting precheck")
					pre_check_valid = ar_upgrade.Pre_Post_check("Precheck")
				else:
					self.eprint("warning","TERMINATED User aborted the precheck")
					self.final_status = ["TERMINATED","User aborted the precheck"]
					return False

				# Start the Installation
				pre_check_valid = True
				upgrade_valid = False
				if pre_check_valid == True:
					if "all" in job_list:
						self.user_pause_terminate()
						res = self.get_user_input("Are you sure want to start the AOS Upgrade",["yes","no"])
						if res == "yes":
							self.user_pause_terminate()
							upgrade_valid = ar_upgrade.Upload_Images()
							self.eprint("info","Starting Upgrade")
						else:
							self.eprint("warning","TERMINATED User aborted the upgrade")
							self.final_status = ["TERMINATED","User aborted the upgrade"]
							return False
					else:
						self.final_status = ["COMPLETED","Precheck Valid"]
						return True
				else:
					self.final_status = ["TERMINATED","Precheck Validation failed"]
					self.eprint("error","Precheck validation failed")
					return False

				# Start the reboot, Running from upgraded AOS

				if upgrade_valid == True:
					self.user_pause_terminate()
					res = self.get_user_input("Are you sure want to start the AOS Upgrade",["yes","no"])
					if res == "yes":
						self.user_pause_terminate()
						self.eprint("info","Starting reboot")
						ar_upgrade.ReBoot_Controller()
					else:
						self.eprint("warning","TERMINATED User aborted the reboot")
						self.final_status = ["TERMINATED","User aborted the reboot"]
						return False

				# Starting Post check
				self.user_pause_terminate()
				res = self.get_user_input("Are you sure want to start the postcheck",["yes","no"])
				self.logger.info(res)
				post_check_valid = False
				if res == "yes":
					self.eprint("info","Starting postcheck")
					post_check_valid = ar_upgrade.Pre_Post_check("Postcheck")
				else:
					self.eprint("warning","TERMINATED User aborted the postcheck")
					self.final_status = ["TERMINATED","User aborted the postcheck"]
					return False

			else:
				self.final_status = ["TERMINATED","Yaml configuration validation failed"]
				self.eprint("error","Generating config failed (Terminating)")
				return False



		except Exception as e:
			print("main_run: "+str(e))
			#self.logger.exception("main_run")
		finally:
			# Update the job status as completed with message
			print("===============>>>>")
			self.finish_upgrade(self.final_status[0],self.final_status[1])





if __name__ == '__main__':
	mm = main_model()
	mm.main_run(12345,"configuration_2.yaml",["precheck"])
	#print("Direct call not supported...")