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

logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(os.getcwd()+"/Aruba_Upgrade.log", maxBytes=5000000, backupCount=25)
formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = True

logger.info("Starting Aruba Upgrade....")

class xls_writer():
	# Writing data to XLSX file
	def __init__(self,):
		try:
			self.df = pandas.DataFrame()
		except Exception:
			print("xls_writer error")
			logger.exception("xls_writer error")
	
	def append(self,dict_data):
		try:
			d = pandas.DataFrame(dict_data,index=[0])
			self.df = self.df.append(d,ignore_index = True)
		except Exception:
			print("xls_writer append error")
			logger.exception("xls_writer append error")

	def save(self,filename,sheet_name):
		try:
			self.filename = filename
			self.sheet_name = sheet_name
			self.df.to_excel(self.filename+".xlsx",sheet_name=self.sheet_name, engine='xlsxwriter',index=False)
		except Exception:
			print("xls_writer save error")
			logger.exception("xls_writer save error")

class Aruba_upgrade():
	def __init__(self):
		self.config_file_name = "configuration.yaml"
		self.config = None
		self.api_show_cmd = "https://{}/v1/configuration/showcommand?command={}&UIDARUBA={}"
		self.mm_image_upload = "https://{}/screens/wms/wms-os-upload.html"
		self.controller_save_reload = "https://{}/v1/configuration/object/reload_save_pending?UIDARUBA={}"
		self.ap_image_preload = "https://{}/v1/configuration/object/ap_image_preload?UIDARUBA={}"
		self.copy_flash_tftp = "https://{}/v1/configuration/object/copy_flash_tftp?UIDARUBA={}"
		self.backup_flash_local = "https://{}/v1/configuration/object/flash_backup?UIDARUBA={}"
		self.copy_tftp_system = "https://{}/v1/configuration/object/copy_tftp_system?UIDARUBA={}"
		self.print = pprint.PrettyPrinter(indent=4)

	def yes_no(self,msg="Do you want to continue (Y/N)"):
		while True:
			_input = input(msg)
			if _input == "Y" or _input == "y":
				return True
			elif _input == "N" or _input == "n":
				return False
			else:
				print("Please enter valid option")

	def validate_yaml_configuration(self):
		# Read the YAML configuration file from local path
		# Validate the required configuration information
		try:
			v_status = "Not completed"
			print("=> Validating YAML file for errors ")
			print("=> Reading YAML from {}".format(self.config_file_name))
			config_file = open(self.config_file_name)
			self.config = yaml.load(config_file,Loader=yaml.Loader)
			
			#print(self.config)

			validator = cerberus.Validator()
			validator.allow_unknown = True
			
			form_schema = dict()
			form_schema.update({'Authentication': {'required': True}})
			

			# Validating globle settings
			#print(self.config)
			form_data = {}
			form_data.update({"Authentication":{"schema":
				{"username":{"required":True},"password":{"required":True}}}})
			form_data.update({"Validate Image before upgrade":{"required":True,'allowed':[True,False]}})
			form_data.update({"Validate controller sync before upgrade":{"required":True,'allowed':[True,False]}})
			form_data.update({"Pre_image_AP":{"required":True,'allowed':[True,False]}})
			form_data.update({"Pre_image_AP":{"required":True,'allowed':[True,False]}})
			form_data.update({"max_ap_image_load":{"required":True,'min': 1, 'max': 256}})
			form_validate = validator.validate(self.config,form_data)


			if form_validate == False:
				print("** => Configuration error for {}".format(validator.errors))
				v_status = "Failed"
				#return False
				exit(0)

			# Validating upgrade
			for _type in ["Upgrade"]:
				if self.config.get(_type) != None:
					print("=> Validating {}".format(_type))
					conf = self.config.get(_type)
					form_data = {}
					form_data.update({"hostname":{"required":True}})
					form_data.update({"type":{"required":True,'allowed':['MM','MD']}})
					form_data.update({"host":{"required":True}})
					form_data.update({"image_file_name":{"required":True}})
					form_data.update({"image_version":{"required":True}})
					form_data.update({"image_build":{"required":True,"type":"integer"}})
					form_data.update({"disk":{"required":False,'allowed':[0,1]}})
					form_data.update({"upload_type":{"required":True,'allowed':["tftp","local"]}})
					#form_data.update({"Validate controller configID before upgrade":{"required":True,'allowed':[True,False]}})
					for host in conf:
						#validator = cerberus.Validator()
						#validator.allow_unknown = True
						form_validate = validator.validate(host,form_data)
						if form_validate == False:
							print("** => Configuration error for {} : {}".format(_type,validator.errors))
							#return False
							v_status = "Failed"
							exit(0)
				else:
					print("** => Error Upgrade configuration not found")
					v_status = "Failed"
					exit(0)

			if v_status != "Failed" or v_status != "Not completed":
				v_status = "Completed"

		except Exception:
			print(" Error Reading Config file")
			logger.exception("read_configuration exception:")
			exit(0)
		finally:
			print("==> YAML validation {}".format(v_status))

	def login(self,host_ip):
		try:
			login_url = "https://{}/v1/api/login".format(host_ip)

			auth = self.config.get("Authentication")
			username = auth.get("username")
			password = auth.get("password")

			login_post = {"username":username ,"password": password}
			print(" "*120+">Trying Login => {}".format(host_ip))

			r_session = requests.Session()
			res = r_session.post(login_url, data = login_post,verify=False)
			res = res.json()
			login_status = res.get("_global_result").get("status")
			login_msg = res.get("_global_result").get("status_str")
			UIDARUBA = res.get("_global_result").get("UIDARUBA")
			
			if login_status == "0":
				print(" "*120+">Login Success => {}".format(host_ip))
			else:
				print("** Login Failed : {} => {}".format(host_ip,login_msg))
				return False,login_status

			return True,r_session,UIDARUBA
		
		except requests.exceptions.ConnectTimeout:
			logger.exception("Login request timeout : ".format(str(host_ip)))
			return None,None

		except Exception:
			logger.exception("Login error: ".format(str(host_ip)))
			return None,None

	def logout(self,session,host_ip):
		try:
			#print("Trying logout => {}".format(host_ip))
			url = "https://{}".format(host_ip)
			url = urljoin(url,"v1/api/logout")
			res = session.get(url,verify=False)
			#print(res.content)
		except Exception:
			logger.exception("Logout error:".format(str(host_ip)))

	def backup_flash_to_disk(self,host_ip,session,UIDARUBA,dst_file_name):
		try:
			jdata = {"backup_flash": "backup_flash", "flash": "flash", "filename": dst_file_name}
			url = self.backup_flash_local.format(host_ip,UIDARUBA)
			print("==> {}- Starting flash Backup to file: ".format(host_ip,dst_file_name))
			res = session.post(url,json=jdata,verify=False)
			try:
				response = res.json()
			except:
				response = res.content

			if type(response) == dict:
				result = response.get("_global_result")
				if result.get("status") == 0:
					print("==> Flash Backup {} - Pending {}".format(result.get("status_str"),result.get("_pending")))
					return True
				else:
					print("** ==> Flash Backup Failed: {} \n".format(result.get("status_str")))
		except Exception:
			print("** ==> Flash Backup Failed")
			logger.exception("flash_copy_flash_tftp: ")


	def file_copy_flash_tftp(self,host_ip,src_file,tftphost,dst_file):
		# Copy flash file to tftp server
		try:
			jdata = {"srcfilename":src_file,"destfilename":dst_file,"tftphost":tftphost}
			login_status = self.login(host_ip)
			session = None
			if login_status[0] == True:
				session = login_status[1]
				UIDARUBA = login_status[2]

				#print(jdata)

				print("==> {}- Copying file from flash:{} to {} dstfile: {}".format(host_ip,src_file,tftphost,dst_file))
				url = self.copy_flash_tftp.format(host_ip,UIDARUBA)
				res = session.post(url,json=jdata,verify=False)
				try:
					response = res.json()
				except:
					response = res.content

				if type(response) == dict:
					result = response.get("_global_result")
					if result.get("status") == 0:
						print("==> copy {} - Pending {}".format(result.get("status_str"),result.get("_pending")))
					else:
						print("** ==> Copy Failed: {} \n".format(result.get("status_str")))

				#print(response)

		except Exception:
			logger.exception("flash_copy_flash_tftp: ")
		finally:
			self.logout(session,host_ip)

	def validating_pre_check(self,single_host,host_output,xlw):
		# 1) Validate current image version
		# 2) Validate the current disk image
		
		try:

			new_image = single_host.get("image_file_name")
			new_disk = single_host.get("disk")
			upload_type = single_host.get("upload_type")
			device_type = single_host.get("type")
			hostname = single_host.get("hostname")
			host_ip = single_host.get("host")

			
			if host_output.get("show switchinfo") != None:
				try:
					result = host_output.get("show switchinfo")
					out = result.get("_data")[0]
					re_table = textfsm.TextFSM(open(os.path.join(os.getcwd(),"text_fsm","show_switchinfo.txt")))
					fsm_results = re_table.ParseTextToDicts(out)
					for res in fsm_results[0].items():
						xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":res[0],"VALUE":res[1]})
				except Exception:
					logger.exception("validating_pre_check : show switchinfo")

			if host_output.get("show image version") != None:
				try:
					result = host_output.get("show image version")
					out = result.get("_data")[0]
					part_1 = re.findall(r'Partition.*',out)[0]
					re.findall(r'Partition.*',part_1)[0]

					part_1 = re.findall(r'Partition.*',out)[0]
					v1 = re.findall(r'Software Version.*',out)[0].split("ArubaOS")[1]
					build_1 = re.findall(r'Build number.*',out)[0]
					xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":part_1,"VALUE":v1})
					xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"BUILD","VALUE":build_1})

					part_2 = re.findall(r'Partition.*',out)[1]
					v2 = re.findall(r'Software Version.*',out)[1].split("ArubaOS")[1]
					build_2 = re.findall(r'Build number.*',out)[1]
					xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":part_2,"VALUE":v2})
					xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"BUILD","VALUE":build_2})

				except Exception:
					logger.exception("validating_pre_check : show image version")

			if host_output.get("show storage") != None:
				try:
					result = host_output.get("show storage")
					out = result.get("_data")[0]
					for t in re.findall(r'/.*%',out):
						used_disk = t.split(" ")[-1]
						xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"Disk usage","VALUE":used_disk})
				except Exception:
					logger.exception("validating_pre_check : show storage")

			if host_output.get("show cpuload") != None:
				try:
					result = host_output.get("show cpuload")
					out = result.get("_data")[0]
					o = re.findall(r'idle.*',out)[0]
					xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"Free CPU","VALUE":o})
				except Exception:
					logger.exception("validating_pre_check : show cpuload")

			if host_output.get("show memory") != None:
				try:
					result = host_output.get("show memory")
					out = result.get("_data")[0]
					o = re.findall(r'free.*',out)[0]
					xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"Free Memory","VALUE":o})
				except Exception:
					logger.exception("validating_pre_check : show memory")

			for cm in ["show master-l3redundancy","show master-redundancy"]:
				try:
					result = host_output.get(cm)
					out = result.get("_data")[0]
					o = re.findall("current state is.*",out)
					if len(out) > 0:
						xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"Redundancy","VALUE":o[0]})
				except Exception:
					pass;
					#logger.exception("validating_pre_check : redundancy")


			if upload_type == "local":
				if os.path.isfile(os.path.join(os.getcwd(),new_image)) == False:
					print(" ** Failed => Image file {} not present for {}".format(new_image,single_host.get("hostname")))
			#_new_image = ""
			#new_image = re.findall(r'\d+', new_image)
			#for i in new_image:
			#	_new_image = _new_image + str(i)

			#Validate the current disk image
			running_disk = host_output.get("show boot")
			running_disk = str(running_disk).split("PARTITION ")[1]
			running_disk = int(running_disk[0])

			#if int(new_disk) == running_disk:
			#	print(" ** Failed => Running Disk ({}) Upgrade Disk ({}) are same".format(running_disk,new_disk))
		except Exception:
			print("==> Validation failed for: "+str(hostname))
			logger.exception("validating_pre_check")


	def Pre_Post_check(self,check_type,log_file_path):
		try:

			xlw = xls_writer()

			c_date = str(datetime.datetime.now().strftime('%b_%d_%H_%M_%S'))

			print("Executing "+check_type)
			hosts = self.config.get("Upgrade")
			
			for single_host in hosts:
				host = single_host.get("host")
				hostname = single_host.get("hostname")
				device_type = single_host.get("type").strip()
				cmds = self.config.get("CheckList_"+device_type)
				print("\nChecking : {}".format(host))
				_host = host.split(":")[0]
				log_file = open(os.path.join(log_file_path,_host+".txt"),"w")
				pyobj_file = open(os.path.join(log_file_path,_host+".pyobj"),"wb")
				
				session = None
				login_status = self.login(host)

				if login_status[0] == True:
					session = login_status[1]
					UIDARUBA = login_status[2]
					host_output = dict()
					for cmd in cmds:
						if cmd.get("show") != None:
							cmd = cmd.get("show")
							cmd = cmd.lower().strip()
							print("Executing {} - {} => {}".format(hostname,host,cmd))
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
							print("** => Not Implemented for: "+str(cmd))
					
					
					self.validating_pre_check(single_host,host_output,xlw)
					
				else:
					print("Precheck failed for => {}".format(host))
					if self.yes_no() == False: exit(0)

				self.logout(session,host)
				log_file.close()
				pyobj_file.close()

		except Exception:
			print("** ==> Check execution error")
			logger.exception("Precheck_Error")
		finally:
			p = os.path.join(log_file_path,check_type+"_"+c_date)
			xlw.save(p,check_type)
			print("\n ============== Check Completed =========== \n")


	def upload_image_tftp(self,host_ip,img_file,disk,tftp_ip):
		try:
			login_status = self.login(host_ip)
			
			if login_status[0] == True:
				session = login_status[1]
				UIDARUBA = login_status[2]
				partition = "partition"+str(disk)

				jdata = {"partition_num": partition,"tftphost": tftp_ip,"filename": img_file}

				print(jdata)

				print("==> {}- Copying file: {} from tftp:{}".format(host_ip,img_file,tftp_ip))
				url = self.copy_tftp_system.format(host_ip,UIDARUBA)
				res = session.post(url,json=jdata,verify=False)
				try:
					response = res.json()
				except:
					response = res.content

				if type(response) == dict:
					print(response)
					result = response.get("_global_result")
					if result != None:
						if result.get("status") == 0:
							print("==> copy {} - Pending {}".format(result.get("status_str"),result.get("_pending")))
						else:
							print("** ==> Copy Failed: {} \n".format(result.get("status_str")))
					else:
						print("** ==> Copy Failed: {} \n".format(str(response)))

		except Exception:
			logger.exception("upload_image_tftp")


	def upload_image_http(self,host_ip,img_file,disk):
		try:
			login_status = self.login(host_ip)

			headers = {}

			if login_status[0] == True:
				session = login_status[1]
				UIDARUBA = login_status[2]
				file_path = os.path.join(os.getcwd(),img_file)
				file_data = open(file_path,'rb')
				
				data = {'.osimage_handle': (img_file,file_data,"application/octet-stream")}
				data.update({"fpartition":str(disk),"UIDARUBA":UIDARUBA})
				url = self.mm_image_upload.format(host_ip)
				#print(url)
				#print(UIDARUBA)
				mp = MultipartEncoder(fields=data)
				headers.update({'Content-Type': mp.content_type})
				
				#prepared = requests.Request('POST', url,data=mp,headers=headers).prepare()
				
				print("==> Uploading image file to MD: {} AOS: {}".format(host_ip,img_file))
				#print(prepared.headers)
				#print(session.cookies.get_dict())
				
				#url = "https://10.17.84.221:4343/v1/configuration/showcommand?command=show%20version&UIDARUBA="+UIDARUBA
				#prepared = requests.Request('GET', url).prepare()
				
				res = session.post(url,data=mp,headers=headers,verify=False)
				print(res.content)
				print("==> Completed Upload image file to MD: {} AOS: {}".format(host_ip,img_file))
				
				self.logout(session,host_ip)
		except Exception:
			logger.exception("upload_image_http: ")

	def execute_cmd(self,host_ip,cmds):
		try:
			out_cmd = {}
			login_status = self.login(host_ip)
			if login_status[0] == True:
				session = login_status[1]
				UIDARUBA = login_status[2]
				for cmd in cmds:
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

				self.logout(session,host_ip)
				return out_cmd
		except Exception:
			logger.exception("get_image_details: ")



	def MM_MD_Upload(self,host):
		upload_not_required = False
		img_file = host.get("image_file_name")
		host_ip = host.get("host")
		hostname = host.get("hostname")
		disk = host.get("disk")
		upload_type = host.get("upload_type")
		upload_type = host.get("upload_type")
		image_build = host.get("image_build")
		image_version = host.get("image_version")
		auto_detect_failed = None

		if disk == None:
			# Get alternative partition
			cmd_out = self.execute_cmd(host_ip,["show boot"])
			try:
				out = cmd_out.get("show boot")
				out = out.get("_data")[0]
				out = re.findall(r'PARTITION\s*.*',out)[0][-1]
				out = int(out)
				if out == 1:
					disk = 0
				elif out == 0:
					disk = 1
				else:
					auto_detect_failed = True
				print("=> {}-{} :Auto detect alternative partition: {}".format(hostname,host_ip,disk))
				auto_detect_failed = False
			except:
				auto_detect_failed = True
				print("** => {}-{} : Auto detect alternative partition failed".format(hostname,host_ip))
				logger.exception("Auto detect alternative partition failed")
				auto_detect_failed = True

		if disk == None or auto_detect_failed == True:
			print("** => {}-{} : Skipping Install...".format(hostname,host_ip))
			return False
		else:
			# Just overwrite disk if autodetected
			host.update({"disk":disk})

		while upload_not_required == False:
			if self.validate_image_upload(host_ip,disk,image_version,image_build) != True:
				msg = "Do you want to install the image for: "
				if self.yes_no("{} {} - {} on Disk {} (Y/N)".format(msg,hostname,host_ip,disk)) == True:
					#print("==> Starting MM Upgrade for {}".format(host_ip))
					if upload_type == "local":
						self.upload_image_http(host_ip,img_file,disk)
					elif upload_type == "tftp":
						tftp_ip = self.config.get(upload_type)
						self.upload_image_tftp(host_ip,img_file,disk,tftp_ip)
					else:
						print("No valid file upload type found"+str(upload_type))
						exit(0)
				else:
					upload_not_required = True
			else:
				upload_not_required = True

		

	def AP_IMAGE_PRELOAD(self,host):
		try:

			global last_skip
			upload_not_required = False
			img_file = host.get("image_file_name")
			host_ip = host.get("host")
			host_name = host.get("hostname")
			disk = host.get("disk")
			image_build = host.get("image_build")
			image_version = host.get("image_version")
			max_ap_image_load = self.config.get("max_ap_image_load")

			msg = " \n Do You want to preimage AP's for :"
			if self.yes_no("{} {} - {} from Disk {} (Y/N):".format(msg,host_name,host_ip,disk)) == False:
				print("Skipping AP's preimage....")
				return False
			
			print("==> STARTING AP IMAGE PRELOAD FOR {}-{} FROM DISK:{} MAX AP:{}".format
				(host_name,host_ip,disk,max_ap_image_load))
			
			# Execute the pre-image command
			input_required()
			valid_state = False
			
			while last_skip == False and valid_state == False:
				try:
					upload_not_required = True
					login_status = self.login(host_ip)
					if login_status[0] == True:
						session = login_status[1]
						UIDARUBA = login_status[2]
						url = self.ap_image_preload.format(host_ip,UIDARUBA)
						data = {"ap_info":"all-aps","partition":int(disk),"max-downloads":int(max_ap_image_load)}
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
									print("==> AP Pre-load Success:{}-{} => {}".format(host_name,host_ip,p))
									valid_state = True
									self.logout(session,host_ip)
								else:
									p = response.get("_result").get("status_str")
									print("** ==> AP Pre-load Failed:{}-{} => {}".format(host_name,host_ip,p))
							else:
								raise TypeError("Response not having 'ap_image_preload' field")
				except TypeError:
					self.logout(session,host_ip)
					print("===> Failed")
					logger.exception("AP_IMAGE_PRELOAD:")

				except Exception:
					self.logout(session,host_ip)
					print("===> Failed")
					logger.exception("AP_IMAGE_PRELOAD POST: ")
				finally:
					# Sleep for some time before retry
					print("Retry in 3 (sec) - Press Ctl+c to Skip the retry")
					time.sleep(3)


			# Validate the pre-load
			input_required()
			valid_state = False
			
			while last_skip == False and valid_state == False:
				try:
					res = self.execute_cmd(host_ip,["show ap image-preload status summary"])
					if res != None:
						out = res.get("show ap image-preload status summary")
						itm = out.get("AP Image Preload Parameters")[0].get("Item")
						value = out.get("AP Image Preload Parameters")[0].get("Value")
						print("==> AP Preload Status:{}-{} => {} : {} ".format(host_name,host_ip,itm,value))
					else:
						print("** ==>AP Preload status check failed:{}-{}".format(host_name,host_ip))
				except Exception:
					print("===> Failed")
					logger.exception("AP_IMAGE_PRELOAD POST: ")
				finally:
					# Sleep for some time before retry
					print("Retry in 3 (sec) - Press Ctl+c to Skip the retry")
					time.sleep(3)



		except Exception:
			logger.exception("AP_IMAGE_PRELOAD: ")

	def validate_all_sync(self,host_ip,validate_sync,validate_up):
		try:
			out = self.execute_cmd(host_ip,["show switches"])
			valid_sync = None
			if out != None:
				_data = out.get("show switches")
				switches = _data.get("All Switches")
				valid_sync = True
				for switch in switches:
					cs = switch.get("Configuration State")
					cid = switch.get("Config ID")
					ctype = switch.get("Type")
					cname = switch.get("Name")
					ip = switch.get("IP Address")
					status = switch.get("Status")
					version = switch.get("Version")
					ct = switch.get("Config Sync Time (sec)")

					print("\nFrom:{}=> Host:{}-{} Status:{} Config:{} ID:{} V:{} SYNC_TIME:{} \n".format
						(host_ip,cname,ip,status,cs,cid,version,ct))
					
					if validate_sync != False:
						if cs != "UPDATE SUCCESSFUL":
							valid_sync = False
					if validate_up != False:
						if status != "up":
							valid_sync = False


			return valid_sync


		except Exception:
			logger.exception("validate_all_sync")
			return False


	def validate_image_upload(self,host_ip,disk,version,build):
		try:
			out = self.execute_cmd(host_ip,["show image version"])
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
					print("=> New Image Already Installed = Host:{} Disk:{} Version:{} Build:{}"
						.format(host_ip,disk,version,build))
					return True
				else:
					print("** => New Image Not Installed = Host:{} Disk:{} Version:{} Build:{}"
						.format(host_ip,disk,version,build))
					return False
				

			else:
				return None
		except Exception:
			logger.exception("validate_image_upload")


	def validate_running_image(self,host_ip,version,build):
		try:
			out = self.execute_cmd(host_ip,["show version"])
			valid_image = False
			if out != None:
				_data = out.get("show version")
				_data = _data.get("_data")[0]
				if _data.find(str(version)) != -1:
					if _data.find(str(build)) != -1:
						print("=> Running Image Host:{} Version:{} Build:{}"
						.format(host_ip,version,build))
						return True
				return False
		except Exception:
			logger.exception("validate_running_image: ")

	def process_controller_reboot(self,host_ip,host_name,host_type,wait_reboot=True):
		try:
			global last_skip
			rebooted = False
			login_status = self.login(host_ip)
			if login_status[0] == True:
				session = login_status[1]
				UIDARUBA = login_status[2]
				url = self.controller_save_reload.format(host_ip,UIDARUBA)
				res = session.post(url,data = {},verify=False)
				#print(res.content)
				print("==> Reloading {}: {} - {}".format(host_type,host_name,host_ip))
				time.sleep(3)

				reload_completed = False
				reachability_failed = False

				if wait_reboot == True:
					input_required()
					while last_skip == False and reload_completed == False:
						try:
							# Check for session expire to validate the reload
							s_url = self.api_show_cmd.format(host_ip,"show clock",UIDARUBA)
							res = session.get(s_url,verify=False)
							#print(res.status_code)

							if res.status_code == 401 and reachability_failed == True:
								# Session Expired Reload completed
								print("==> Reload Completed for ({}) {} {}".format(host_type,host_name,host_ip))
								reload_completed = True
								return True
							else:
								print("({}) {} {} => Pinging...".format(host_type,host_name,host_ip))
						except Exception:
							reachability_failed = True
							print("({}) {} {} => Request timeout...".format(host_type,host_name,host_ip))
							#logger.exception("Ping Timeout")

						print(" "*80+"Press Ctl+c to skip this validation")
						time.sleep(3)
		except Exception:
			logger.exception("process_controller_reboot: ")


	def ReBoot_Controller(self):
		try:
			global last_skip
			upgrade_hosts = self.config.get("Upgrade")
			validate_image = self.config.get("Validate Image before upgrade")
			validate_sync = self.config.get("Validate controller sync before upgrade")
			#validate_confid = self.config.get("Validate controller configID before upgrade")
			validate_up = self.config.get("Validate controller up before upgrade")
			
			image_valid = None
			sync_valid = None
			confid_valid = None

			if validate_image != False:
				# Validate the new image in controller
				
				for host in upgrade_hosts:
					host_name = host.get("hostname")
					host_ip = host.get("host")
					disk = host.get("disk")
					image_build = host.get("image_build")
					image_version = host.get("image_version")
					print("=>{}-{} : Validating New Image....".format(host_name,host_ip))
					if self.validate_image_upload(host_ip,disk,image_version,image_build) != True:
						image_valid = False

			
			for host in upgrade_hosts:
				host_ip = host.get("host")
				host_name = host.get("hostname")
				print("=>{}-{} : Validating switch sync...".format(host_name,host_ip))
				if self.validate_all_sync(host_ip,validate_sync,validate_up) != True:
					confid_valid = False

			if validate_image != False:
				if image_valid == False:
					print("\n** ==> Image Validation failed \n\n")
					#exit(0)
			
			if validate_sync != False or validate_up != False:
				if confid_valid == False:
					print("\n** ==> Validation switches status failed\n\n")
					#exit(0)

			for host in upgrade_hosts:
				host_name = host.get("hostname")
				host_ip = host.get("host")
				host_type = host.get("type")
				image_build = host.get("image_build")
				image_version = host.get("image_version")
				print("\n *** Do you want to reboot: ({}) - {} - {}".format(host_type,host_name,host_ip))
				if self.yes_no() == True:
					reboot_status = self.process_controller_reboot(host_ip,host_name,host_type,True)
					if reboot_status != True:
						print("*** Warning : Failed to get reboot info (Please check manualy...)")
						input("Press Enter to continue after validation...")
					#self.validate_controller_up(host_ip)
					# Validate config sync and up status
					if self.validate_running_image(host_ip,image_version,image_build) == False:
						print("** ==> ({}) {}-{} Not booted from new image".format(host_type,host_name,host_ip))
					else:
						print("==>({}) {}-{} Image upgrade success".format(host_type,host_name,host_ip))

					input_required()
					valid_state = False
					while last_skip == False and valid_state == False:
						if self.validate_all_sync(host_ip,True,True) == True:
							valid_state = True

						print("Sleeping 10 sec (Press Ctl+c to skip this validation for:{} {})".format
							(host_ip,host_name))
						time.sleep(10)




		except Exception as e:
			print("ReBoot_Controller"+str(e))



	def Upload_Images(self):
		try:
			#Read upgrade host details from configuration
			upgrade_hosts = self.config.get("Upgrade")
			print("\nTotal upgrade hosts:{}".format(len(upgrade_hosts)))

			# Uploading Images to MM and MD
			for host in upgrade_hosts:
				host_name = host.get("hostname")
				host_ip = host.get("host")
				disk = host.get("disk")
				image_build = host.get("image_build")
				image_version = host.get("image_version")

				if host.get("type") == "MM":
					# Start the MM Upgrade
					print("==> MM: Preparing for host {} IP: {}".format(host_name,host_ip))
					#self.validate_image_upload(host_ip,disk,image_version,image_build)
					self.MM_MD_Upload(host)
					#self.validate_running_image(host_ip,image_version,image_build)
					
				elif host.get("type") == "MD":
					print("==> MD: Preparing for host {} IP: {}".format(host_name,host_ip))
					self.MM_MD_Upload(host)
				else:
					print("Upgrade type invalid ({})".format(host.get("type")))

			#Pre-Uploading images to AP
			for host in upgrade_hosts:
				host_name = host.get("hostname")
				host_ip = host.get("host")
				disk = host.get("disk")
				image_build = host.get("image_build")
				image_version = host.get("image_version")

				if host.get("type") == "MD" :
					# Pre-Upload images to this MD
					self.AP_IMAGE_PRELOAD(host)


		except Exception:
			print("** => Upload Image Error For : {} - {}".format(host_name,host_ip))
			logger.exception("Upgrade Error: ")


global last_skip
last_skip = False

def catch_c(signal, frame):
	# Catching the Ctl+C 
	try:
		global last_skip
		print("Skip....")
		last_skip = True
		#time.sleep(100)
	except KeyboardInterrupt:
		print("Skipping.....")

def input_required():
	# Reset the last user Ctl+c press to False
	try:
		global last_skip
		last_skip = False
	except Exception:
		logger.exception("skip_required")



if __name__ == '__main__':
	print("** Aruba Controller upgrade **")

	# Skip the process if user press Ctl+C
	signal.signal(signal.SIGINT,catch_c)
	
	start_time = str(datetime.datetime.now().strftime('%b_%d_%H_%M_%S'))
	
	os_path = os.path.join(os.getcwd(),"log",start_time)

	if not os.path.exists(os_path):
		os.makedirs(os_path)

	au = Aruba_upgrade()
	au.validate_yaml_configuration()

	#au.file_copy_flash_tftp("10.17.84.221:4343","logs.tar","10.17.84.225","logs.tar")
	#exit(0)
	while True:

		print("\nPlease select below option")
		print("=="*20+"\n")
		print("1 => Pre-Check")
		print("2 => Post-Check")
		print("3 => Install Images")
		print("4 => Reboot from new image")
		print("Q => Quit")
		

		script_type = None
		inp = input("Enter Your Choice: ")

		if inp == "q" or inp == "Q":
			print("\nGood bye...\n")
			exit(0)
		
		if int(inp) == 1:
			
			pre_chk = os.path.join(os_path,"PreCheck")
			if not os.path.exists(pre_chk):
				os.makedirs(pre_chk)
			script_type = "PreCheck"
			print(pre_chk)
			au.Pre_Post_check(script_type,pre_chk)
		
		elif int(inp) == 2:
			
			post_chk = os.path.join(os_path,"PostCheck")
			if not os.path.exists(post_chk):
				os.makedirs(post_chk)

			script_type = "PostCheck"
			au.Pre_Post_check(script_type,post_chk)
		
		elif int(inp) == 3:

			upgrade_path = os.path.join(os_path,"Upload")
			if not os.path.exists(upgrade_path):
				os.makedirs(upgrade_path)

			script_type = "Upload"
			au.Upload_Images()

		elif int(inp) == 4:

			upgrade_path = os.path.join(os_path,"Boot from new Image")
			if not os.path.exists(upgrade_path):
				os.makedirs(upgrade_path)

			script_type = "Upgrade"
			au.ReBoot_Controller()
		
		else:
			print("Please select correct option, bye....")
			exit(0)