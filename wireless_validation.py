"""Validations
1) Validate current disk image versions and default boot set
2) Validate the CPU, Memory,Disk status
3) Validate - L3-redundance validation in MM, show lc-cluster vlan probe status on MDs
4) Validate the controller sync ID,up status
5) Backup flash before upgrade
6) Backup configuration before upgrade
7) Backup license before upgrade
8) Validate the local new image files, with MD5 checksum
9) Validate the ftp,scp,tftp reachability
"""

import os
import re
import db_management


def validating_login(obj,hosts):
	results = []
	
	for single_host in hosts:
		hostname = single_host.get("hostname")
		host = single_host.get("host")
		device_type = single_host.get("device_type")

		device_info = {"hostname":hostname}
		device_info.update({"host":host})
		device_info.update({"device_type":device_type})
		db_management.update_upgrade_status_by_device_host(obj.upgrade_db,host,"RUNNING Checklist","Validating login")
		_d = dict()
		try:
			cmd_out = obj.execute_cmd(single_host,["show clock"],True)
			if type(cmd_out) == dict:
				clock = cmd_out.get("show clock")
				_d = {"validation":"Login","value":"Success","status":"Good"}
				_d.update(device_info)
				results.append(_d)
			else:
				if cmd_out[0] == False:
					_d = {"validation":"Login","value":"Authentication failed","status":"Failed"}
				else:
					_d = {"validation":"Login","value":"Request timeout","status":"Failed"}
				_d.update(device_info)
				results.append(_d)

		except Exception:
			#obj.eprint("error","Upload Image Error For : {} - {}".format(host_name,host_ip))
			obj.logger.exception("get_version")

	return results


def get_version(obj,hosts):
	""" Get the show version output """
	results = []
	
	for single_host in hosts:
		hostname = single_host.get("hostname")
		host = single_host.get("host")
		device_type = single_host.get("device_type")

		device_info = {"hostname":hostname}
		device_info.update({"host":host})
		device_info.update({"device_type":device_type})
		db_management.update_upgrade_status_by_device_host(obj.upgrade_db,host,"RUNNING Checklist","Validating version")
		_d = dict()
		try:
			cmd_out = obj.execute_cmd(single_host,["show version"])
			if cmd_out != None:
				_version = cmd_out.get("show version")
				_version = _version.get("_data")[0]
				run_version = re.findall(r'Version.*',_version)[0]
				_d = {"validation":"running version","value":run_version ,"status":"Ok"}
				_d.update(device_info)
				results.append(_d)
		except Exception:
			#obj.eprint("error","Upload Image Error For : {} - {}".format(host_name,host_ip))
			obj.logger.exception("get_version")

	return results

def get_disk_images(obj,hosts):
	"""Validate current disk image versions and default boot set for list of upgraded_hosts
	"""
	results = []
	for single_host in hosts:
		#print(single_host)
		hostname = single_host.get("hostname")
		host = single_host.get("host")
		device_type = single_host.get("device_type")

		device_info = {"hostname":hostname}
		device_info.update({"host":host})
		device_info.update({"device_type":device_type})

		db_management.update_upgrade_status_by_device_host(obj.upgrade_db,host,"RUNNING Checklist","Validating disk")
		_d = dict()
		
		#_d.update({"current boot partition":None})
		#_d.update({"first partition version":None})
		#_d.update({"first partition build":None})
		#_d.update({"second partition version":None})
		#_d.update({"second partition build":None})
		
		#single_host.update({"report":_d})

		try:
			cmd_out = obj.execute_cmd(single_host,["show boot","show image version"])
			if cmd_out != None:
				_boot = cmd_out.get("show boot")
				_boot = _boot.get("_data")
				current_boot_partition = _boot[0].split("PARTITION ")[1]
				current_boot_partition = int(current_boot_partition)

				_d = {"validation":"current boot partition","value":current_boot_partition,"status":"Ok"}
				_d.update(device_info)
				results.append(_d)

				_data = cmd_out.get("show image version")
				_data = _data.get("_data")
				part = _data[0].split("\n")
				
				first_partition = part[1]
				first_partition = first_partition.split(" : ")[1].split(" ")[0].split(":")[1]
				first_version = part[2]
				first_version = first_version.split("ArubaOS ")[1].split(" ")[0]
				first_build = part[3].split(" : ")[1].split(" ")[0]

				_d = {"validation":"first partition version","value":first_version,"status":"Ok"}
				_d.update(device_info)
				results.append(_d)
				_d = {"validation":"first partition build","value":first_build,"status":"Ok"}
				_d.update(device_info)
				results.append(_d)

				second_partition = part[7]
				second_partition = second_partition.split(" : ")[1].split(" ")[0].split(":")[1]
				second_version = part[8]
				second_version = second_version.split("ArubaOS ")[1].split(" ")[0]
				second_build = part[9].split(" : ")[1].split(" ")[0]

				_d = {"validation":"second partition version","value":first_version,"status":"Ok"}
				_d.update(device_info)
				results.append(_d)
				_d = {"validation":"second partition build","value":first_build,"status":"Ok"}
				_d.update(device_info)
				results.append(_d)

				

		except Exception:
			#obj.eprint("error","Upload Image Error For : {} - {}".format(host_name,host_ip))
			obj.logger.exception("validate_disk")

	return results

def get_system_health(obj,hosts):
	results = []
	for single_host in hosts:
		try:
			hostname = single_host.get("hostname")
			host = single_host.get("host")
			device_type = single_host.get("device_type")

			device_info = {"hostname":hostname}
			device_info.update({"host":host})
			device_info.update({"device_type":device_type})

			db_management.update_upgrade_status_by_device_host(obj.upgrade_db,host,"RUNNING Checklist","Validating CPU/Memory")
			_d = dict()
			host_output = obj.execute_cmd(single_host,["show storage","show cpuload","show memory"])
			
			if host_output.get("show storage") != None:
				try:
					result = host_output.get("show storage")
					out = result.get("_data")[0]
					all_disk = []
					for t in re.findall(r'/dev.*',out):
						t = t.split(" ")
						used_disk = list(filter(None, t))
						_d = {"validation":"disk "+used_disk[0]+" available","value":used_disk[3]}
						_d.update(device_info)
						results.append(_d)
						_d = {"validation":"disk "+used_disk[0]+" used percent","value":used_disk[4].split("%")[0]}
						_d.update(device_info)
						results.append(_d)
				except Exception:
					obj.logger.exception("get_system_health : show storage")

			if host_output.get("show cpuload") != None:
				try:
					result = host_output.get("show cpuload")
					out = result.get("_data")[0]
					o = re.findall(r'idle.*',out)[0]
					o = o.split(" ")[1].split(".")[0]
					#xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"Free CPU","VALUE":o})
					_d = {"validation":"free cpu percent","value":o}
					_d.update(device_info)
					results.append(_d)
				except Exception:
					obj.logger.exception("get_system_health : show cpuload")

			if host_output.get("show memory") != None:
				try:
					result = host_output.get("show memory")
					out = result.get("_data")[0]
					o = re.findall(r'free.*',out)[0]
					o = o.split("free:")[1]
					#xlw.append({"HOSTNAME":hostname,"IP":host_ip,"CMD":"Free Memory","VALUE":o})
					_d = {"validation":"free memory (Kb)","value":o.strip()}
					_d.update(device_info)
					results.append(_d)
				except Exception:
					obj.logger.exception("get_system_health : show memory")

		except Exception:
				#obj.eprint("error","Upload Image Error For : {} - {}".format(host_name,host_ip))
				obj.logger.exception("get_system_health")


	return results

def backup_flask(obj,hosts):
	results = []
	
	for single_host in hosts:
		hostname = single_host.get("hostname")
		host = single_host.get("host")
		device_type = single_host.get("device_type")

		device_info = {"hostname":hostname}
		device_info.update({"host":host})
		device_info.update({"device_type":device_type})
		db_management.update_upgrade_status_by_device_host(obj.upgrade_db,host,"RUNNING Checklist","Flash backup")
		_d = dict()
		try:
			cmd_out = obj.execute_cmd(single_host,["backup flash script_auto_flah_backup",
				"backup config script_auto_config_backup","show license"],True)
			if type(cmd_out) == dict:
				clock = cmd_out.get("backup flash script_auto_flah_backup")
				_d = {"validation":"Flash Backup","value":"Success","status":"Good"}
				_d.update(device_info)
				results.append(_d)

			if type(cmd_out) == dict:
				clock = cmd_out.get("backup config script_auto_config_backup")
				_d = {"validation":"Configuration Backup","value":"Success","status":"Good"}
				_d.update(device_info)
				results.append(_d)

			if type(cmd_out) == dict:
				license = cmd_out.get("show license")
				open(os.path.join(obj.job_path,"Upgrade",host.replace(":","_")+"license_backup.txt"),"w").write(str(license))
				_d = {"validation":"Configuration Backup","value":"Success","status":"Good"}
				_d.update(device_info)
				results.append(_d)
		except Exception:
			#obj.eprint("error","Upload Image Error For : {} - {}".format(host_name,host_ip))
			obj.logger.exception("backup_flask")

	return results


class gen_report():
	def __init__(self):
		pass

	def update_completed_status(self):
		for single_host in self.hosts:
			host = single_host.get("host")
			#db_management.update_upgrade_status_by_device_host(self.obj.upgrade_db,host,"COMPLETED","Checklist")


	def run_checklist(self,obj,hosts,check_type):
		#self.report_location = report_location
		#self.report_data = report_data
		self.check_type = check_type
		self.obj = obj
		self.hosts = hosts
		all_reports = []
		
		#If login failed , then don't run other precheck for any devices
		result = validating_login(self.obj,self.hosts)
		all_reports = all_reports + result
		for res in result:
			if res.get("status") != "Good":
				self.update_completed_status()
				return all_reports

		if self.check_type == "Precheck":
			result = backup_flask(self.obj,self.hosts)
			all_reports = all_reports + result

		result = get_disk_images(self.obj,self.hosts)
		report = self.validate_system_image(result)
		all_reports = all_reports + report
		
		result = get_system_health(self.obj,self.hosts)
		report = self.validate_system_health(result)
		all_reports = all_reports + report

		result = get_version(self.obj,self.hosts)
		report = result
		all_reports = all_reports + report

		self.update_completed_status()

		return all_reports



	def validate_system_health(self,result):
		# Validate 
		for r1 in result:
			try:
				print(r1)
				validation = r1.get("validation")
				print(validation)
				value = r1.get("value")
				if validation.find("disk /") != -1:
					print("Validating disk")
					# Validate disk usage
					if value.find("G") != -1:
						r1.update({"status":"Good"})
					elif value.find("M") != -1:
						value = float(value.split("M")[0])
						if value < 200:
						# Space required 200 MB
							r1.update({"status":"Warning: Avaliable disk less than 200 MB"})
						else:
							r1.update({"status":"Good"})
					elif validation.find("used percent") != -1:
						if float(value) > 80:
							r1.update({"status":"Warning: Used disk is more than 80%"})
						else:
							r1.update({"status":"Good"})

				elif validation.find("free cpu percent") != -1:
					print("Validating cpu")
					if float(value) > 20:
						r1.update({"status":"Good"})
					else:
						r1.update({"status":"Warning: CPU utilization is more than 80%"})

				elif validation.find("free memory") != -1:
					if float(value) < 1000000:
						r1.update({"status":"Warning: Memory is less than 1Gb"})
					else:
						r1.update({"status":"Good"})


			except Exception:
				self.obj.logger.exception("validate_system_health")
		return result

	def validate_system_image(self,result):
		for r1 in result:
			try:
				validation = r1.get("validation")
				value = r1.get("value")
				if validation.find("current boot partition"):
					pass;
				elif validation.find("first partition version"):
					pass;
				elif validation.find("first partition build"):
					pass;
				elif validation.find("second partition version"):
					pass;
				elif validation.find("second partition build"):
					pass;

			except Exception:
				self.obj.logger.exception("validate_system_image")

		return result

