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

import re


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

				_d = {"validation":"current boot partition","value":current_boot_partition}
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

				_d = {"validation":"first partition version","value":first_version}
				_d.update(device_info)
				results.append(_d)
				_d = {"validation":"first partition build","value":first_build}
				_d.update(device_info)
				results.append(_d)

				second_partition = part[7]
				second_partition = second_partition.split(" : ")[1].split(" ")[0].split(":")[1]
				second_version = part[8]
				second_version = second_version.split("ArubaOS ")[1].split(" ")[0]
				second_build = part[9].split(" : ")[1].split(" ")[0]

				_d = {"validation":"second partition version","value":first_version}
				_d.update(device_info)
				results.append(_d)
				_d = {"validation":"second partition build","value":first_build}
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
						_d = {"validation":"disk "+used_disk[0]+" useage","value":used_disk[3]}
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
					_d = {"validation":"free memory bytes","value":o.strip()}
					_d.update(device_info)
					results.append(_d)
				except Exception:
					obj.logger.exception("get_system_health : show memory")

		except Exception:
				#obj.eprint("error","Upload Image Error For : {} - {}".format(host_name,host_ip))
				obj.logger.exception("get_system_health")

	return results


class gen_report():
	def __init__(self):
		pass
	def run_checklist(self,obj,hosts):
		#self.report_location = report_location
		#self.report_data = report_data
		self.obj = obj
		self.hosts = hosts
		r = get_disk_images(self.obj,self.hosts)
		for x in r:
			print(x)
		r = get_system_health(self.obj,self.hosts)

		for x in r:
			print(x)

	def validate_health(self,pre_report,post_report=None):
		# Validate 
		for single_host in self.pre_report:
			pass;
			

