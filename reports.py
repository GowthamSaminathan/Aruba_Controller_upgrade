import os
from jinja2 import Template
from datetime import datetime
import db_management


class report_gen():
	"""Used to generate the upgrade report"""
	def __init__(self,report_data,report_type):
		self.report_type = report_type
		self.report_data = report_data
		self.template_head_path = os.path.join(os.path.abspath('.'),"templates","report_template.html")
		self.template_precheck_path = os.path.join(os.path.abspath('.'),"templates","report_precheck_template")
		self.template_postcheck_path = os.path.join(os.path.abspath('.'),"templates","report_postcheck_template")
		self.template_upgrade_path = os.path.join(os.path.abspath('.'),"templates","report_upgrade_template")
		self.template_foot_path = os.path.join(os.path.abspath('.'),"templates","report_foot_template")
		

	def upgrade_gen(self):
		upgrade_data = []
		validation_db = self.report_data.get("validation_db")
		precheck_data = db_management.get_checklist(validation_db,"Precheck")
		precheck_data = db_management.get_checklist(validation_db,"Postcheck")
		hosts = self.report_data.get("Upgrade")
		div = 0
		for single_host in hosts:
			
			div = div+1
			device_type = single_host.get("device_type")
			host = single_host.get("host")
			hostname = single_host.get("hostname")

			q = "report_name='Precheck' AND validation='running version' AND host='{}' ".format(host)
			pre_version = db_management.get_checklist_by_val(validation_db,q)
			try:
				pre_version = pre_version[0][4]
			except:
				pre_version = "Na"
				pass;

			q = "report_name='Postcheck' AND validation='running version' AND host='{}' ".format(host)
			post_version = db_management.get_checklist_by_val(validation_db,q)

			try:
				post_version = post_version[0][4]
			except:
				post_version = "Na"
				pass;
			
			upgrade_data.append([div,device_type,host,hostname,pre_version,post_version])


		print(upgrade_data)
		self.template = self.template + open(self.template_upgrade_path).read()
		self.report_data.update({"upgrade_table":upgrade_data})


	def precheck_gen(self,check_type):
		self.template = self.template + open(self.template_precheck_path).read()
		validation_db = self.report_data.get("validation_db")
		precheck_data = db_management.get_checklist(validation_db,check_type)
		precheck_data = list(map(list, precheck_data))
		warning = 0
		failed = 0
		status = ""
		for chk in precheck_data:
			if chk[5].find("Warning") == 0:
				warning = warning + 1
				chk[5] = '<span class="badge badge-warning">'+chk[5]+'</span>'
			elif chk[5].find("Failed") == 0:
				failed = failed + 1
				chk[5] = '<span class="badge badge-danger">'+chk[5]+'</span>'
			elif chk[5].find("Good") == 0:
				chk[5] = '<span class="badge badge-success">'+chk[5]+'</span>'
			else:
				chk[5] = '<span class="badge badge-info">'+chk[5]+'</span>'

		
		status = "Good"
		status_clr = "success"
		if warning > 0:
			status_clr = "warning"
			status = "Warning"
		if failed > 0:
			status_clr = "danger"
			status = "Failed"

		self.report_data.update({"status":status,"status_clr":status_clr,"warning":warning,"failed":failed})
		self.report_data.update({"precheck_table":precheck_data})

	def create_footer(self):
		self.template = self.template + open(self.template_foot_path).read()

	def create_header(self):
		"""Create Report header"""
		self.template = open(self.template_head_path).read()
		_d = datetime.now().strftime("%H:%M:%S %d-%B-%Y")
		self.report_data.update({"report_type":self.report_type})
		self.report_data.update({"report_date":_d})
		self.report_data.update({"postcheck_table":[[]]})
		self.report_data.update({"upgrade_table":[[]]})

		precheck_start_time = self.report_data.get("precheck_start_time")
		precheck_end_time = self.report_data.get("precheck_end_time")
		
		elapsed_time = datetime.now() - precheck_start_time
		self.report_data.update({"elapsed_time":str(elapsed_time).split(".")[0]})

		self.report_data.update({"start_time":precheck_start_time.strftime("%H:%M:%S %d-%B-%Y")})
		self.report_data.update({"end_time":precheck_end_time.strftime("%H:%M:%S %d-%B-%Y")})

		if self.report_type is "Upgrade":
			pass;
			#precheck_elapsed_time = datetime.datetime.now() - precheck_start_time
			#self.report_data.update({"elapsed_time":str(precheck_elapsed_time).split(".")[0]})
			#self.report_data.update({"end_time":datetime.datetime.now().strftime("%H:%M:%S %d-%B-%Y")})

		
		hosts = self.report_data.get("Upgrade")

		total_mm = 0
		total_md = 0
		for single_host in hosts:
			print(single_host)
			print("=====>")
			print(single_host.get("device_type"))
			if single_host.get("device_type") == "MM":
				total_mm = total_mm + 1
			if single_host.get("device_type") == "MD":
				total_md = total_md + 1
		
		total_devices = total_md+total_mm

		self.report_data.update({"total_mm":total_mm,"total_md":total_md,"total_devices":total_devices})
		

	def final_render(self):
		self.template = Template(self.template)
		return self.template.render(**self.report_data)

	def create_report(self,c_type):
		self.create_header()
		if c_type == "Precheck":
			self.precheck_gen("Precheck")
		if c_type == "Postcheck":
			self.upgrade_gen()
			self.precheck_gen("Postcheck")
		#job_path = self.report_data.get("job_path")
		self.create_footer()
		html = self.final_render()
		return html
		#open(os.path.join(job_path,"Reports",self.report_type+".html"),"w").write(html)
