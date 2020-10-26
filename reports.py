import os
from jinja2 import Template
from datetime import datetime
import db_management


class report_gen():
	"""Used to generate the upgrade report"""
	def __init__(self,report_data,report_type):
		self.report_type = report_type
		self.report_data = report_data
		self.template_path = os.path.join(os.path.abspath('.'),"templates","report_template.html")
		self.template = Template(open(self.template_path).read())
		self.report_type = self.report_type.title()

	def precheck_gen(self):

		validation_db = self.report_data.get("validation_db")
		precheck_data = db_management.get_checklist(validation_db,"Precheck")
		precheck_data = list(map(list, precheck_data))
		print(precheck_data)
		for chk in precheck_data:
			if chk[5].find("Warning") == 0:
				chk[5] = '<span class="badge badge-warning">'+chk[5]+'</span>'
			elif chk[5].find("Failed") == 0:
				chk[5] = '<span class="badge badge-danger">'+chk[5]+'</span>'
			elif chk[5].find("Good") == 0:
				chk[5] = '<span class="badge badge-success">'+chk[5]+'</span>'
			else:
				chk[5] = '<span class="badge badge-info">'+chk[5]+'</span>'

		self.report_data.update({"precheck_table":precheck_data})


	def create_header(self):
		"""Create Report header"""

		_d = datetime.now().strftime("%H:%M:%S %d-%B-%Y")
		self.report_data.update({"report_type":self.report_type})
		self.report_data.update({"report_date":_d})
		self.report_data.update({"report_type":"report"})
		self.report_data.update({"postcheck_table":[[]]})
		self.report_data.update({"upgrade_table":[[]]})

		precheck_start_time = self.report_data.get("precheck_start_time")
		precheck_end_time = self.report_data.get("precheck_end_time")
		precheck_elapsed_time = precheck_end_time - precheck_start_time

		self.report_data.update({"elapsed_time":str(precheck_elapsed_time)})

		self.report_data.update({"start_time":precheck_start_time.strftime("%H:%M:%S %d-%B-%Y")})
		self.report_data.update({"end_time":precheck_end_time.strftime("%H:%M:%S %d-%B-%Y")})

		if self.report_type is "Upgrade":
			self.report_data.update({"end_time":postcheck_end_time.strftime("%H:%M:%S %d-%B-%Y")})

		
		hosts = self.report_data.get("Upgrade")
		
		total_devices = len(hosts)
		total_mm = 0
		total_md = 0
		for single_host in hosts:
			if single_host.get("device_type") is "MM":
				total_mm += 1
			if single_host.get("device_type") is "MD":
				total_md += 1
		
		total_devices = total_md+total_mm

		self.report_data.update({"total_mm":total_mm,"total_md":total_md,"total_devices":total_devices})

		self.precheck_gen()
		

	def final_render(self):
		return self.template.render(**self.report_data)

	def create_report(self):
		self.create_header()
		job_path = self.report_data.get("job_path")
		html = self.final_render()
		return html
		#open(os.path.join(job_path,"Reports",self.report_type+".html"),"w").write(html)
