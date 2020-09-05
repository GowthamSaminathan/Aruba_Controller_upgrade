import yaml
import cerberus
import sys

from marshmallow import Schema, fields,ValidationError,validates_schema,validate,INCLUDE,EXCLUDE,RAISE


class device_authentication(Schema):
	username = fields.Str(validate=validate.Length(min=1),required=True)
	password = fields.Str(validate=validate.Length(min=1),required=True)


class aos_source_schema(Schema):
	device_type = fields.Str(validate=validate.OneOf(["ftp", "tftp","local","sftp"]),required=True)
	
	local_path = fields.Str(validate=validate.Length(min=1),required=False)
	
	tftp_path = fields.Str(validate=validate.Length(min=1),required=False)
	tftp_host = fields.Str(validate=validate.Length(min=1),required=False)
	
	ftp_path = fields.Str(validate=validate.Length(min=1),required=False)
	ftp_host = fields.Str(validate=validate.Length(min=1),required=False)
	ftp_username = fields.Str(validate=validate.Length(min=1),required=False)
	ftp_password = fields.Str(validate=validate.Length(min=1),required=False)
	
	sftp_host = fields.Str(validate=validate.Length(min=1),required=False)
	sftp_username = fields.Str(validate=validate.Length(min=1),required=False)
	sftp_password = fields.Str(validate=validate.Length(min=1),required=False)
	sftp_path = fields.Str(validate=validate.Length(min=1),required=False)

	# Don't raise  ValidationError for unknown data just include it.
	class Meta:
		unknown = INCLUDE

	@validates_schema
	def validate_servers(self, data, **kwargs):
		errors = {}
		if data.get("device_type") == "local":
			# If device_type is local then it must have None local_path , path length is validated by field.str
			if data.get("local_path") == None:
				errors["local_path"] = ["Not valid path"]
		
		elif data.get("device_type") == "tftp":
			if data.get("tftp_path") == None:
				errors["tftp_path"] = ["Not Valid path"]
			if data.get("tftp_host") == None:
				errors["tftp_host"] = ["Not Valid host"]
		
		elif data.get("device_type") == "ftp":
			if data.get("ftp_path") == None:
				errors["ftp_path"] = ["Not Valid path"]
			if data.get("ftp_host") == None:
				errors["ftp_host"] = ["Not Valid host"]
			if data.get("ftp_username") == None:
				errors["ftp_username"] = ["Not Valid username"]
			if data.get("ftp_password") == None:
				errors["ftp_password"] = ["Not Valid password"]
		
		elif data.get("device_type") == "sftp":
			if data.get("sftp_path") == None:
				errors["sftp_path"] = ["Not Valid path"]
			if data.get("sftp_host") == None:
				errors["local_path"] = ["Not Valid host"]
			if data.get("sftp_host") == None:
				errors["sftp_username"] = ["Not Valid username"]
			if data.get("sftp_password") == None:
				errors["sftp_password"] = ["Not valid password"]

		else:
			raise ValidationError("Device type must be local,sftp,ftp or local")

		if errors:
			raise ValidationError(errors)

class mm_config_schema(Schema):
	
	#class Meta:
	#	unknown = INCLUDE
	
	image_file_name =  fields.Str(required=True)
	image_version =  fields.Str(required=True)
	image_build =  fields.Str(required=True)
	upgrade_disk =  fields.Str(validate=validate.OneOf(["Auto", "0", "1"]),required=True)
	CheckList = fields.List(fields.Dict(),validate=validate.Length(min=1),required=True)

class md_config_schema(Schema):
	
	#class Meta:
	#	unknown = INCLUDE
	
	image_file_name =  fields.Str(required=True)
	image_version =  fields.Str(required=True)
	image_build =  fields.Str(required=True)
	upgrade_disk =  fields.Str(validate=validate.OneOf(["Auto", "0", "1"]),required=True)
	CheckList = fields.List(fields.Dict(),validate=validate.Length(min=1),required=True)

	Pre_image_AP = fields.Boolean(required=True)
	max_ap_image_load = fields.Int(validate=validate.Range(min=1, max=250),required=False)

	@validates_schema
	def validate_max_ap_image_load(self, data, **kwargs):
		errors = {}
		if data.get("Pre_image_AP") == True:
			if type(data.get("max_ap_image_load")) != int:
				errors["max_ap_image_load"] = ["Must intiger"]
		if errors:
			raise ValidationError(errors)



class settingsschema(Schema):
	device_type = fields.Str(validate=validate.OneOf(["MM", "MD"]))
	#print(device_type)
	MM = fields.Nested(mm_config_schema,required=False)
	MD = fields.Nested(md_config_schema,required=False)
	AOS_Source = fields.Nested(aos_source_schema,required=True)
	Validate_Image_before_upgrade =  fields.Boolean(required=True)
	Validate_controller_sync_before_upgrade =  fields.Boolean(required=True)
	Validate_controller_up_before_upgrade =  fields.Boolean(required=True)
	Authentication = fields.Nested(device_authentication,required=True)

	# @validates_schema
	# def validate_mm_md_present(self, data, **kwargs):
	# 	if data["device_type"] != "MD" and data["device_type"] != "MM":
	# 		raise ValidationError("Device type must be MM or MD")

class defaultsettingschema(Schema):
	default_settings = fields.Nested(settingsschema)


class hostschema(Schema):
	hostname = fields.String()
	device_type = fields.String()
	host = fields.String()

	device_type = fields.Str(validate=validate.OneOf(["MM", "MD"]))
	#print(device_type)
	MM = fields.Nested(mm_config_schema,required=False)
	MD = fields.Nested(md_config_schema,required=False)
	AOS_Source = fields.Nested(aos_source_schema,required=True)
	Validate_Image_before_upgrade =  fields.Boolean(required=True)
	Validate_controller_sync_before_upgrade =  fields.Boolean(required=True)
	Validate_controller_up_before_upgrade =  fields.Boolean(required=True)
	Authentication = fields.Nested(device_authentication,required=True)

	image_file_name =  fields.Str(required=True)
	image_version =  fields.Str(required=True)
	image_build =  fields.Str(required=True)
	upgrade_disk =  fields.Str(validate=validate.OneOf(["Auto", "0", "1"]),required=True)
	CheckList = fields.List(fields.Dict(),validate=validate.Length(min=1),required=True)

	Pre_image_AP = fields.Boolean(required=False)
	max_ap_image_load = fields.Int(validate=validate.Range(min=1, max=250),required=False)

	# If device type is MD then Pre_image_AP required
	@validates_schema
	def validate_max_ap_image_load(self, data, **kwargs):
		errors = {}
		if data.get("device_type") == "MD":
			if data.get("Pre_image_AP") == None:
				errors["Pre_image_AP"] = ["Missing field"]
		
			if data.get("Pre_image_AP") != True:
				if type(data.get("max_ap_image_load")) != int:
					errors["max_ap_image_load"] = ["Must intiger"]
		
		if errors:
			raise ValidationError(errors)



	# @validates_schema
	# def validate_mm_md_present(self, data, **kwargs):
	# 	if data["device_type"] != "MD" and data["device_type"] != "MM":
	# 		raise ValidationError("Device type must be MM or MD")

class upgradeschema(Schema):
	#Upgrade = fields.List(fields.Dict(), required=True,min=10000)
	Upgrade = fields.List(fields.Nested(hostschema))
	#email = fields.Email()
	#created_at = fields.DateTime()

def validate_create_yaml(config_yaml):
	try:
		
		config_json = yaml.load(config_yaml,Loader=yaml.Loader)
		upgrade_host = config_json.get("Upgrade")
		default_settings = config_json.get("default_settings")
		
		for host in upgrade_host:
			#print(host)
			AOS_Source = default_settings.get("AOS_Source")
			if host.get("AOS_Source") == None:
				host.update({"AOS_Source":AOS_Source})

			Authentication = default_settings.get("Authentication")
			if host.get("Authentication") == None:
				host.update({"Authentication":Authentication})

			Validate_Image_before_upgrade = default_settings.get("Validate_Image_before_upgrade")
			if host.get("Validate_Image_before_upgrade") == None:
				host.update({"Validate_Image_before_upgrade":Validate_Image_before_upgrade})

			Validate_controller_sync_before_upgrade = default_settings.get("Validate_controller_sync_before_upgrade")
			if host.get("Validate_controller_sync_before_upgrade") == None:
				host.update({"Validate_controller_sync_before_upgrade":Validate_controller_sync_before_upgrade})

			Validate_controller_up_before_upgrade = default_settings.get("Validate_controller_up_before_upgrade")
			if host.get("Validate_controller_up_before_upgrade") == None:
				host.update({"Validate_controller_up_before_upgrade":Validate_controller_up_before_upgrade})


			host_type = host.get("device_type")
			host_type_settings = default_settings.get(host_type)

			image_file_name = host_type_settings.get("image_file_name")
			if host.get("image_file_name") == None:
				host.update({"image_file_name":image_file_name})

			image_version = host_type_settings.get("image_version")
			if host.get("image_version") == None:
				host.update({"image_version":image_version})

			image_build = host_type_settings.get("image_build")
			if host.get("image_build") == None:
				host.update({"image_build":image_build})

			upgrade_disk = host_type_settings.get("upgrade_disk")
			if host.get("upgrade_disk") == None:
				host.update({"upgrade_disk":upgrade_disk})

			Pre_image_AP = host_type_settings.get("Pre_image_AP")
			if host_type == "MD" and host.get("Pre_image_AP") == None:
				host.update({"Pre_image_AP":Pre_image_AP})

			max_ap_image_load = host_type_settings.get("max_ap_image_load")
			if host_type == "MD" and host.get("max_ap_image_load") == None:
				host.update({"max_ap_image_load":max_ap_image_load})

			CheckList = host_type_settings.get("CheckList")
			if host.get("CheckList") == None:
				host.update({"CheckList":CheckList})

			#if type(host_type_settings) == dict:
			#	host.update(host_type_settings)


		config_json.update({"Upgrade":upgrade_host})
		validate = upgradeschema().load(config_json,unknown=EXCLUDE)
		#print(validate)
		gen_yaml = yaml.safe_dump(config_json,default_flow_style=False)
		return {"status":"success","config_yaml":gen_yaml}
	except ValidationError as err:
		print(err.messages)
		return {"status": "error","error":err.messages}
		#print(err.valid_data)

	except Exception as e:
		print("validate_create_yaml: "+str(e))