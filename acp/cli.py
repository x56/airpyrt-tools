import argparse
import logging
import os.path
import sys
import time

from collections import OrderedDict

from .basebinary import *
from .client import ACPClient
from .exception import *
from .property import ACPProperty


class _ArgParser(argparse.ArgumentParser):
	def error(self, message):
		sys.stderr.write("error: {0}\n".format(message))
		#self.print_help()
		sys.exit(2)


def _cmd_not_implemented(*unused):
	raise ACPCommandLineError("command handler not implemented")

def _cmd_listprop(unused):
	print "\nSupported properties:\n"
	prop_names = ACPProperty.get_supported_property_names()
	for name in prop_names:
		print "{0}: {1}".format(name, ACPProperty.get_property_info_string(name, "description"))
	print

def _cmd_helpprop(args):
	prop_name = args.pop()
	description = ACPProperty.get_property_info_string(prop_name, "description")
	prop_type = ACPProperty.get_property_info_string(prop_name, "type")
	validation = ACPProperty.get_property_info_string(prop_name, "validation")
	s = "{0} ({1}".format(description, prop_type)
	if validation:
		s += ", {0})".format(validation)
	else:
		s += ")"
	print s

def _cmd_getprop(client, args):
	prop_name = args.pop()
	prop = client.get_properties([prop_name])
	if len(prop):
		print ACPProperty(prop_name, prop[0].value)

def _cmd_setprop(client, args):
	prop_name, prop_value = args
	prop_type = ACPProperty.get_property_info_string(prop_name, "type")
	prop = ACPProperty()
	if prop_type == "dec":
		try:
			prop = ACPProperty(prop_name, int(prop_value))
		except ValueError:
			logging.error("value for \"{0}\" has the wrong type, should be {0}".format(prop_name, prop_type))
	elif prop_type == "hex":
		try:
			#XXX: this is not the right way to do exceptions
			prop = ACPProperty(prop_name, int(prop_value, 16))
		except ValueError:
			logging.error("value for \"{0}\" has the wrong type, should be {0}".format(prop_name, prop_type))
	elif prop_type == "mac":
		#XXX: not catching our exception
		prop = ACPProperty(prop_name, prop_value)
	elif prop_type == "bin":
		prop = ACPProperty(prop_name, prop_value.decode("hex"))
	elif prop_type == "str":
		prop = ACPProperty(prop_name, prop_value)
	elif prop_type in ["cfb", "log"]:
		logging.error("unsupported prop type: {0}".format(prop_type))
	client.set_properties({prop_name : prop})

def _cmd_dumpprop(client, unused):
	prop_names = ACPProperty.get_supported_property_names()
	properties = client.get_properties(prop_names)
	for prop in properties:
		padded_description = ACPProperty.get_property_info_string(prop.name, "description").ljust(32, " ")
		print "{0}: {1}".format(padded_description, prop)

def _cmd_acpprop(client, unused):
	props_reply = client.get_properties(["prop"])
	props_raw = props_reply[0].value
	props = ""
	for i in range(len(props_raw) / 4):
		props += "{0}\n".format(props_raw[i*4:i*4+4])
	print props

def _cmd_dump_syslog(client, unused):
	print "{0}".format(client.get_properties(["logm"])[0])

def _cmd_reboot(client, unused):
	print "Rebooting device"	
	client.set_properties({"acRB" : ACPProperty("acRB", 0)})

def _cmd_factory_reset(client, unused):
	print "Performing factory reset"	
	client.set_properties(OrderedDict([("acRF",ACPProperty("acRF", 0)), ("acRB",ACPProperty("acRB", 0))]))

def _cmd_flash_primary(client, args):
	fw_path = args.pop()
	if os.path.exists(fw_path):
		with open(fw_path, "rb") as fw_file:
			fw_data = fw_file.read()
		print "Flashing primary firmware partition"
		client.flash_primary(fw_data)
	else:
		logging.error("Basebinary not readable at path: {0}".format(fw_path))

def _cmd_do_feat_command(client, unused):
	print client.get_features()

def _cmd_decrypt(args):
	(inpath, outpath) = args
	with open(inpath, "rb") as infile:
		indata = infile.read()
	
	#XXX: lazy, fixme
	try:
		outdata = Basebinary.parse(indata)
	except BasebinaryError:
		raise
	else:
		with open(outpath, "wb") as outfile:
			outfile.write(outdata)

def _cmd_extract(args):
	(inpath, outpath) = args
	with open(inpath, "rb") as infile:
		indata = infile.read()
	
	#XXX: lazy, fixme
	try:
		outdata = Basebinary.extract(indata)
	except BasebinaryError:
		raise
	else:
		with open(outpath, "wb") as outfile:
			outfile.write(outdata)

def _cmd_srp_test(client, unused):
	print "SRP testing"
	client.authenticate_AppleSRP()
	client.close()


def main():
	#TODO: add CLI arg for verbosity
	logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
	
	parser = _ArgParser()
	
	parameters_group = parser.add_argument_group("AirPort client parameters")
	parameters_group.add_argument("-t", "--target", metavar="address", help="IP address or hostname of the target router")
	parameters_group.add_argument("-p", "--password", metavar="password", help="router admin password")
	
	airport_client_group = parser.add_argument_group("AirPort client commands")
	airport_client_group.add_argument("--listprop", action="store_const", const=True, help="list supported properties")
	airport_client_group.add_argument("--helpprop", metavar="property", nargs=1, help="print the description of the specified property")
	airport_client_group.add_argument("--getprop", metavar="property", nargs=1, help="get the value of the specified property")
	airport_client_group.add_argument("--setprop", metavar=("property", "value"), nargs=2, help="set the value of the specified property")
	airport_client_group.add_argument("--dumpprop", action="store_const", const=True, help="dump values of all supported properties")
	airport_client_group.add_argument("--acpprop", action="store_const", const=True, help="get acp acpprop list")
	airport_client_group.add_argument("--dump-syslog", action="store_const", const=True, help="dump the router system log")
	airport_client_group.add_argument("--reboot", action="store_const", const=True, help="reboot device")
	airport_client_group.add_argument("--factory-reset", action="store_const", const=True, help="RESET EVERYTHING and reboot; you have been warned!")
	airport_client_group.add_argument("--flash-primary", metavar="firmware_path", nargs=1, help="flash primary partition firmware")
	airport_client_group.add_argument("--do-feat-command", action="store_const", const=True, help="send 0x1b (feat) command")
	
	basebinary_group = parser.add_argument_group("Basebinary commands")
	basebinary_group.add_argument("--decrypt", metavar=("inpath", "outpath"), nargs=2, help="decrypt the basebinary")
	basebinary_group.add_argument("--extract", metavar=("inpath", "outpath"), nargs=2, help="extract the gzimg contents")
	
	test_group = parser.add_argument_group("Test arguments")
	test_group.add_argument("--srp-test", action="store_const", const=True, help="SRP (requires OS X)")
	
	args_dict = vars(parser.parse_args())
	
	#TODO: give each element a dict containing parameter requirements/argparse infos, then generate parser based on this
	commands = {
		"listprop": "local",
		"helpprop": "local",
		"getprop": "remote_admin",
		"setprop": "remote_admin",
		"dumpprop": "remote_admin",
		"acpprop": "remote_admin",
		"dump_syslog": "remote_admin",
		"reboot": "remote_admin",
		"factory_reset": "remote_admin",
		"flash_primary": "remote_admin",
		"do_feat_command": "remote_noauth",
		"decrypt": "local",
		"extract": "local",
		"srp_test": "remote_admin",
		}
	
	target = args_dict["target"]
	password = args_dict["password"]
	command_args = {k: v for k, v in args_dict.items() if k in commands and v is not None}
	
	if len(command_args) == 0:
		logging.error("must specify a command")
		
	elif len(command_args) == 1:
		#TODO: clean this up a bit
		cmd, arg = command_args.popitem()
		assert commands[cmd] in ["local", "remote_noauth", "remote_admin"], "unknown command type \"{0}\"".format(commands[cmd])
		cmd_handler_name = "_cmd_{0}".format(cmd)
		cmd_handler = globals().get(cmd_handler_name, _cmd_not_implemented)
		
		if commands[cmd] == "local":
			cmd_handler(arg)
		
		if commands[cmd] == "remote_noauth":
			if target is not None:
				c = ACPClient(target)
				c.connect()
				cmd_handler(c, arg)
				c.close()
			else:
				logging.error("must specify a target")
		
		if commands[cmd] == "remote_admin":
			if target is not None and password is not None:
				c = ACPClient(target, password)
				c.connect()
				cmd_handler(c, arg)
				c.close()
			else:
				logging.error("must specify a target and administrator password")
				
	else:
		logging.error("multiple commands not supported, choose only one")
