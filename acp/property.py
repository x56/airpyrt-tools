import logging
import pprint
import struct

from .cflbinary import CFLBinaryPListParser
from .exception import ACPPropertyError


_acp_properties = [
	# Uncomment and fill out relevant fields to add support for a property
	# Properties must be in the following format:
	# (name, type, description, validation), where
	# name (required) is a 4 character string,
	# type (required) is a valid property type (str, dec, hex, log, mac, cfb, bin)
	# description (required) is a short, one-line description of the property
	# validation (optional) is eval()d to verify the input value for setting a property
	("buil","str","Build string?",""),
	("DynS","cfb","DNS",""),
	#("cfpf","","",""),
	#("cloC","","",""),
	#("cloD","","",""),
	#("conf","","",""),
	("fire","cfb","Firewall???",""),
	#("prob","","",""),
	("srcv","str","Source Version",""),
	("syNm","str","Device name",""),
	#("syDN","","",""),
	#("syPI","","",""),
	("syPW","str","Router administration password",""),
	("syPR","str","syPR string???",""),
	("syGP","str","Router guest password???",""),
	#("syCt","","",""),
	#("syLo","","",""),
	("syDs","str","System description",""),
	("syVs","str","System version",""),
	("syVr","str","System version???",""),
	("syIn","str","System information???",""),
	("syFl","hex","????",""),
	("syAM","str","Model Identifier",""),
	("syAP","dec","Product ID",""),
	("sySN","str","Apple Serial Number",""),
	#("ssSN","","",""),
	#("sySK","","",""),
	("ssSK","str","Apple SKU",""),
	#("syRe","","",""),
	("syLR","cfb","syLR Blob",""),
	("syAR","cfb","syAR Blob",""),
	("syUT","dec","System Uptime",""),
	#("minV","","",""),
	("minS","str","apple-minver",""),
	("chip","str","SoC Description",""),
	#("card","","",""),
	#("memF","","",""),
	#("pool","","",""),
	#("tmpC","","",""),
	#("RPMs","","",""),
	("sySI","cfb","System Info Blob?",""),
	#("fDCY","","",""),
	("TMEn","hex","TMEn???",""),
	("CLTM","cfb","CLTM???",""),
	#("sPLL","","",""),
	#("syTL","","",""),
	#("syST","","",""),
	("sySt","cfb","System Status",""),
	#("syIg","","",""),
	("syBL","str","Bootloader vesrsion string",""),
	("time","dec","System time",""),
	("timz","cfb","Timezone Config Blob",""),
	("usrd","cfb","usrd???",""),
	#("uuid","","",""),
	#("drTY","","",""),
	#("sttE","","",""),
	#("sttF","","",""),
	#("stat","","",""),
	#("sRnd","","",""),
	#("Accl","","",""),
	("dSpn","cfb","Disk spin status?",""),
	("syMS","str","MLB Serial Number",""),
	#("IGMP","","",""),
	("diag","bin","diag???",""),
	#("paFR","","",""),
	("raNm","str","Radio Name",""),
	#("raCl","","",""),
	#("raSk","","",""),
	#("raWM","","",""),
	#("raEA","","",""),
	#("raWE","","",""),
	#("raCr","","",""),
	#("raKT","","",""),
	#("raNN","","",""),
	#("raGK","","",""),
	#("raHW","","",""),
	#("raCM","","",""),
	#("raRo","","",""),
	#("raCA","","",""),
	#("raCh","","",""),
	#("rCh2","","",""),
	#("raWC","","",""),
	#("raDe","","",""),
	#("raMu","","",""),
	#("raLC","","",""),
	#("raLF","","",""),
	#("ra1C","","",""),
	#("raVs","","",""),
	("raMA","mac","Radio MAC Address",""),
	#("raM2","","",""),
	#("raMO","","",""),
	#("raLO","","",""),
	#("raDS","","",""),
	#("raNA","","",""),
	#("raWB","","",""),
	#("raIS","","",""),
	#("raMd","","",""),
	#("raPo","","",""),
	#("raPx","","",""),
	#("raTr","","",""),
	#("raDt","","",""),
	#("raFC","","",""),
	#("raEC","","",""),
	#("raMX","","",""),
	#("raIE","","",""),
	#("raII","","",""),
	#("raB0","","",""),
	#("raB1","","",""),
	#("raB2","","",""),
	#("raSt","","",""),
	#("APSR","","",""),
	#("raTX","","",""),
	#("raRX","","",""),
	#("raAC","","",""),
	("raSL","cfb","Radios list?",""),
	#("raMI","","",""),
	#("raST","","",""),
	#("raDy","","",""),
	#("raEV","","",""),
	#("rTSN","","",""),
	("raSR","cfb","Radio scan results?",""),
	#("eaRA","","",""),
	("WiFi","cfb","Wifi configuration?",""),
	("rCAL","cfb","Radio calibration data?",""),
	#("moPN","","",""),
	#("moAP","","",""),
	#("moUN","","",""),
	#("moPW","","",""),
	#("moIS","","",""),
	#("moLS","","",""),
	#("moLI","","",""),
	#("moID","","",""),
	#("moDT","","",""),
	#("moPD","","",""),
	#("moAD","","",""),
	#("moCC","","",""),
	#("moCR","","",""),
	#("moCI","","",""),
	#("^moM","","",""),
	#("moVs","","",""),
	#("moMP","","",""),
	#("moMF","","",""),
	#("moFV","","",""),
	#("pdFl","","",""),
	#("pdUN","","",""),
	#("pdPW","","",""),
	#("pdAR","","",""),
	#("pdID","","",""),
	#("pdMC","","",""),
	#("peSN","","",""),
	#("peUN","","",""),
	#("pePW","","",""),
	#("peSC","","",""),
	#("peAC","","",""),
	#("peID","","",""),
	#("peAO","","",""),
	("waCV","bin","WAN Config Mode?",""),
	("waIn","bin","WAN Interface Mode?",""),
	#("waD1","","",""),
	#("waD2","","",""),
	#("waD3","","",""),
	#("waC1","","",""),
	#("waC2","","",""),
	#("waC3","","",""),
	("waIP","bin","WAN IP",""),
	#("waSM","","",""),
	("waRA","bin","WAN Upstream Gateway IP",""),
	#("waDC","","",""),
	#("waDS","","",""),
	("waMA","mac","WAN MAC Address",""),
	#("waMO","","",""),
	#("waDN","","",""),
	#("waCD","","",""),
	#("waIS","","",""),
	#("waNM","","",""),
	#("waSD","","",""),
	#("waFF","","",""),
	#("waRO","","",""),
	#("waW1","","",""),
	#("waW2","","",""),
	#("waW3","","",""),
	#("waLL","","",""),
	#("waUB","","",""),
	("waDI","cfb","WAN DHCP Info?",""),
	#("laCV","","",""),
	#("laIP","","",""),
	#("laSM","","",""),
	#("laRA","","",""),
	#("laDC","","",""),
	#("laDS","","",""),
	#("laNA","","",""),
	("laMA","mac","LAN MAC Address",""),
	#("laIS","","",""),
	#("laSD","","",""),
	#("laIA","","",""),
	#("gn6?","","",""),
	#("gn6A","","",""),
	#("gn6P","","",""),
	#("dhFl","","",""),
	#("dhBg","","",""),
	#("dhEn","","",""),
	#("dhSN","","",""),
	#("dhRo","","",""),
	#("dhLe","","",""),
	#("dhMg","","",""),
	#("dh95","","",""),
	("DRes","cfb","DHCP Reservations",""),
	#("dhWA","","",""),
	#("dhDS","","",""),
	#("dhDB","","",""),
	#("dhDE","","",""),
	#("dhDL","","",""),
	("dhSL","cfb","DHCP Server leases?",""),
	#("gnFl","","",""),
	#("gnBg","","",""),
	#("gnEn","","",""),
	#("gnSN","","",""),
	#("gnRo","","",""),
	#("gnLe","","",""),
	#("gnMg","","",""),
	#("gn95","","",""),
	#("gnDi","","",""),
	#("naFl","","",""),
	#("naBg","","",""),
	#("naEn","","",""),
	#("naSN","","",""),
	#("naRo","","",""),
	#("naAF","","",""),
	#("nDMZ","","",""),
	#("pmPI","","",""),
	#("pmPS","","",""),
	#("pmPR","","",""),
	#("pmTa","","",""),
	#("acEn","","",""),
	#("acTa","","",""),
	("tACL","cfb","Timed Access Control",""),
	#("wdFl","","",""),
	#("wdLs","","",""),
	#("dWDS","","",""),
	#("cWDS","","",""),
	#("dwFl","","",""),
	#("raFl","","",""),
	#("raI1","","",""),
	#("raTm","","",""),
	#("raAu","","",""),
	#("raAc","","",""),
	#("raSe","","",""),
	#("raRe","","",""),
	#("raF2","","",""),
	#("raI2","","",""),
	#("raT2","","",""),
	#("raU2","","",""),
	#("raC2","","",""),
	#("raS2","","",""),
	#("raR2","","",""),
	#("raCi","","",""),
	("ntSV","str","NTP Server Hostname",""),
	#("ntpC","","",""),
	#("smtp","","",""),
	#("slog","","",""),
	#("slgC","","",""),
	#("slCl","","",""),
	("slvl","dec","System log severity level?",""),
	#("slfl","","",""),
	("logm","log","System log data",""),
	#("snAF","","",""),
	#("snLW","","",""),
	#("snLL","","",""),
	#("snRW","","",""),
	#("snWW","","",""),
	#("snRL","","",""),
	#("snWL","","",""),
	#("snCS","","",""),
	#("srtA","","",""),
	#("srtF","","",""),
	#("upsF","","",""),
	#("usbF","","",""),
	("USBi","cfb","USB Info",""),
	#("USBL","","",""),
	#("USBR","","",""),
	#("USBO","","",""),
	#("USBs","","",""),
	#("USBo","","",""),
	#("USBh","","",""),
	#("USBb","","",""),
	#("USBn","","",""),
	("prni","cfb","Printer Info?",""),
	#("prnM","","",""),
	#("prnI","","",""),
	#("prnR","","",""),
	#("RUdv","","",""),
	#("RUfl","","",""),
	("MaSt","cfb","USB Mass Storage Info",""),
	#("SMBw","","",""),
	#("SMBs","","",""),
	#("fssp","","",""),
	#("diSD","","",""),
	#("diCS","","",""),
	#("deSt","","",""),
	#("daSt","","",""),
	#("dmSt","","",""),
	#("adNm","","",""),
	#("adBD","","",""),
	#("adAD","","",""),
	#("adHU","","",""),
	#("IDNm","","",""),
	("seFl","bin","????",""), #????
	#("nvVs","","",""),
	#("dbRC","","",""),
	("dbug","hex","Debug flags","0 <= value <= 0xFFFFFFFF"),
	#("dlvl","","",""),
	#("dcmd","","",""),
	#("dsps","","",""),
	#("logC","","",""),
	#("cver","","",""),
	("ctim","hex","ctim???",""),
	#("svMd","","",""),
	#("serM","","",""),
	#("serT","","",""),
	#("emNo","","",""),
	#("effF","","",""),
	#("LLnk","","",""),
	#("WLnk","","",""),
	#("PHYS","","",""),
	#("PHYN","","",""),
	#("Rnfo","","",""),
	#("evtL","","",""),
	#("isAC","","",""),
	#("Adet","","",""),
	("Prof","cfb","Restore Profile Blob",""),
	#("maAl","","",""),
	#("maPr","","",""),
	#("leAc","","",""),
	#("APID","","",""),
	#("AAU ","","",""),
	("lcVs","str","lcVs Version String?",""),
	#("lcVr","","",""),
	#("lcmV","","",""),
	#("lcMV","","",""),
	#("iMTU","","",""),
	("wsci","cfb","wsci Blob",""),
	#("FlSu","","",""),
	("OTPR","hex","machdep.otpval",""),
	("acRB","dec","Reboot device flag","value == 0"),
	("acRI","dec","Reload services??","value == 0"),
	#("acPC","","",""),
	#("acDD","","",""),
	#("acPD","","",""),
	#("acPG","","",""),
	#("acDS","","",""),
	#("acFN","","",""),
	#("acRP","","",""),
	("acRN","dec","Resets something... (?)","value == 0"),
	("acRF","dec","Reset to factory defaults","value == 0"),
	#("MdmH","","",""),
	#("dirf","","",""),
	#("Afrc","","",""),
	#("lebl","","",""),
	#("lebs","","",""),
	("LEDc","dec","LED color/pattern","0 <= value <= 3"),
	#("acEf","","",""),
	#("invr","","",""),
	#("FLSH","","",""),
	#("acPL","","",""),
	#("rReg","","",""),
	#("dReg","","",""),
	("GPIs","bin","GPIOs values","len(value) == 8"),
	#("play","","",""),
	#("paus","","",""),
	#("ffwd","","",""),
	#("rwnd","","",""),
	#("itun","","",""),
	#("plls","","",""),
	#("User","","",""),
	#("Pass","","",""),
	#("itIP","","",""),
	#("itpt","","",""),
	#("daap","","",""),
	#("song","","",""),
	#("arti","","",""),
	#("albm","","",""),
	#("volm","","",""),
	#("rvol","","",""),
	#("Tcnt","","",""),
	#("Bcnt","","",""),
	#("shfl","","",""),
	#("rept","","",""),
	#("auPr","","",""),
	#("auJD","","",""),
	#("auNN","","",""),
	#("auNP","","",""),
	#("aFrq","","",""),
	#("aChn","","",""),
	#("aLvl","","",""),
	#("aPat","","",""),
	#("aSta","","",""),
	#("aStp","","",""),
	#("auCC","","",""),
	#("acmp","","",""),
	#("aenc","","",""),
	#("anBf","","",""),
	#("aWan","","",""),
	#("auRR","","",""),
	#("auMt","","",""),
	#("aDCP","","",""),
	#("DCPc","","",""),
	#("DACP","","",""),
	#("DCPi","","",""),
	#("auSl","","",""),
	#("auFl","","",""),
	("fe01","hex","????",""),
	("feat","str","Supported features?",""),
	("prop","str","Valid acp properties",""),
	("hw01","hex","????",""),
	#("fltr","","",""),
	#("wdel","","",""),
	#("plEB","","",""),
	#("rWSC","","",""),
	#("uDFS","","",""),
	#("dWPA","","",""),
	#("dpFF","","",""),
	#("duLF","","",""),
	#("ieHT","","",""),
	#("dwlX","","",""),
	#("dd11","","",""),
	#("dRdr","","",""),
	#("dotD","","",""),
	#("dotH","","",""),
	#("dPwr","","",""),
	#("wlBR","","",""),
	#("iTIM","","",""),
	#("idAG","","",""),
	#("mvFL","","",""),
	#("mvFM","","",""),
	#("dPPP","","",""),
	#("!mta","","",""),
	#("minR","","",""),
	#("SpTr","","",""),
	#("dRBT","","",""),
	#("dRIR","","",""),
	("pECC","cfb","PCIe ECC Blob?",""),
	#("fxEB","","",""),
	#("fxID","","",""),
	#("fuup","","",""),
	#("fust","","",""),
	#("fuca","","",""),
	("fugp","str","Firmware upgrade progress",""),
	("cks0","hex","Bootloader Flash Checksum",""),
	("cks1","hex","Primary Flash Checksum",""),
	("cks2","hex","Secondary Flash Checksum",""),
	#("ddBg","","",""),
	#("ddEn","","",""),
	#("ddIn","","",""),
	#("ddSm","","",""),
	#("ddEC","","",""),
	#("ddFE","","",""),
	#("ddSR","","",""),
	#("6cfg","","",""),
	#("6aut","","",""),
	#("6Qpd","","",""),
	#("6Wad","","",""),
	#("6Wfx","","",""),
	#("6Wgw","","",""),
	#("6Wte","","",""),
	#("6Lfw","","",""),
	#("6Lad","","",""),
	#("6Lfx","","",""),
	#("6sfw","","",""),
	#("6pmp","","",""),
	#("6trd","","",""),
	#("6sec","","",""),
	#("6fwl","","",""),
	#("6NS1","","",""),
	#("6NS2","","",""),
	#("6NS3","","",""),
	#("6ahr","","",""),
	#("6dhs","","",""),
	#("6dso","","",""),
	#("6PDa","","",""),
	#("6PDl","","",""),
	#("6vlt","","",""),
	#("6plt","","",""),
	#("6CWa","","",""),
	#("6CWp","","",""),
	#("6CWg","","",""),
	#("6CLa","","",""),
	#("6NSa","","",""),
	#("6NSb","","",""),
	#("6NSc","","",""),
	#("6CPa","","",""),
	#("6CPl","","",""),
	#("6!at","","",""),
	("rteI","cfb","rteI Blob",""),
	#("PCLI","","",""),
	#("dxEM","","",""),
	#("dxID","","",""),
	#("dxAI","","",""),
	#("dxIP","","",""),
	#("dxOA","","",""),
	#("dxIA","","",""),
	#("dxC1","","",""),
	#("dxP1","","",""),
	#("dxC2","","",""),
	#("dxP2","","",""),
	#("bjFl","","",""),
	#("bjSd","","",""),
	#("bjSM","","",""),
	#("wbEn","","",""),
	#("wbHN","","",""),
	#("wbHU","","",""),
	#("wbHP","","",""),
	#("wbRD","","",""),
	#("wbRU","","",""),
	#("wbRP","","",""),
	#("wbAC","","",""),
	#("dMac","","",""),
	#("iCld","","",""),
	#("iCLH","","",""),
	#("iCLB","","",""),
	#("SUEn","","",""),
	#("SUAI","","",""),
	#("SUFq","","",""),
	#("SUSv","","",""),
	#("suPR","","",""),
	#("msEn","","",""),
	#("trCo","","",""),
	#("EZCF","","",""),
	#("ezcf","","",""),
	#("gVID","","",""),
	#("wcfg","","",""),
	#("awce","","",""),
	#("wcgu","","",""),
	#("wcgs","","",""),
	#("awcc","","",""),
	]

def _generate_acp_property_dict():	
	props = {}
	for (name, type, description, validation) in _acp_properties:
		# basic validation of tuples
		assert len(name) == 4, "bad name in _acp_properties list: {0}".format(name)
		assert type in ["str", "dec", "hex", "log", "mac", "cfb", "bin"], "bad type in _acp_properties list for name: {0}".format(name)
		assert description, "missing description in _acp_properties list for name: {0}".format(name)
		props[name] = dict(type=type, description=description, validation=validation)
	return props


class ACPPropertyInitValueError(ACPPropertyError):
	pass


class ACPProperty(object):
	_acpprop = _generate_acp_property_dict()
	
	_element_header_format = struct.Struct("!4s2I")
	element_header_size = _element_header_format.size
	
	
	def __init__(self, name=None, value=None):
		# handle "null" property packed name and value first
		if name == "\x00\x00\x00\x00" and value == "\x00\x00\x00\x00":
			name = None
			value = None
		
		if name and name not in self.get_supported_property_names():
			raise ACPPropertyError("invalid property name passed to initializer: {0}".format(name))
		
		if value is not None:
			# accept value as packed binary string or Python type
			prop_type = self.get_property_info_string(name, "type")
			_init_handler_name = "_init_{0}".format(prop_type)
			assert hasattr(self, _init_handler_name), "missing init handler for \"{0}\" property type".format(prop_type)
			_init_handler = getattr(self, _init_handler_name)
			
			logging.debug("old value: {0!r} type: {1}".format(value, type(value)))
			try:
				value = _init_handler(value)
			except ACPPropertyInitValueError as e:
				raise ACPPropertyError("{0!s} provided for \"{1}\" property type: {2!r}".format(e, prop_type, value))
			logging.debug("new value: {0!r} type: {1}".format(value, type(value)))
			
			#XXX: this is still really hacky, should probably do something with anonymous functions or introspection
			validation_expr = self.get_property_info_string(name, "validation")
			if validation_expr and not eval(validation_expr):
				raise ACPPropertyError("invalid value passed to initializer for property \"{0}\": {1}".format(name, repr(value)))
		
		self.name = name
		self.value = value
	
	def _init_dec(self, value):
		if   type(value) == int:
			return value
		elif type(value) == str:
			try:
				return struct.unpack("!I", value)[0]
			except:
				raise ACPPropertyInitValueError("invalid packed binary string")
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	def _init_hex(self, value):
		if   type(value) == int:
			return value
		elif type(value) == str:
			try:
				return struct.unpack("!I", value)[0]
			except:
				raise ACPPropertyInitValueError("invalid packed binary string")
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	def _init_mac(self, value):
		if type(value) == str:
			# first, try as packed binary value
			if len(value) == 6:
				return value
			# second, attempt to unpack colon delimited value
			mac_bytes = value.split(":")
			if len(mac_bytes) == 6:
				try:
					return "".join(mac_bytes).decode("hex")
				except TypeError:
					raise ACPPropertyInitValueError("non-hex digit in value")
			# fallthrough
			raise ACPPropertyInitValueError("invalid value")
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	def _init_bin(self, value):
		if type(value) == str:
			return value
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	def _init_cfb(self, value):
		if type(value) == str:
			return value
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	def _init_log(self, value):
		if type(value) == str:
			return value
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	def _init_str(self, value):
		if type(value) == str:
			return value
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	
	def __repr__(self):
		#XXX: return tuple or dict?
		return repr((self.name, self.value))
	
	
	#TODO: make this function return something other than the formatted value of the property...I keep getting confused by its current shittiness
	def __str__(self):
		#XXX: is this the correct thing to do?
		if self.name is None or self.value is None:
			return ""
		
		prop_type = self.get_property_info_string(self.name, "type")
		_format_handler_name = "_format_{0}".format(prop_type)
		assert hasattr(self, _format_handler_name), "missing format handler for \"{0}\" property type".format(prop_type)
		return getattr(self, _format_handler_name)(self.value)
	
	def _format_dec(self, value):
		return str(value)
	
	def _format_hex(self, value):
		return hex(value)
	
	def _format_mac(self, value):
		mac_bytes = []
		for i in range(6):
			mac_bytes.append(value[i].encode("hex"))
		return "{0}:{1}:{2}:{3}:{4}:{5}".format(*mac_bytes)
	
	def _format_bin(self, value):
		return value.encode("hex")
	
	def _format_cfb(self, value):
		return pprint.pformat(CFLBinaryPListParser.parse(value))
	
	def _format_log(self, value):
		s = ""
		for line in value.strip("\x00").split("\x00"):
			s += "{0}\n".format(line)
		return s
	
	def _format_str(self, value):
		return value
	
	
	@classmethod
	def get_supported_property_names(cls):
		props = []
		for name in cls._acpprop:
			props.append(name)
		return props
	
	
	@classmethod
	def get_property_info_string(cls, prop_name, key):
		#XXX: should we do this differently?
		if prop_name is None:
			return None
		if prop_name not in cls._acpprop:
			logging.error("property \"{0}\" not supported".format(prop_name))
			return None
		prop_info = cls._acpprop[prop_name]
		if key not in prop_info:
			logging.error("invalid property info key \"{0}\"".format(key))
			return None
		return prop_info[key]
	
	
	@classmethod
	def parse_raw_element(cls, data):
		name, flags, size = cls.parse_raw_element_header(data[:cls.element_header_size])
		#TODO: handle flags!???
		return cls(name, data[cls.element_header_size:])
	
	
	@classmethod
	def parse_raw_element_header(cls, data):
		try:
			return cls._element_header_format.unpack(data)
		except struct.error:
			raise ACPPropertyError("failed to parse property element header")
	
	
	@classmethod
	def compose_raw_element(cls, flags, property):
		#TODO: handle flags!???
		#XXX: handles "null" name or value first, but this is currently garbage
		name = property.name if property.name is not None else "\x00\x00\x00\x00"
		value = property.value if property.value is not None else "\x00\x00\x00\x00"
		if   type(value) == int:
			st = struct.Struct(">I")
			#XXX: this could throw an exception, we need to range check int/hex values to ensure they pack into 32 bits still
			return cls.compose_raw_element_header(name, flags, st.size) + st.pack(value)
		elif type(value) == str:
			return cls.compose_raw_element_header(name, flags, len(value)) + value
		else:
			raise ACPPropertyError("unhandled property type for raw element composition")
	
	
	@classmethod
	def compose_raw_element_header(cls, name, flags, size):
		try:
			return cls._element_header_format.pack(name, flags, size)
		except struct.error:
			raise ACPPropertyError("failed to compose property header")
