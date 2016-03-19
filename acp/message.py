import logging
import struct
import zlib

from .exception import ACPMessageError
from .keystream import *


def _generate_acp_header_key(password):
	"""
	Encrypt password for ACP message header key field
	
	Note:
		Truncates the password at 0x20 bytes, not sure if this is the right thing to use in all cases
	
	Args:
		password (str): system password of the router (syAP)
	
	Returns:
		String containing encrypted password of proper length for the header field
	
	"""
	pw_len = 0x20
	pw_key = generate_acp_keystream(pw_len)
	
	# pad with NULLs
	pw_buf = password[:pw_len].ljust(pw_len, "\x00")
	enc_pw_buf = ""
	for i in range(pw_len):
		enc_pw_buf += chr(ord(pw_key[i]) ^ ord(pw_buf[i]))	
	
	return enc_pw_buf


class ACPMessage(object):
	"""ACP message composition and parsing"""
	
	#XXX: struct is stupid about unpacking unsigned ints > 0x7fffffff, so treat everything as signed and
	#     "cast" where necessary. Should we switch to using ctypes?
	_header_format = struct.Struct("!4s8i12x32s48x")
	_header_magic  = "acpp"
	
	header_size = _header_format.size
	
	
	def __init__(self, version, flags, unused, command, error_code, key, body=None, body_size=None):
		self.version = version
		self.flags = flags
		self.unused = unused
		self.command = command
		self.error_code = error_code
		
		# body is not specified, this is a stream header
		if body == None:
			# the body size is already specified, don't override it
			self.body_size = body_size if body_size != None else -1
			self.body_checksum = 1 # equivalent to zlib.adler32("")
		else:
			# the body size is already specified, don't override it
			self.body_size = body_size if body_size != None else len(body)
			self.body_checksum = zlib.adler32(body)
		
		self.key = key
		self.body = body
	
	
	def __str__(self):
		s =  "ACPMessage:    {0!r}\n".format(self)
		s += "body_checksum: {0:#x}\n".format(self.body_checksum)
		s += "body_size:     {0:#x}\n".format(self.body_size)
		s += "flags:         {0:#x}\n".format(self.flags)
		s += "unused:        {0:#x}\n".format(self.unused)
		s += "command:       {0:#x}\n".format(self.command)
		s += "error_code:    {0:#x}\n".format(self.error_code)
		s += "key:           {0!r}".format(self.key)
		return s
	
	
	@classmethod
	def parse_raw(cls, data):
		# bail early if there is not enough data
		if len(data) < cls.header_size:
			raise ACPMessageError("need to pass at least {0} bytes".format(cls.header_size))
		header_data = data[:cls.header_size]
		# make sure there's data beyond the header before we try to access it
		body_data = data[cls.header_size:] if len(data) > cls.header_size else None
		
		(magic, version, header_checksum, body_checksum, body_size, flags, unused, command, error_code, key) = cls._header_format.unpack(header_data)
		logging.debug("ACP message header fields, parsed not validated")
		logging.debug("magic           {0!r}".format(magic))
		logging.debug("header_checksum {0:#x}".format(header_checksum))
		logging.debug("body_checksum   {0:#x}".format(body_checksum))
		logging.debug("body_size       {0:#x}".format(body_size))
		logging.debug("flags           {0:#x}".format(flags))
		logging.debug("unused          {0:#x}".format(unused))
		logging.debug("command         {0:#x}".format(command))
		logging.debug("error_code      {0:#x}".format(error_code))
		logging.debug("key             {0!r}".format(key))
		
		if magic != cls._header_magic:
			raise ACPMessageError("bad header magic")
		
		if version not in [0x00000001, 0x00030001]:
			raise ACPMessageError("invalid version")
		
		#TODO: can we zero the header_checksum field without recreating the struct (how?)
		tmphdr = cls._header_format.pack(magic, version, 0, body_checksum, body_size, flags, unused, command, error_code, key)
		if header_checksum != zlib.adler32(tmphdr):
			raise ACPMessageError("header checksum does not match")
		
		if body_data and body_size == -1:
			raise ACPMessageError("cannot handle stream header with data attached")
		
		if body_data and body_size != len(body_data):
			raise ACPMessageError("message body size does not match available data")
		
		if body_data and body_checksum != zlib.adler32(body_data):
			raise ACPMessageError("body checksum does not match")
		
		#TODO: check flags
		
		#TODO: check status
		
		if command not in [1, 3, 4, 5, 6, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b]:
			raise ACPMessageError("unknown command")
		
		#TODO: check error code
		
		return cls(version, flags, unused, command, error_code, key, body_data, body_size)
	
	
	@classmethod
	def compose_echo_command(cls, flags, password, payload):
		return cls(0x00030001, flags, 0, 1, 0, _generate_acp_header_key(password), payload)._compose_raw_packet()
	
	
	@classmethod
	def compose_flash_primary_command(cls, flags, password, payload):
		return cls(0x00030001, flags, 0, 3, 0, _generate_acp_header_key(password), payload)._compose_raw_packet()
	
	
	@classmethod
	def compose_flash_secondary_command(cls, flags, password, payload):
		return cls(0x00030001, flags, 0, 5, 0, _generate_acp_header_key(password), payload)._compose_raw_packet()
	
	
	@classmethod
	def compose_flash_bootloader_command(cls, flags, password, payload):
		return cls(0x00030001, flags, 0, 6, 0, _generate_acp_header_key(password), payload)._compose_raw_packet()
	
	
	@classmethod
	def compose_getprop_command(cls, flags, password, payload):
		return cls(0x00030001, flags, 0, 0x14, 0, _generate_acp_header_key(password), payload)._compose_raw_packet()
	
	
	@classmethod
	def compose_setprop_command(cls, flags, password, payload):
		return cls(0x00030001, flags, 0, 0x15, 0, _generate_acp_header_key(password), payload)._compose_raw_packet()
	
	
	@classmethod
	def compose_perform_command(cls, flags, password, payload):
		return cls(0x00030001, flags, 0, 0x16, 0, _generate_acp_header_key(password), payload)._compose_raw_packet()
	
	
	@classmethod
	def compose_monitor_command(cls, flags, password, payload):
		return cls(0x00030001, flags, 0, 0x18, 0, _generate_acp_header_key(password), payload)._compose_raw_packet()
	
	
	@classmethod
	def compose_rpc_command(cls, flags, password, payload):
		return cls(0x00030001, flags, 0, 0x19, 0, _generate_acp_header_key(password), payload)._compose_raw_packet()
	
	
	@classmethod
	def compose_auth_command(cls, flags, payload):
		return cls(0x00030001, flags, 0, 0x1a, 0, _generate_acp_header_key(""), payload)._compose_raw_packet()
	
	
	@classmethod
	def compose_feat_command(cls, flags):
		return cls(0x00030001, flags, 0, 0x1b, 0, _generate_acp_header_key(""))._compose_raw_packet()
	
	
	@classmethod
	def compose_message_ex(cls, version, flags, unused, command, error_code, password, payload, payload_size):
		return cls(version, flags, unused, command, error_code, _generate_acp_header_key(password), payload, payload_size)._compose_raw_packet()
	
	
	def _compose_raw_packet(self):
		"""Compose a request from the client to ACP daemon
		
		Returns:
			String containing message to send
		
		"""
		reply = self._compose_header()
		if self.body:
			reply += self.body
		
		return reply
	
	
	def _compose_header(self):
		"""Compose the message header
		
		Returns:
			String containing header data
		
		"""
		tmphdr = self._header_format.pack(self._header_magic,
		                                  self.version,
		                                  0,
		                                  self.body_checksum,
		                                  self.body_size,
		                                  self.flags,
		                                  self.unused,
		                                  self.command,
		                                  self.error_code,
		                                  self.key)
		
		header = self._header_format.pack(self._header_magic,
		                                  self.version,
		                                  zlib.adler32(tmphdr),
		                                  self.body_checksum,
		                                  self.body_size,
		                                  self.flags,
		                                  self.unused,
		                                  self.command,
		                                  self.error_code,
		                                  self.key)
		
		return header
