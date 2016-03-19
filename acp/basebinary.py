import logging
import os.path
import struct
import zlib

from Crypto.Cipher import AES

#XXX: ugh...
from .misc import cast_u32

# hardcoded 128 bit values
# 107: 52 49 C3 51 02 8B F1 FD 2B D1 84 9E 28 B2 3F 24
# 108: BB 7D EB 09 70 D8 EE 2E 00 FA 46 CB 1C 3C 09 8E
# 115: 10 75 E8 06 F4 77 0C D4 76 3B D2 85 A6 4E 91 74
# 120: 68 8C DD 3B 1B 6B DD A2 07 B6 CE C2 73 52 92 D2

_basebinary_keys = {
	#3   : "",
	#102 : "",
	#104 : "",
	#105 : "",
	#106 : "",
	107 : "5249c351028bf1fd2bd1849e28b23f24",
	108 : "bb7deb0970d8ee2e00fa46cb1c3c098e",
	#109 : "",
	#113 : "",
	#114 : "",
	115 : "1075e806f4770cd4763bd285a64e9174",
	#116 : "",
	#117 : "",
	#119 : "",
	120 : "688cdd3b1b6bdda207b6cec2735292d2",
	}

def _derive_key(model):
	if model not in _basebinary_keys:
		return None
	key = _basebinary_keys[model].decode("hex")
	derived_key = ""
	for i in range(len(key)):
		derived_key += chr(ord(key[i]) ^ (i + 0x19))
	logging.debug("derived key {0}".format(derived_key.encode("hex")))
	return derived_key


class BasebinaryError(Exception):
	pass

class Basebinary(object):
	_header_magic = "APPLE-FIRMWARE\x00"
	#XXX: do we need to fix shitty Python struct member signdness things here too?
	_header_format = struct.Struct(">15sB2I4BI")
	
	header_size = _header_format.size
	
	
	@classmethod
	def parse(cls, data):
		if len(data) < (cls.header_size + 4):
			raise BasebinaryError("not enough data to parse")
		
		header_data = data[:cls.header_size]
		inner_data = data[cls.header_size:-4]
		
		#XXX: and here??
		stored_checksum, = struct.unpack(">I", data[-4:])
		
		(byte_0x0F, model, version, byte_0x18, byte_0x19, byte_0x1A, flags, unk_0x1C) = cls.parse_header(header_data)
		
		if flags & 2:
			inner_data = cls.decrypt(inner_data, model, byte_0x0F)
		
		#XXX: why is Python so shitty about this comparison <.<
		checksum = cast_u32(zlib.adler32(header_data+inner_data))
		logging.debug("stored checksum     {0:#x}".format(stored_checksum))
		logging.debug("calculated checksum {0:#x}".format(checksum))
		logging.debug("data length         {0:#x}".format(len(header_data+inner_data)))
		if stored_checksum != checksum:
			raise BasebinaryError("bad checksum")
			
		return inner_data
	
	
	@classmethod
	def compose(cls, data):
		#TODO
		pass
	
	
	@classmethod
	def parse_header(cls, data):
		magic, byte_0x0F, model, version, byte_0x18, byte_0x19, byte_0x1A, flags, unk_0x1C = cls._header_format.unpack(data)
		
		if magic != cls._header_magic:
			raise BasebinaryError("bad header magic")
		
		return (byte_0x0F, model, version, byte_0x18, byte_0x19, byte_0x1A, flags, unk_0x1C)
	
	
	@classmethod
	def compose_header(cls, byte_0x0F, model, version, byte_0x18, byte_0x19, byte_0x1A, flags, unk_0x1C):
		#TODO
		pass
	
	
	@classmethod
	def decrypt(cls, data, model, byte_0x0F):
		iv = cls._header_magic+chr(byte_0x0F)
		key = _derive_key(model)
		if key is None:
			raise BasebinaryError("key missing for model {0}".format(model))
		
		decrypted_data = ""
		remaining_length = len(data)
		chunk_length = 0x8000
		while remaining_length:
			if remaining_length > chunk_length:
				decrypted_data   += cls.decrypt_chunk(data[-remaining_length:-(remaining_length-chunk_length)], key, iv)
				remaining_length -= chunk_length
			else:
				decrypted_data   += cls.decrypt_chunk(data[-remaining_length:], key, iv)
				remaining_length = 0
		
		return decrypted_data
	
	
	@classmethod
	def decrypt_chunk(cls, encrypted_data, key, iv):
		cipher = AES.new(key, AES.MODE_CBC, iv)
		decrypted_data = ""
		bytes_left = len(encrypted_data)
		while bytes_left:
			#logging.debug("bytes left: {0:#x}".format(bytes_left))
			if bytes_left > 0x10:
				decrypted_data += cipher.decrypt(encrypted_data[-bytes_left:-(bytes_left-0x10)])
				bytes_left -= 0x10
			elif bytes_left == 0x10:
				decrypted_data += cipher.decrypt(encrypted_data[-bytes_left:])
				bytes_left = 0
			else: # bytes_left < 0x10
				#LOL: odd-sized chunk at the end is left unencrypted
				decrypted_data += encrypted_data[-bytes_left:]
				bytes_left = 0
		
		return decrypted_data
	
	
	@classmethod
	def encrypt(cls, data):
		#TODO: not really necessary; router doesn't require an encrypted firmware if flag is unset
		pass
	
	
	@classmethod
	def extract(cls, data):
		#TODO: proper gzip header validation?
		gzip_offset = data.index("\x1f\x8b\x08")
		gzdata = data[gzip_offset:]
		
		return zlib.decompress(gzdata, 16+zlib.MAX_WBITS)
