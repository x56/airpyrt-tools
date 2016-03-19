import logging
import struct
from collections import OrderedDict
from math  import log
from types import *


_header_magic = "CFB0"
_footer_magic = "END!"
_header_size = len(_header_magic)
_footer_size = len(_footer_magic)

def _lslice(data, length):
	""" Slice object into two counting from the left
	
	Returns:
		(left_slice, right_slice)
	"""
	return data[:length], data[length:]


class CFLBinaryPListComposeError(Exception):
	"""Exception raised for errors composing a cflbinary format property list"""
	pass

class CFLBinaryPListParseError(Exception):
	"""Exception raised for errors parsing a cflbinary format property list"""
	pass


class CFLBinaryPListComposer(object):
	"""Write cflbinary format property list"""
	
	@classmethod
	def _pack_object(cls, obj):
		""" Pack a supported Python built-in object
		
		Note:
			this function is super hacky and needs to be fixed
		
		Returns:
			data
		
		Raises:
			CFLBinaryPListComposeError
		"""
		data = ""
		
		object_type = type(obj)
		
		if	 object_type == NoneType:
			data += "\x00"
		
		elif object_type == BooleanType:
			if not obj:
				data += "\x08"
			else:
				data += "\x09"
		
		elif object_type == IntType:
			object_marker = 0x10
			buf = ""
			#XXX: need to actually catch unsupported packed sizes
			for fmt in [">B", ">H", ">I", ">Q"]:
				try:
					buf = struct.pack(fmt, obj)
				except struct.error:
					logging.debug("XXX: skipping {0}".format(fmt))
					pass
				else:
					break
			
			object_marker += int(log(len(buf), 2))
			
			data += chr(object_marker)
			data += buf
		
		elif object_type == FloatType:
			object_marker = 0x20
			buf = ""
			#XXX: need to actually catch unsupported packed sizes
			for fmt in ["!f", "!d"]:
				try:
					buf = struct.pack(fmt, obj)
				except struct.error:
					logging.debug("XXX: skipping {0}".format(fmt))
					pass
				else:
					break
			
			object_marker += int(log(len(buf), 2))
			
			data += chr(object_marker)
			data += buf
		
		#XXX: DateType?
		
		elif object_type == StringType:
			object_marker = 0x40
			data_len = len(obj)
			if data_len < 0xF:
				object_marker += data_len
				data += chr(object_marker)
			else:
				object_marker += 0xF
				data += chr(object_marker)
				data += cls._pack_object(data_len)
			data += obj
		
		elif object_type == UnicodeType:
			data += "\x70"
			data += obj.encode("utf-8")
			data += "\x00"
		
		elif object_type == ListType:
			data += "\xA0"
			for element in obj:
				data += cls._pack_object(element)
			data += "\x00"
		
		elif object_type in [DictType, OrderedDict]:
			data += "\xD0"
			for k, v in obj.iteritems():
				data += cls._pack_object(k)
				data += cls._pack_object(v)
			data += "\x00"
		
		else:
			raise CFLBinaryPListComposeError("unsupported Python built-in type: {0}".format(type(obj)))
		
		return data
	
	@classmethod
	def compose(cls, object):
		""" Compose Python object into equivalent plist
		
		Returns:
			plist_data
		
		Raises:
			CFLBinaryPListComposeError
		"""
		data =  _header_magic
		# assume one root object
		data += cls._pack_object(object)
		data += _footer_magic
		return data


class CFLBinaryPListParser(object):
	"""Read cflbinary format property list"""
	
	@classmethod
	def _unpack_int(cls, size_exponent, data):
		""" Unpack an int object as a Python int from the provided data
		
		Returns:
			(int, remaining_data)
		
		Raises:
			CFLBinaryPListParseError
		"""
		int_size = 2**size_exponent
		int_bytes, data = _lslice(data, int_size)
		#XXX: are these supposed to be signed or unsigned?
		if int_size == 1:
			int_fmt = ">B"
		elif int_size == 2:
			int_fmt = ">H"
		elif int_size == 4:
			int_fmt = ">I"
		elif int_size == 8:
			int_fmt = ">Q"
		else:
			raise CFLBinaryPListParseError("unsupported int packed object size of {0} bytes")
		
		try:
			(int_val, ) = struct.unpack(int_fmt, int_bytes)
		except struct.error:
			raise CFLBinaryPListParseError("failed to unpack int value")
		
		return int_val, data
	
	@classmethod
	def _unpack_real(cls, size_exponent, data):
		""" Unpack a real object as a Python float from the provided data
		
		Returns:
			(float, remaining_data)
		
		Raises:
			CFLBinaryPListParseError
		"""
		real_size = 2**size_exponent
		real_bytes, data = _lslice(data, real_size)
		if   real_size == 4:
			real_fmt = ">f"
		elif real_size == 8:
			real_fmt = ">d"
		else:
			raise CFLBinaryPListParseError("unsupported real packed object size of {0} bytes")
		
		try:
			(float_val, ) = struct.unpack(real_fmt, real_bytes)
		except struct.error:
			raise CFLBinaryPListParseError("failed to unpack float value")
		
		return float_val, data
	
	@classmethod
	def _unpack_count(cls, object_info, data):
		""" Unpack count from object info nibble and/or packed int value
		
		Returns:
			(count, remaining_data)
		
		Raises:
			CFLBinaryPListParseError
		"""
		if object_info == 0x0F:
			# count is the following packed int object
			marker, data = cls._unpack_object_marker(data)
			count_object_type = marker & 0xF0
			count_object_info = marker & 0x0F
			if count_object_type != 0x10:
				raise CFLBinaryPListParseError("expected count to be a packed int object")
			count, data = cls._unpack_int(count_object_info, data)
		else:
			count = object_info
		
		return count, data
	
	@classmethod
	def _unpack_object_marker(cls, data):
		""" Unpack an object marker from the provided data
		
		Returns:
			(marker, remaining_data)
		
		Raises:
			CFLBinaryPListParseError
		"""
		marker_byte, data = _lslice(data, 1)
		try:
			(marker, ) = struct.unpack(">B", marker_byte)
		except struct.error:
			raise CFLBinaryPListParseError("failed to unpack object marker")
		
		return marker, data
	
	@classmethod
	def _unpack_object(cls, data):
		""" Unpack an object from the provided data
		
		Returns:
			(obj, remaining_data)
		
		Raises:
			CFLBinaryPListParseError
		"""
		obj = None
		
		marker, data = cls._unpack_object_marker(data)
		object_type = marker & 0xF0
		object_info = marker & 0x0F
		
		if object_type == 0x00:
			if object_info == 0x00:   # null, null object
				return None, data
			elif object_info == 0x08: # bool, false
				return False, data
			elif object_info == 0x09: # bool, true
				return True, data
			else:
				raise CFLBinaryPListParseError("unsupported object info value for object type 0x00: {0:#x}".format(object_info))
		
		elif object_type == 0x10:     # int, big-endian
			return cls._unpack_int(object_info, data)
		
		elif object_type == 0x20:     # real, big-endian
			return cls._unpack_real(object_info, data)
		
		elif object_type == 0x30:     # date
			#XXX: not sure if this is actually used
			raise CFLBinaryPListParseError("date support not implemented")
		
		elif object_type == 0x40:     # data
			size, data = cls._unpack_count(object_info, data)
			#XXX: we return data as str type, is this ok?
			return _lslice(data, size)
		
		elif object_type == 0x50:     # string, ASCII
			raise CFLBinaryPListParseError("ASCII string support not implemented")
		
		elif object_type == 0x60:     # string, Unicode
			raise CFLBinaryPListParseError("Unicode string support not implemented")
		
		elif object_type == 0x70:     # string, UTF8, NULL terminated
			raw = ""
			while True:
				byte, data = _lslice(data, 1)
				if byte == "\x00":
					break
				raw += byte
			#XXX: what exceptions could we get here?
			obj = raw.decode("utf-8")
			return obj, data
		
		elif object_type == 0x80:      # uid
			raise CFLBinaryPListParseError("uid support not implemented")
		
		elif object_type == 0xA0:      # array
			obj = []
			while True:
				element, data = cls._unpack_object(data)
				if element == None:
					break
				obj.append(element)
			return obj, data
		
		elif object_type == 0xB0:      # ordset
			raise CFLBinaryPListParseError("ordset support not implemented")
		
		elif object_type == 0xC0:      # set
			raise CFLBinaryPListParseError("set support not implemented")
		
		elif object_type == 0xD0:      # dict
			keys = []
			values = []
			while True:
				key, data = cls._unpack_object(data)
				if key == None:
					break
				keys.append(key)
				
				value, data = cls._unpack_object(data)
				values.append(value)
			
			obj = OrderedDict()
			for i in range(len(keys)):
				obj[keys[i]] = values[i]
			
			return obj, data
		
		else:
			raise CFLBinaryPListParseError("unsupported object type: {0:#x}".format(object_type))
	
	@classmethod
	def parse(cls, data):
		""" Parse plist data into equivalent Python built-in object type
		
		Returns:
			obj
		
		Raises:
			CFLBinaryPListParseError
		"""
		# bail now if there isn't enough data for header, footer, and at least one object
		if len(data) < (_header_size + _footer_size + 1):
			raise CFLBinaryPListParseError("not enough data to parse")
		
		header_data, data = _lslice(data, _header_size)
		if header_data != _header_magic:
			raise CFLBinaryPListParseError("bad header magic")
		
		# read object stream (assume one root object)
		obj, remaining_data = cls._unpack_object(data)
		if len(remaining_data) > _footer_size:
			raise CFLBinaryPListParseError("extra data found after unpacking root object")
		
		if remaining_data != _footer_magic:
			raise CFLBinaryPListParseError("bad footer magic")
		
		return obj
