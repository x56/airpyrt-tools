#XXX: this file exists until I think of a better way to do this

def cast_u32(value):
	#XXX: lazy, how do we do this correctly?
	if value < -0x80000000 or value > 0x7FFFFFFF:
		raise Exception("value outside u32 range")
	return value & 0xFFFFFFFF
