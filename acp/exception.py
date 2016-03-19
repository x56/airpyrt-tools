#TODO: put other exceptions in here...

class ACPError(Exception):
	"""Base class for exceptions in this module."""
	pass


class ACPClientError(ACPError):
	"""Exception raised for errors in the ACP client"""
	pass


class ACPCommandLineError(ACPError):
	"""Exception raised for command line invocation errors"""
	pass


class ACPMessageError(ACPError):
	"""Exception raised for errors processing ACP packets"""
	pass


class ACPPropertyError(ACPError):
	"""Exception raised for errors processing ACP properties"""
	pass

