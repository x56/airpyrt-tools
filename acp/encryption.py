from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from Crypto.Util import Counter


PBKDF_salt0 = "F072FA3F66B410A135FAE8E6D1D43D5F".decode("hex")
PBKDF_salt1 = "BD0682C9FE79325BC73655F4174B996C".decode("hex")


class _ACPEncryptionContext(object):
	def __init__(self, key, iv):
		self.key = key
		self.iv = iv
		
		self.ctr = Counter.new(128, initial_value=int(iv.encode("hex"), 16))
		self.cipher = AES.new(key, AES.MODE_CTR, counter=self.ctr)


class ACPEncryption(object):
	def __init__(self, key, client_iv, server_iv):
		self._client_context = self._init_client_context(key, client_iv)
		self._server_context = self._init_server_context(key, server_iv)
	
	def _init_client_context(cls, key, iv):
		derived_key = KDF.PBKDF2(key, PBKDF_salt0, 16, 5)
		return _ACPEncryptionContext(derived_key, iv)
	
	def _init_server_context(cls, key, iv):
		derived_key = KDF.PBKDF2(key, PBKDF_salt1, 16, 7)
		return _ACPEncryptionContext(derived_key, iv)
	
	
	def client_decrypt(self, data):
		return self._client_context.cipher.decrypt(data)
	
	
	def client_encrypt(self, data):
		return self._client_context.cipher.encrypt(data)
	
	
	def server_decrypt(self, data):
		return self._server_context.cipher.decrypt(data)
	
	
	def server_encrypt(self, data):
		return self._server_context.cipher.encrypt(data)

