import logging
import socket

from .encryption import ACPEncryption


ACP_SERVER_PORT = 5009

class _ACPSession(object):
	def __init__(self, target, password):
		#XXX: how should we make this abstract enough to cover client and server?
		self.target = target
		self.password = password
		
		self.sock = None
		
		#self.encryption_context = None
		self.encrypt_method = None
		self.decrypt_method = None
		
		#XXX: AppleSRP hax
		#self.SRP = None
		#self.state = 0
	
	
	def connect(self, port=ACP_SERVER_PORT):
		self.port = port
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		logging.info("connecting to host {0}:{1}".format(self.target, self.port))
		self.sock.connect((self.target, self.port))
	
	
	def close(self):
		if self.sock:
			self.sock.close()
			self.sock = None
	
	
	def send(self, data):
		if self.encrypt_method:
			data = self.encrypt_method(data)
		
		if self.sock:
			self.sock.sendall(data)
		#TODO: else? what if sock is not None but not valid in some other way?
	
	
	def _recv_size(self, size):
		recvd_chunks = []
		recvd_size = 0
		while True:
			if recvd_size == size:
				break
			#XXX: this is broken for server receiving stream headers
			data = self.sock.recv(size - recvd_size)
			if not data:
				break
			recvd_chunks.append(data)
			recvd_size += len(data)
		
		return "".join(recvd_chunks)
	
	def _recv_size_timeout(self, size, timeout):
		#XXX: blargh
		self.sock.setblocking(0)
		recvd_chunks = []
		recvd_size = 0
		
		begin=time.time()
		while True:
			if recvd_size == size:
				break
			if recvd_chunks and time.time()-begin > timeout:
				break
			if time.time()-begin > timeout*2:
				break
			
			try:
				#XXX: this is broken for server receiving stream headers
				data = self.sock.recv(size - recvd_size)
				if data:
					recvd_chunks.append(data)
					recvd_size += len(data)
					begin = time.time()
				else:
					time.sleep(0.1)
			except socket.error:
				pass
		
		#XXX: should non-blocking just be the default?
		self.sock.setblocking(1)
		return "".join(recvd_chunks)
	

	def recv(self, size, timeout=0):
		if not self.sock:
			#XXX: do nothing? throw an exception?
			return ""
		
		data = ""
		if timeout:
			data = self._recv_size_timeout(size, timeout)
		else:
			data = self._recv_size(size)
		
		if self.decrypt_method:
			data = self.decrypt_method(data)
		
		return data


class ACPClientSession(_ACPSession):
	def enable_encryption(self, key, client_iv, server_iv):
		self.encryption_context = ACPEncryption(key, client_iv, server_iv)
		
		self.encrypt_method = encryption_context.client_encrypt
		self.decrypt_method = encryption_context.server_decrypt


class ACPServerSession(_ACPSession):
	def enable_encryption(self, key, client_iv, server_iv):
		self.encryption_context = ACPEncryption(key, client_iv, server_iv)
		
		self.encrypt_method = self.encryption_context.server_encrypt
		self.decrypt_method = self.encryption_context.client_decrypt


