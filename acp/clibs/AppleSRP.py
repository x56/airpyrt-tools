from ctypes import *


#XXX: hax to display NULL pointer thingies
def _fmt_void_ptr(value):
	if value is None:
		return 0
	return value

def _fmt_cstr(value):
	if cast(value, c_void_p).value is None:
		return "<null cstr>"
	return value.contents.get_data_buffer().encode("hex")

def _fmt_ccz_class(value):
	if cast(value, c_void_p).value is None:
		return "<null ccz_class>"
	return value.contents

def _fmt_ccz(value):
	if cast(value, c_void_p).value is None:
		return "<null ccz>"
	return value.contents


class cstr(Structure):
	_fields_ = [("data", c_void_p),
	            ("length", c_long),
	            ("cap", c_long),
	            ("ref", c_int),
	            ("allocator", c_void_p)]
	
	def __str__(self):
		s =  "cstr:  {0!r}\n".format(self)
		s += "data:  {0}\n".format(self.get_data_buffer().encode("hex"))
		s += "len:   {0}\n".format(self.length)
		s += "cap:   {0}\n".format(self.cap)
		s += "ref:   {0}\n".format(self.ref)
		s += "alloc: {0:#x}".format(self.allocator)
		return s
	
	def get_data_buffer(self):
		return string_at(self.data, self.length)


# define SHA_LBLOCK      16
'''
typedef struct SHAstate_st {
    SHA_LONG h0, h1, h2, h3, h4;
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num;
} SHA_CTX;
'''
class SHA1_CTX(Structure):
	_fields_ = [("h0", c_uint),
	            ("h1", c_uint),
	            ("h2", c_uint),
	            ("h3", c_uint),
	            ("h4", c_uint),
	            ("Nl", c_uint),
	            ("Nh", c_uint),
	            ("data", c_uint * 16), # uninitialized data???
	            ("num", c_uint)]
	
	def __str__(self):
		s =  "SHA1_CTX: {0!r}\n".format(self)
		s += "h0:       {0:#x}\n".format(self.h0)
		s += "h1:       {0:#x}\n".format(self.h1)
		s += "h2:       {0:#x}\n".format(self.h2)
		s += "h3:       {0:#x}\n".format(self.h3)
		s += "h4:       {0:#x}\n".format(self.h4)
		s += "Nl:       {0}\n".format(self.Nl)
		s += "Nh:       {0}\n".format(self.Nh)
		s += "data:     {0}\n".format("".join(["{0:08x}".format(self.data[i]) for i in range(16)])) # uninitialized data???
		s += "num:      {0}".format(self.num)
		return s


#define RFC2945_KEY_LEN 40	/* length of session key (bytes) */
#define RFC2945_RESP_LEN 20	/* length of proof hashes (bytes) */
'''
struct client_meth_st {
  SHA1_CTX hash;
  SHA1_CTX ckhash;
  unsigned char k[RFC2945_KEY_LEN];
};
'''
class client_meth_st(Structure):
	_fields_ = [("hash", SHA1_CTX),
	            ("ckhash", SHA1_CTX),
	            ("k", c_ubyte * 40)]
	
	def __str__(self):
		s =  "client_meth_st: {0!r}\n".format(self)
		s += "hash:           {0}\n".format(self.hash)
		s += "ckhash:         {0}\n".format(self.ckhash)
		s += "k:              {0}".format(self.k)
		return s


'''
struct server_meth_st {
  SHA1_CTX hash;
  SHA1_CTX ckhash;
  SHA1_CTX oldhash;
  SHA1_CTX oldckhash;
  unsigned char k[RFC2945_KEY_LEN];
  unsigned char r[RFC2945_RESP_LEN];
};
'''
class server_meth_st(Structure):
	_fields_ = [("hash", SHA1_CTX),
	            ("ckhash", SHA1_CTX),
	            ("oldhash", SHA1_CTX),
	            ("oldckhash", SHA1_CTX),
	            ("k", c_ubyte * 40),
	            ("r", c_ubyte * 20)]
	
	def __str__(self):
		s =  "server_meth_st: {0!r}\n".format(self)
		s += "hash:           {0}\n".format(self.hash)
		s += "ckhash:         {0}\n".format(self.ckhash)
		s += "oldhash:        {0}\n".format(self.oldhash)
		s += "oldckhash:      {0}\n".format(self.oldckhash)
		s += "k:              {0}\n".format(self.k)
		s += "r:              {0}".format(self.r)
		return s


'''
struct ccz_class {
	void *ctx;
	void *(*ccz_alloc)(void *, size_t);
	void *(*ccz_realloc)(void *, size_t, void *, size_t);
	void (*ccz_free)(void *, size_t, void *);
};
'''
class ccz_class(Structure):
	_fields_ = [("ctx", c_void_p),
	            ("ccz_alloc", c_void_p),
	            ("ccz_realloc", c_void_p),
	            ("ccz_free", c_void_p)]
	
	def __str__(self):
		s =  "ccz_class:   {0!r}\n".format(self)
		s += "ctx:         {0:#x}\n".format(_fmt_void_ptr(self.ctx))
		s += "ccz_alloc:   {0:#x}\n".format(self.ccz_alloc)
		s += "ccz_realloc: {0:#x}\n".format(self.ccz_realloc)
		s += "ccz_free:    {0:#x}".format(self.ccz_free)
		return s


'''
struct ccz {
    size_t n;
    struct ccz_class *isa;
    int sac;
    cc_unit *u;
};
typedef struct ccz ccz;
'''
class ccz(Structure):
	_fields_ = [("n", c_size_t),
	            ("isa", POINTER(ccz_class)),
	            ("sac", c_int),
	            ("u", c_void_p)]
	
	def __str__(self):
		s =  "ccz: {0!r}\n".format(self)
		s += "n:   {0}\n".format(self.n)
		s += "isa: {0}\n".format(_fmt_ccz_class(self.isa))
		s += "sac: {0}\n".format(self.sac)
		s += "u:   {0:#x}".format(_fmt_void_ptr(self.u))
		return s


'''
struct srp_st {
  int magic;	/* To distinguish client from server (and for sanity) */

  int flags;

  cstr * username;

  BigInteger modulus;
  BigInteger generator;
  cstr * salt;

  BigInteger verifier;
  BigInteger password;

  BigInteger pubkey;
  BigInteger secret;
  BigInteger u;

  BigInteger key;

  cstr * ex_data;

  SRP_METHOD * meth;
  void * meth_data;

  BigIntegerCtx bctx;	     /* to cache temporaries if available */
  BigIntegerModAccel accel;  /* to accelerate modexp if available */

  SRP_CLIENT_PARAM_VERIFY_CB param_cb;	/* to verify params */
  SRP_SERVER_LOOKUP * slu;   /* to look up users */
};
'''
class srp_st(Structure):
	_fields_ = [("magic", c_int),
	            ("flags", c_int),
	            ("username", POINTER(cstr)),
	            ("modulus", POINTER(ccz)),
	            ("generator", POINTER(ccz)),
	            ("salt", POINTER(cstr)),
	            ("verifier", POINTER(ccz)),
	            ("password", POINTER(ccz)),
	            ("pubkey", POINTER(ccz)),
	            ("secret", POINTER(ccz)),
	            ("u", POINTER(ccz)),
	            ("key", POINTER(ccz)),
	            ("ex_data", POINTER(cstr)),
	            ("meth", c_void_p),
	            #XXXXXXXXXXXXXXXX
	            ("meth_data", POINTER(client_meth_st)),
	            #("meth_data", POINTER(server_meth_st)),
	            #XXXXXXXXXXXXXXXX
	            ("bctx", c_void_p),
	            ("accel", c_void_p),
	            ("param_cb", c_void_p),
	            ("slu", c_void_p)]
	
	def __str__(self):
		s =  "*** START ***\n"
		s += "srp_st:    {0!r}\n".format(self)
		s += "magic:     {0}\n".format(self.magic)
		s += "flags:     {0}\n".format(self.flags)
		s += "username:  {0}\n".format(_fmt_cstr(self.username))
		s += "modulus:   {0}\n".format(_fmt_ccz(self.modulus))
		s += "generator: {0}\n".format(_fmt_ccz(self.generator))
		s += "salt:      {0}\n".format(_fmt_cstr(self.salt))
		s += "verifier:  {0}\n".format(_fmt_ccz(self.verifier))
		s += "password:  {0}\n".format(_fmt_ccz(self.password))
		s += "pubkey:    {0}\n".format(_fmt_ccz(self.pubkey))
		s += "secret:    {0}\n".format(_fmt_ccz(self.secret))
		s += "u:         {0}\n".format(_fmt_ccz(self.u))
		s += "key:       {0}\n".format(_fmt_ccz(self.key))
		s += "ex_data:   {0}\n".format(_fmt_cstr(self.ex_data))
		s += "meth:      {0:#x}\n".format(_fmt_void_ptr(self.meth))
		s += "meth_data: {0}\n".format(self.meth_data.contents) #XXXXXXXXXXXXXXXX
		s += "bctx:      {0:#x}\n".format(_fmt_void_ptr(self.bctx))
		s += "accel:     {0:#x}\n".format(_fmt_void_ptr(self.accel))
		s += "param_cb:  {0:#x}\n".format(_fmt_void_ptr(self.param_cb))
		s += "slu:       {0:#x}\n".format(_fmt_void_ptr(self.slu))
		s += "**** END ****"
		return s


__AppleSRP = cdll.LoadLibrary("/System/Library/PrivateFrameworks/AppleSRP.framework/Versions/A/AppleSRP")
#print "AppleSRP:", __AppleSRP

# SRP_METHOD *SRP6a_client_method(void)
SRP6a_client_method = __AppleSRP.SRP6a_client_method
SRP6a_client_method.restype = c_void_p

# SRP_METHOD *SRP6a_server_method(void)
SRP6a_server_method = __AppleSRP.SRP6a_server_method
SRP6a_server_method.restype = c_void_p

# SRP *SRP_new(SRP_METHOD *meth)
SRP_new = __AppleSRP.SRP_new
#SRP_new.restype = c_void_p
SRP_new.restype = POINTER(srp_st)
SRP_new.argtypes = [ c_void_p ]

# SRP_RESULT SRP_set_username(SRP *srp, const char *username)
SRP_set_username = __AppleSRP.SRP_set_username
SRP_set_username.argtypes = [ c_void_p, c_char_p ]

# SRP_RESULT SRP_set_params(SRP *srp, const unsigned char *modulus, int modlen,
#                           const unsigned char *generator, int genlen,
#                           const unsigned char *salt, int saltlen)
SRP_set_params = __AppleSRP.SRP_set_params
SRP_set_params.argtypes = [ c_void_p, c_char_p, c_int, c_char_p, c_int, c_char_p, c_int ]

# SRP_RESULT SRP_gen_pub(SRP *srp, cstr **result)
SRP_gen_pub = __AppleSRP.SRP_gen_pub
SRP_gen_pub.argtypes = [ c_void_p, POINTER(POINTER(cstr)) ]

# SRP_RESULT SRP_set_auth_password(SRP *srp, const unsigned char *password, int passlen)
SRP_set_auth_password = __AppleSRP.SRP_set_auth_password
SRP_set_auth_password.argtypes = [ c_void_p, c_char_p, c_int ]

# SRP_RESULT SRP_compute_key(SRP *srp, cstr **result, const unsigned char *pubkey, int pubkeylen)
SRP_compute_key = __AppleSRP.SRP_compute_key
SRP_compute_key.argtypes = [ c_void_p, POINTER(POINTER(cstr)), c_char_p, c_int ]

# SRP_RESULT SRP_respond(SRP *srp, cstr **proof)
SRP_respond = __AppleSRP.SRP_respond
SRP_respond.argtypes = [ c_void_p, POINTER(POINTER(cstr)) ]

# SRP_RESULT SRP_verify(SRP *srp, const unsigned char *proof, int prooflen)
SRP_verify = __AppleSRP.SRP_verify
SRP_verify.argtypes = [ c_void_p, c_char_p, c_int ]

# SRP_RESULT SRP_free(SRP *srp)
SRP_free = __AppleSRP.SRP_free
SRP_free.argtypes = [ c_void_p ]

# cstr *cstr_new(void)
cstr_new = __AppleSRP.cstr_new
cstr_new.restype = POINTER(cstr)

# void cstr_free(cstr *str)
cstr_free = __AppleSRP.cstr_free
cstr_free.restype = None
cstr_free.argtypes = [ POINTER(cstr) ]
