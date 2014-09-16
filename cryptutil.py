'''
drizzle -- Drizzle
cryptutils -- Basic Cryptographic Utilities

This module defines some cryptographic supporting functions.
'''

from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_PSS
from Crypto import Random

import serialize

#Implements the cipher protocol, but doesn't actually perform cryptography.
class NullCipher(object):
	key_size=(0,)
	block_size=1
	@staticmethod
	def encrypt(s):
		return s
	@staticmethod
	def decrypt(s):
		return s
	#A moderate bastardization of the fact that this is present as a module-level
	#function in the normal PyCrypto modules.
	@classmethod
	def new(cls, *args):
		return cls

#Implements the hash protocol, but doesn't actually perform cryptography.
class NullHash(object):
	digest_size=0
	def __init__(self, data=None):
		pass
	@classmethod
	def new(cls, *args):
		return cls(*args)
	def copy(self):
		return type(self)()
	def update(self, data):
		pass
	def digest(self):
		return ''
	def hexdigest(self):
		return ''

class PKCS5Padding(object):
	def __new__(cls):
		return cls #Don't create instances, just in case someone tries...
	@staticmethod
	def Pad(message, cipher):
		padlen=cipher.block_size-(len(message)%cipher.block_size)
		return message+padlen*chr(padlen)
	@staticmethod
	def Unpad(message, cipher):
		padlen=ord(message[-1])
		if padlen>cipher.block_size:
			raise ValueError('Invalid padding')
		return message[:-padlen]

class SimpleCipher(object):
	RANDOM=Random.new()
	def __init__(self, algo, key, iv=None):
		self.iv=iv
		self.key=key
		self.algo=algo
		if iv is not None:
			self._MakeCipher(iv, key)
	def _MakeCipher(self, iv):
		self.cipher=self.algo.new(self.key, algo.MODE_CBC, iv)
	def encrypt(self, s):
		if self.iv is None:
			self.iv=self.RANDOM.read(algo.block_size)
			self._MakeCipher(self.iv)
		return self.iv+self.cipher.encrypt(s)
	def decrypt(self, s):
		iv=s[:self.algo.block_size]
		if iv!=self.iv:
			self.iv=iv
			self._MakeCipher(self.iv)
		return self.cipher.decrypt(s[self.algo.block_size:])

class PKCertificate(object):
	SIG_SCHEME=PKCS1_PSS
	HASH_ALGO=SHA512
	def __init__(self, pubkey, sig, **info):
		if pubkey.has_private():
			pubkey=pubkey.publickey()
		self.pubkey=pubkey
		self.sig=sig
		self.info=info
	@classmethod
	def FromPrivate(cls, prikey, **info):
		inst=cls(prikey.publickey(), '', **info)
		inst.GenSignature()
		return inst
	def DumpCertificate(self, sig=True):
		pass

class PKDB(object):
	def __init__(self, store='pubkey.db'):
		pass