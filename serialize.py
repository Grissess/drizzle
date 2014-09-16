'''
serialize -- Type serialization

This module defines a serializer architecture for reading and writing most
basic Python objects to bytestrings, and returning them from this
representation.

To create custom serializers, the easiest way is to define a class, inheriting
from BaseSerializer, with two classmethods:
-Serialize(cls, obj, fout): Write the serialized form of obj to stream fout.
-Deserialize(cls, fin): Return an unserialized object by reading from fin.
This will automatically assign the next USER tag to that serializer, which is
fine if you just want the same version of the application to have consistent
protocols. If you require backward-compatibility, it is IMPORTANT that you
only append serializers to the loading order; inserting them will change
assigned tag orders. Alternatively, you can assign to __tag__ in the class
definition any byte value (0-255 inclusive--but it must be greater than or
equal to TAG.USER to not conflict with the basic objects). Users should not
mix these interfaces, or an auto-assigned tag could rewrite a manually-
defined tag.

If using classmethods is cumbersome or impossible, you can also use the
following method function:
-SetSerializer(tp, ser): Set serializer for type "tp" to ser.
In this case, the "ser" object will be called as above, but without the
implicit "cls" parameter (as they are not necessarily classmethods). Users
can use this to override arbitrary serializers, but this is generally never
a good idea.
'''

import struct
import cStringIO
import exceptions

SERIALIZERS={} #type -> BaseSerializer derivative (a type)
TAGS={} #tag (int) -> BaseSerializer derivative

CURTAG=0 #BaseSerializer always gets this. Consider it invalid.

PREFERRED_ENCODING='UTF-8' #This is the default for outbound data.
#Inbound data is converted based on a tag.
TEXT_ERROR_MODE='replace' #Silently drop errors with "unknown" characters.
#Set to 'strict' if you actually want these errors bugging you. (This will
#likely come about during Deserialize calls, and wherever Deserialize is
#implicitly done, such as packet parsing, etc.)

#BaseSerializer's metaclass (SerializerMeta) automatically takes care of this
#from the __types__ tuple provided in the class definition. However...if you
#set that after-the-fact, you'll want to call either this function or the next
#one.
def SetSerializer(tp, ser):
	SERIALIZERS[tp]=ser
	TAGS[ser.__tag__]=ser

def UpdateSerializer(ser):
	remove=[]
	for tp, s in SERIALIZERS.iteritems():
		if s==ser:
			remove.append(tp)
	for tp in remove:
		del SERIALIZERS[tp]
	for tp in ser.__types__:
		SERIALIZERS[tp]=ser

#This seems like it may be useful, but it's not particularly pragmatic
#except for readability and (maybe) type monkey-patching.
#When in doubt, do a reverse lookup on TAGS.

class TAG:
	INT=1
	LONG=2
	FLOAT=3
	BYTES=4
	TEXT=5
	BOOL=6
	SEQ=7
	MAP=8
	BYTE=9
	NONE=10
	SLICE=11
	ELLIPSIS=12
	ERROR=13
	USER=14

def RegisterTag(name):
	if not hasattr(TAG, name):
		setattr(TAG, name, TAG.USER)
		TAG.USER+=1
	return TAG.USER-1

class SerializerMeta(type):
	def __new__(mcs, name, bases, dict):
		global CURTAG
		tp=type.__new__(mcs, name, bases, dict)
		if hasattr(tp, '__types__'):
			UpdateSerializer(tp)
		if not hasattr(tp, '__tag__'):
			tp.__tag__=CURTAG
		CURTAG=min(TAG.USER, tp.__tag__+1)
		TAGS[tp.__tag__]=tp
		return tp

class BaseSerializer(object):
	__metaclass__=SerializerMeta
	@classmethod
	def Serialize(cls, obj, fout):
		raise NotImplementedError(cls.__name__+' does not support serialization.')
	@classmethod
	def Deserialize(cls, fin):
		raise NotImplementedError(cls.__name__+' does not support deserialization.')

class IntSerializer(BaseSerializer):
	__types__=(int,)
	__tag__=TAG.INT
	@classmethod
	def Serialize(cls, obj, fout):
		fout.write(struct.pack('!l', obj))
	@classmethod
	def Deserialize(cls, fin):
		return struct.unpack('!l', fin.read(struct.calcsize('!l')))[0]
	
class LongSerializer(BaseSerializer):
	__types__=(long,)
	__tag__=TAG.LONG
	@classmethod
	def Serialize(cls, obj, fout):
		BytesSerializer.Serialize(str(obj), fout)
	@classmethod
	def Deserialize(cls, fin):
		return long(BytesSerializer.Deserialize(fin))

class FloatSerializer(BaseSerializer):
	__types__=(float,)
	__tag__=TAG.FLOAT
	@classmethod
	def Serialize(cls, obj, fout):
		fout.write(struct.pack('!d', obj))
	@classmethod
	def Deserialize(cls, fin):
		return struct.unpack('!d', fin.read(struct.calcsize('!d')))[0]

class BytesSerializer(BaseSerializer):
	__types__=(str,)
	__tag__=TAG.BYTES
	@classmethod
	def Serialize(cls, obj, fout):
		IntSerializer.Serialize(len(obj), fout)
		fout.write(obj)
	@classmethod
	def Deserialize(cls, fin):
		l=IntSerializer.Deserialize(fin)
		return fin.read(l)

class TextSerializer(BaseSerializer):
	__types__=(unicode,)
	__tag__=TAG.TEXT
	@classmethod
	def Serialize(cls, obj, fout):
		BytesSerializer.Serialize(PREFERRED_ENCODING, fout)
		BytesSerializer.Serialize(obj.encode(PREFERRED_ENCODING, TEXT_ERROR_MODE), fout)
	@classmethod
	def Deserialize(cls, fin):
		codec=BytesSerializer.Deserialize(fin)
		data=BytesSerializer.Deserialize(fin)
		try:
			return data.decode(codec, TEXT_ERROR_MODE)
		except LookupError:
			if TEXT_ERROR_MODE=='strict':
				raise
			else:
				return u''

class BoolSerializer(BaseSerializer):
	__types__=(bool,)
	__tag__=TAG.BOOL
	@classmethod
	def Serialize(cls, obj, fout):
		IntSerializer.Serialize((1 if obj else 0), fout)
	@classmethod
	def Deserialize(cls, fin):
		return bool(IntSerializer.Deserialize(fin))

class SequenceSerializer(BaseSerializer):
	__types__=(list, tuple, set)
	__tag__=TAG.SEQ
	SEQ_TYPE_MAP={0: list, 1: tuple, 2: set, 'next': 3}
	SEQ_ID_MAP={list: 0, tuple: 1, set: 2}
	@classmethod
	def RegisterType(cls, seqtp):
		cls.__types__+=(seqtp,)
		UpdateSerializer(cls)
		cls.SEQ_TYPE_MAP[cls.SEQ_TYPE_MAP['next']]=seqtp
		cls.SEQ_ID_MAP[seqtp]=cls.SEQ_TYPE_MAP['next']
		cls.SEQ_TYPE_MAP['next']+=1
		return cls.SEQ_TYPE_MAP['next']-1
	@classmethod
	def Serialize(cls, obj, fout):
		IntSerializer.Serialize(len(obj), fout)
		ByteSerializer.Serialize(cls.SEQ_ID_MAP[type(obj)], fout)
		for item in obj:
			Serialize(item, fout)
	@classmethod
	def Deserialize(cls, fin):
		l=IntSerializer.Deserialize(fin)
		tp=cls.SEQ_TYPE_MAP[ByteSerializer.Deserialize(fin)]
		ret=[]
		for i in xrange(l):
			ret.append(Deserialize(fin))
		if tp is list:
			return ret
		return tp(ret)

class MapSerializer(BaseSerializer):
	__types__=(dict,)
	__tag__=TAG.MAP
	@classmethod
	def Serialize(cls, obj, fout):
		IntSerializer.Serialize(len(obj), fout)
		for pair in sorted(obj.items(), key=lambda item: item[0]):
			SequenceSerializer.Serialize(pair, fout)
	@classmethod
	def Deserialize(cls, fin):
		l=IntSerializer.Deserialize(fin)
		ret={}
		for i in xrange(l):
			key, val=SequenceSerializer.Deserialize(fin)
			ret[key]=val
		return ret

class ByteSerializer(BaseSerializer):
	#No types for a good reason--use Int instead from the API.
	#The only reason this is important is for coding small protocol bits of
	#information, like the tag itself.
	__tag__=TAG.BYTE
	@classmethod
	def Serialize(cls, obj, fout):
		fout.write(struct.pack('!B', obj))
	@classmethod
	def Deserialize(cls, fin):
		return struct.unpack('!B', fin.read(struct.calcsize('!B')))[0]

class NoneSerializer(BaseSerializer):
	__types__=(type(None),)
	__tag__=TAG.NONE
	@classmethod
	def Serialize(cls, obj, fout):
		pass
	@classmethod
	def Deserialize(cls, fin):
		return None

class SliceSerializer(BaseSerializer):
	__types__=(slice,)
	__tag__=TAG.SLICE
	@classmethod
	def Serialize(cls, obj, fout):
		IntSerializer.Serialize(obj.start, fout)
		IntSerializer.Serialize(obj.stop, fout)
		IntSerializer.Serialize(obj.step, fout)
	@classmethod
	def Deserialize(cls, fin):
		return slice(IntSerializer.Deserialize(fin),
					IntSerializer.Deserialize(fin),
					IntSerializer.Deserialize(fin))

class EllipsisSerializer(BaseSerializer):
	__types__=(type(Ellipsis),)
	__tag__=TAG.ELLIPSIS
	@classmethod
	def Serialize(cls, obj, fout):
		pass
	@classmethod
	def Deserialize(cls, fin):
		return Ellipsis
	
class RemoteException(Exception):
	pass
	
class ErrorSerializer(BaseSerializer):
	__types__=(Exception,)
	__tag__=TAG.ERROR
	@classmethod
	def Serialize(cls, obj, fout):
		BytesSerializer.Serialize(type(obj).__name__, fout)
		SequenceSerializer.Serialize(obj.args, fout)
	@classmethod
	def Deserialize(cls, fin):
		ename=BytesSerializer.Deserialize(fin)
		args=tuple(SequenceSerializer.Deserialize(fin))
		ecls=getattr(exceptions, ename, None)
		if ecls:
			return ecls(*args)
		else:
			return RemoteException(ename, *args)

def Serialize(obj, stream=None):
	if not stream:
		stream=cStringIO.StringIO()
	se=GetIdealSerializer(obj)
	if se is None:
		raise TypeError('Unserializeable type: '+repr(type(obj)))
	ByteSerializer.Serialize(se.__tag__, stream)
	se.Serialize(obj, stream)
	return stream.getvalue() #Not accurate unless stream=None (or empty) on entry.

def Deserialize(stream):
	if isinstance(stream, str):
		stream=cStringIO.StringIO(stream)
	tag=ByteSerializer.Deserialize(stream)
	se=TAGS[tag]
	return se.Deserialize(stream)

def GetIdealSerializer(obj):
	#Returns a serializer with the "best" (most specific) serializer type for
	#that object. It does so by comparing MROs--types with longer MROs are
	#assumed to be more specific, and thus desirable for serialization.
	#XXX is this always the case in multiple inheritance situations? If not,
	#a user can pull the desired serializer from SERIALIZERS manually, or by
	#referring to it wherever it's defined...
	curser=None
	curmrolen=0
	for tp, ser in SERIALIZERS.iteritems():
		if isinstance(obj, tp):
			if len(tp.mro())>curmrolen:
				curser=ser
				curmrolen=len(tp.mro())
	return curser