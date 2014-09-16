'''
drizzle -- Drizzle
netlayer -- Tunneling and peering

Drizzle is a compact, open distribution system that loosely resembles BitTorrent
over UDP. Drizzle aims to be fast, lightweight, flexible, and secure.

This library enables clients to interconnect with each other, but does little
else than maintain a densely-linked meshnet.
'''

import sys
import socket
import time
import random

from Crypto.Cipher import AES
from Crypto.Cipher import CAST
from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from cryptutil import NullCipher

from Crypto.Hash import SHA512
from Crypto.Hash import SHA
from Crypto.Hash import MD5
from cryptutil import NullHash

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS

import serialize
import log
from cryptutil import PKCS5Padding

PYTHON_3=(sys.version_info.major>=3)

if PYTHON_3:
	xrange=range

logger=log.getLogger(__name__)

padder=PKCS5Padding #Not instantiated, using staticmethods

#These values are totally pulled out of my ass. While I was in there, I also
#found a tuba, a rusty nail, and a copy of last year's Playboy.
#Guidelines:
#256 is a good baseline for algorithms that are considered essentially unbreakable
#if used properly in the current setting. The numbers may end up higher than this
#as new algorithms are added and implemented.
#Values in [128, 256] generally represent variants of algorithms that are still
#cryptographically sound, but not ideal for some reason (speed, small keys,
#weak keys, etc.)
#Values <=16 represent algorithms with known weaknesses and flaws that aren't
#secure in the modern setting and should not be used.
#0 is an algorithm that provides no security whatsoever. This is generally
#reserved for the NullCipher (the cipher that operates with a zero-byte key) and the
#NullHash (the hash that produces a zero-byte digest).
AES.strength=256
CAST.strength=256
DES3.strength=128
DES.strength=16
NullCipher.strength=0

SHA512.strength=256
SHA.strength=128
MD5.strength=16
NullHash.strength=0

CIPHER_MAP={'AES': AES,
			'CAST': CAST,
			'DES3': DES3,
			'DES': DES,
			'NULL': NullCipher}

HASH_MAP={'SHA512': SHA512,
			'SHA': SHA,
			'MD5': MD5,
			'NULL': NullHash}

class CMD:
	KEEPALIVE=0 #No-op, sent periodically to avoid timeouts
	SYNC=1 #Synchronize with a peer
	DESYNC=2 #Gracefully desynchronize with a peer
	ARBITRATE=3 #Request a hole-punching maneuver
	PEERS=4 #List peers
	HANDLERS=5 #List handlers
	DATA=6 #Other data
	ROUTE=7 #Best effort delivery function (for embedded packets)
CMD.LOOKUP=dict(zip(CMD.__dict__.values(), CMD.__dict__.keys()))

class Packet(object):
	def __init__(self, cmd, **kwargs):
		self.cmd=cmd
		self.attrs=kwargs
	@classmethod
	def FromStr(cls, s):
		return cls(ord(s[0]), **serialize.Deserialize(s[1:]))
	@classmethod
	def Make(cls, obj):
		if isinstance(obj, cls):
			return obj
		return cls.FromStr(obj) #XXX Eww.
	def __getattr__(self, attr):
		if attr=='cmd':
			logger.warning('Failed to find "cmd" on a Packet; assuming default')
			self.cmd=CMD.KEEPALIVE
			return self.cmd
		if attr=='attrs':
			logger.warning('Failed to find "attrs" on a Packet; assuming default')
			self.attrs={}
			return self.attrs
		return self.attrs[attr]
	def __setattr__(self, attr, val):
		if attr in ('cmd', 'attrs'):
			object.__setattr__(self, attr, val)
		else:
			self.attrs[attr]=val
	def __delattr__(self, attr):
		del self.attrs[attr]
	def __str__(self):
		return chr(self.cmd)+serialize.Serialize(self.attrs)
	def __repr__(self):
		return '<Packet cmd=%s %r>'%(CMD.LOOKUP[self.cmd], self.attrs)
	def Has(self, *attrs):
		for attr in attrs:
			if attr not in self.attrs:
				return False
		return True
	@staticmethod
	def REQUIRE(*attrs):
		def decorator(f, attrs=attrs):
			f.attrs=set(attrs)
			return f
		return decorator

class STATE:
	NOT_CONNECTED=0 #Not connected to this peer at all
	DIRECT=1 #Directly connected
	INDIRECT=2 #Indirectly connected
	ARBITRATING=3 #Attempting to arbitrate
	BLOCKED=4 #Inbound communication disallowed.
	DIRECT_LOCAL=5 #Directly connected on a LAN--don't attempt to route this peer to the WAN.
	INDIRECT_REMOTE=6 #Analogue to PEERS response for DIRECT_LOCAL; we know this peer exists,
	#but we can't arbitrate it. Also useful for peers remotely listed as INDIRECT. May be
	#upgraded to indirect if we find a peer with a DIRECT connection.
	MAX=INDIRECT_REMOTE #Please keep this up to date!
	@classmethod
	def ONLY(cls, *states):
		def decorator(f, cls=cls, states=states):
			f.states=set(states)
			return f
		return decorator
	@classmethod
	def EXCLUDE(cls, *states):
		def decorator(f, cls=cls, states=states):
			f.states=cls.ALL-set(states)
			return f
		return decorator
STATE.LOOKUP=dict(zip(STATE.__dict__.values(), STATE.__dict__.keys()))
STATE.ALL=set(xrange(STATE.MAX))

class Peer(object):
	KA_INTERVAL=5
	KA_DROP=30
	STATE_UPDATE=30
	def __init__(self, this, addr, state=STATE.NOT_CONNECTED):
		self.this=this
		self.addr=tuple(addr)
		self._state=state
		self.handlers=set()
		self.peers=set()
		self.psmap={}
		self.lastact=time.time()
		self.lastsent=self.lastact
		self.lastup=self.lastact
	def __repr__(self):
		return '<Peer @%r state %s>'%(self.addr, STATE.LOOKUP[self.state])
	def _get_state(self):
		return self._state
	def _set_state(self, val):
		logger.info('%r state transition to %s', self, STATE.LOOKUP[val])
		for handler in self.this.handlers.itervalues():
			handler.StateChange(self, val)
		self._state=val
	state=property(_get_state, _set_state)
	def Disconnect(self):
		logger.info('Disconnecting %r...', self)
		if self.state!=STATE.NOT_CONNECTED:
			self.Send(Packet(CMD.DESYNC))
		self.state=STATE.NOT_CONNECTED
	def DoKATimer(self):
		if self.state not in (STATE.DIRECT, STATE.DIRECT_LOCAL):
			return
		t=time.time()
		if self.lastact+self.KA_DROP<t:
			logger.info('Disconnecting %r due to timeout', self)
			self.Disconnect()
		elif self.lastsent+self.KA_INTERVAL<t:
			logger.debug('Keep-alive sent to %r', self)
			self.Send(Packet(CMD.KEEPALIVE))
	def DoStateTimer(self):
		if self.state not in (STATE.DIRECT, STATE.DIRECT_LOCAL):
			return
		if self.lastup+self.STATE_UPDATE<time.time():
			self.UpdateState()
	def UpdateState(self):
		logger.debug('Updating state on %r', self)
		self.Send(Packet(CMD.HANDLERS))
		self.Send(Packet(CMD.PEERS))
		self.lastup=time.time()
	def Send(self, pkt):
		logger.log(log.NETWORK, '%r <- %r', self, pkt)
		self.this.sock.sendto(str(pkt), self.addr)
		self.lastsent=time.time()
	def Recv(self, pkt):
		self.lastact=time.time()
		pkt=Packet.Make(pkt)
		logger.log(log.NETWORK, '%r -> %r', self, pkt)
		handler=getattr(self, 'cmd_'+CMD.LOOKUP[pkt.cmd])
		if hasattr(handler, 'states') and self.state not in handler.states:
			logger.warning('%s packet not expected in %s state (accepts states %r); ignoring.', CMD.LOOKUP[pkt.cmd], STATE.LOOKUP[self.state], map(lambda x: STATE.LOOKUP[x], handler.states))
			return
		if hasattr(handler, 'attrs'):
			missing=handler.attrs-set(pkt.attrs.keys())
			if missing:
				logger.warning('%s packet missing attributes %r; ignoring.', CMD.LOOKUP[pkt.cmd], missing)
				return
		handler(pkt)
	@STATE.ONLY(STATE.DIRECT, STATE.DIRECT_LOCAL)
	def cmd_KEEPALIVE(self, pkt):
		if not pkt.Has('response'):
			pkt.response=1
			self.Send(pkt)
	@STATE.EXCLUDE(STATE.DIRECT, STATE.DIRECT_LOCAL)
	def cmd_SYNC(self, pkt):
		if pkt.Has('local'):
			logger.info('%r synchronizing locally', self)
			self.state=STATE.DIRECT_LOCAL
		else:
			self.state=STATE.DIRECT
		if pkt.Has('you'):
			logger.info('Peer-apparent address: %r', pkt.you)
			if len(self.this.addrs)>self.this.MAX_SELVES:
				logger.error('(MAX_SELVES) Too many recognized self-addresses to add %r; possible attack?', pkt.you)
			else:
				self.this.addrs.add(tuple(pkt.you))
		if pkt.Has('response'):
			#A good time to do a state update
			self.UpdateState()
		else:
			pkt.response=1
			pkt.you=self.addr
			self.Send(pkt)
	def cmd_DESYNC(self, pkt):
		self.state=STATE.NOT_CONNECTED
	@STATE.ONLY(STATE.DIRECT, STATE.DIRECT_LOCAL)
	def cmd_ARBITRATE(self, pkt):
		if pkt.Has('remote'):
			peer=self.this.GetPeer(pkt.remote)
			if (not peer) or peer.state!=STATE.DIRECT or peer==self or peer.addr in self.this.addrs:
				logger.debug('Arbitration from %r failed; no such peer %r, peer not connected, peer is self, or peer is us.', self, pkt.remote)
				self.Send(Packet(CMD.ARBITRATE, success=0, arbitrated=pkt.remote))
				return
			logger.debug('Arbitrating %r to %r, outbound phase', self, peer)
			peer.Send(Packet(CMD.ARBITRATE, behalf=self.addr))
		elif pkt.Has('behalf'):
			peer=self.this.GetPeer(pkt.behalf)
			if peer and peer.state==STATE.BLOCKED:
				logger.info('Dropping arbitration request on behalf of %r (peer is blocked)', peer)
				return
			peer=Peer(self.this, pkt.behalf, STATE.ARBITRATING)
			logger.debug('Arbitration request received from %r via %r', peer, self)
			self.this.peers[tuple(pkt.behalf)]=peer
			peer.Send(Packet(CMD.KEEPALIVE))
			self.Send(Packet(CMD.ARBITRATE, respond=pkt.behalf))
		elif pkt.Has('respond'):
			peer=self.this.GetPeer(pkt.respond)
			if peer:
				logger.debug('Arbitrating %r to %r, return phase', self, peer)
				peer.Send(Packet(CMD.ARBITRATE, success=1, arbitrated=self.addr))
			else:
				logger.warning('Could not find arbitration response peer.')
		elif pkt.Has('success', 'arbitrated'):
			peer=self.this.GetPeer(pkt.arbitrated)
			if pkt.success:
				if peer:
					logger.debug('Arbitration to %r succeeded; syncing.', peer)
					peer.Send(Packet(CMD.SYNC, you=peer.addr))
				else:
					logger.warning('Could not find arbitration remote peer.')
			else:
				logger.debug('Arbitration to %r failed.', pkt.arbitrated)
				peer.state=STATE.INDIRECT
		else:
			logger.warning('Invalid arbitration state.')
	@STATE.ONLY(STATE.DIRECT, STATE.DIRECT_LOCAL)
	def cmd_PEERS(self, pkt):
		if pkt.Has('peers', 'states'):
			self.peers=set((tuple(i) for i in pkt.peers))
			self.psmap=dict(zip(self.peers, pkt.states))
			for addr in self.peers:
				if addr not in self.this.addrs: #Get rid of silly warnings
					peer=self.this.GetPeer(addr, True)
					if peer and peer.state in (STATE.NOT_CONNECTED, STATE.INDIRECT):
						if self.psmap[addr]==STATE.DIRECT:
							peer.state=STATE.INDIRECT
						elif self.psmap[addr]in (STATE.INDIRECT, STATE.DIRECT_LOCAL):
							peer.state=STATE.INDIRECT_REMOTE
		else:
			pkt.peers=self.this.peers.keys()
			pkt.states=[i.state for i in self.this.peers.values()]
			self.Send(pkt)
	@STATE.ONLY(STATE.DIRECT, STATE.DIRECT_LOCAL)
	def cmd_HANDLERS(self, pkt):
		if pkt.Has('handlers'):
			self.handlers=set(pkt.handlers)
		else:
			pkt.handlers=self.this.handlers.keys()
			self.Send(pkt)
	@STATE.ONLY(STATE.DIRECT, STATE.DIRECT_LOCAL)
	@Packet.REQUIRE('handler')
	def cmd_DATA(self, pkt):
		handler=self.this.GetHandler(pkt.handler)
		if handler:
			handler.Recv(self, pkt)
	@STATE.ONLY(STATE.DIRECT, STATE.DIRECT_LOCAL)
	@Packet.REQUIRE('dest', 'data', 'ttl', 'src')
	def cmd_ROUTE(self, pkt):
		if pkt.ttl<0:
			return
		if tuple(pkt.dest) in self.this.addrs:
			self.this.Recv(pkt.data, tuple(pkt.src))
			return
		peer=self.this.GetPeer(pkt.dest)
		if peer:
			if peer.state==STATE.DIRECT:
				peer.Send(pkt)
				return
		rpeer=None
		for rp in self.this.peers.itervalues():
			if peer.addr in rp.peers and rp.psmap[peer.addr]==STATE.DIRECT:
				rpeer=rp
				break
		else:
			rpeer=random.choice(self.this.peers.values())
		pkt.ttl-=1
		if pkt.ttl<0:
			return
		rpeer.Send(pkt)

class Timer(object):
	def __init__(self, interval, callback, *args):
		self.interval=interval
		self.callback=callback
		self.args=args
		self.nextcall=time.time()+interval
	def Run(self):
		if time.time()>=self.nextcall:
			self.callback(*self.args)
			self.nextcall=time.time()+self.interval

class SECMODE:
	REJECT=0 #Reject connections with low security.
	ACCEPT_LIMITED=1 #Accept connections, but don't allow applications that require security to use them.
	ACCEPT=2 #Accept as usual. (NOT RECOMMENDED.)

class DrizzlePeer(object):
	BUF_SIZE=65536 #Maximum MTU to read from UDP socket recvfrom call
	TIMEOUT=1 #Timeout (in s) on read socket; affects timer resolution
	PT_RESOLUTION=1 #Scheduling resolution (in s) on which to call peer timers
	CONNECT_INTERVAL=10 #Interval during which arbitration is automatically attempted
	MAX_ARBITRATIONS=25 #Maximum number of arbitrations to do at once
	MAX_CONNECTIONS=256 #Maximum number of direct connections to hold
	MAX_PEERS=4096 #Maximum number of peers to know about
	MAX_SELVES=8 #Maximum number of addresses to attribute to the local adapter
	SEC_LEVEL=32 #Reject security schemes with strengths less than this
	def __init__(self, sock=None):
		if not sock:
			sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock=sock
		self.addrs=set([sock.getsockname()])
		self.sock.settimeout(self.TIMEOUT)
		self.peers={} #Addr -> Peer (object) with .addr==addr
		self.handlers={} #Name -> Handler (object)
		self.timers=set()
		self.timers.add(Timer(self.PT_RESOLUTION, self.DoPeerTimers))
		self.timers.add(Timer(self.CONNECT_INTERVAL, self.DoConnection))
		self.secmode=SECMODE.ACCEPT_LIMITED
		self.dorun=False
	def GetPeer(self, addr, create=False):
		addr=tuple(addr)
		if addr in self.addrs:
			logger.warning('Attempted to create a peer with one of our known addresses.')
			return None
		if create:
			if logger.isEnabledFor(log.INFO) and addr not in self.peers:
				logger.info('GetPeer: Creating peer at %r', addr)
				if len(self.peers)>self.MAX_PEERS:
					logger.error('(MAX_PEERS) Too many peers; not creating peer at %r', addr)
					return None
			return self.peers.setdefault(addr, Peer(self, addr))
		return self.peers.get(addr, None)
	def GetHandler(self, handler):
		return self.handlers.get(handler, None)
	def SyncTo(self, addr):
		logger.info('SyncTo %r', addr)
		peer=self.GetPeer(addr, True)
		if peer:
			peer.Send(Packet(CMD.SYNC, you=addr))
		else:
			logger.error('Failed to sync to %r; could not create peer!', addr)
	def DesyncAll(self):
		logger.info('Desyncing all peers...')
		for peer in self.peers.itervalues():
			if peer.state==STATE.DIRECT:
				peer.Send(Packet(CMD.DESYNC))
	def Run(self):
		self.dorun=True
		while self.dorun:
			try:
				self.Recv(*self.sock.recvfrom(self.BUF_SIZE))
			except socket.timeout:
				pass
			logger.log(log.VERBOSE, 'Timer tick')
			for t in self.timers:
				t.Run()
	def Recv(self, data, src):
		pkt=Packet.Make(data)
		peer=self.GetPeer(src, True)
		if peer:
			if peer.state!=STATE.BLOCKED:
				peer.Recv(pkt)
			else:
				logger.info('Dropping packet from %r (peer is blocked)', peer)
		else:
			logger.warning('Dropped packet from %r; could not create peer.', src)
	def DoPeerTimers(self):
		for peer in self.peers.itervalues():
			peer.DoKATimer()
			peer.DoStateTimer()
	def DoConnection(self):
		logger.debug('Running DoConnection...')
		for addr in self.addrs:
			if addr in self.peers:
				del self.peers[addr]
		cpeer=None
		for peer in self.peers.itervalues():
			if peer.state==STATE.DIRECT:
				cpeer=peer
				break
		else:
			logger.warning('In DoConnection: no directly connected peers; this situation will never rectify itself without intervention.')
			return #Nothing to do--no direct connections.
		i=0
		for peer in self.peers.itervalues():
			if peer.state==STATE.INDIRECT:
				logger.debug('DoConnection: Arbitrating %r through %r', peer, cpeer)
				cpeer.Send(Packet(CMD.ARBITRATE, remote=peer.addr))
				peer.state=STATE.ARBITRATING
				i+=1
				if i>self.MAX_ARBITRATIONS:
					logger.warning('DoConnection: (MAX_ARBITRATIONS) Hit arbitrations limit, done for now.')
					return #Finish for now.

if __name__=='__main__':
	import sys
	sys.setrecursionlimit(50)
	pc=DrizzlePeer()
	if len(sys.argv)<2:
		sys.argv.append('9652')
	pc.sock.bind(('', int(sys.argv[1])))
	print('DPeer initialized on', pc.addrs)
	for peerspec in sys.argv[2:]:
		h, sep, port=peerspec.partition(':')
		port=int(port)
		pc.SyncTo((h, port))
		print('SyncTo', h, port)
	pc.Run()
