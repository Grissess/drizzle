'''
drizzle -- Drizzle
qtnt -- PyQt network tester

Just a simple Qt contraption for keeping track of the netlayer.
'''

import time

from PyQt4.QtCore import *
from PyQt4.QtGui import *

from netlayer import *
import log

applogger=log.getLogger(__name__)

ICON_LOC='icons/%s.png'
ICON_F=lambda s: QPixmap(ICON_LOC%(s,))

class DPeerView(QWidget):
	def __init__(self, dpeer, *args):
		super(DPeerView, self).__init__(*args)
		self.dpeer=dpeer

		self.setMinimumSize(320, 180)

		self.model=DPeerModel(dpeer, self)
		self.view=QTableView(self)
		self.view.setModel(self.model)
		self.view.setContextMenuPolicy(Qt.CustomContextMenu)
		self.view.customContextMenuRequested.connect(self.evCtxMenu)
		self.model.dataChanged.connect(self.evViewUpdate)

		self.mpeerctx=QMenu(self)
		self.mpeerctx.addAction('Disconnect', self.mpcDisconnect).setToolTip('Disconnect these clients, setting the state to NOT_CONNECTED and desyncing.')
		self.mpeerctx.addAction('Forget', self.mpcForget).setToolTip('Forget these clients, removing them from the state machine entirely (after disconnecting). Note that they may reappear if the peers send us traffic again.')
		self.mpeerctx.addAction('Block', self.mpcBlock).setToolTip('Prevent these clients from doing anything with us, directly or indirectly. This can be reset by disconnecting on this side.')

		self.sync=QPushButton('Sync', self)
		self.addr=QLineEdit(self)
		self.sync.clicked.connect(self.evSync)
		self.addr.returnPressed.connect(self.evSync)

		self.layout=QGridLayout(self)
		self.layout.addWidget(self.view, 0, 0, 1, 2)
		self.layout.addWidget(self.addr, 1, 0, 1, 1)
		self.layout.addWidget(self.sync, 1, 1, 1, 1)
		self.setLayout(self.layout)
	def evSync(self):
		t=str(self.addr.text())
		self.addr.setText('')
		host, sep, port=t.partition(':')
		port=int(port)
		self.dpeer.SyncTo((host, port))
	def evCtxMenu(self, point):
		applogger.log(log.VERBOSE, 'CtxMenu event on TableView: at point %r (%r, %r)', point, (point.x(), point.y()))
		self.mpeerctx.selection=[self.model.PeerAt(i.row()) for i in self.view.selectedIndexes()] #IT'S INDICES, DAMNIT
		self.mpeerctx.popup(self.view.mapToGlobal(point))
	def evViewUpdate(self):
		self.view.resizeColumnsToContents()
	def mpcDisconnect(self):
		for peer in self.mpeerctx.selection:
			peer.state=STATE.NOT_CONNECTED
	def mpcForget(self):
		for peer in self.mpeerctx.selection:
			del self.dpeer.peers[peer.addr]
	def mpcBlock(self):
		for peer in self.mpeerctx.selection:
			peer.state=STATE.BLOCKED
	def closeEvent(self, event):
		self.dpeer.DesyncAll()
		return super(DPeerView, self).closeEvent(event)

class DPeerModel(QAbstractTableModel):
	def __init__(self, dpeer, *args):
		super(DPeerModel, self).__init__(*args)
		self.dpeer=dpeer
		self.peers=[]
		self.ICON_MAP={STATE.NOT_CONNECTED: ICON_F('red_dot'),
				STATE.DIRECT: ICON_F('green_dot'),
				STATE.INDIRECT: ICON_F('yellow_dot'),
				STATE.ARBITRATING: ICON_F('blue_dot'),
				STATE.BLOCKED: ICON_F('gray_dot')}
		self.PEER_IMG=ICON_F('host')
		self.dpeer.timers.add(Timer(1, self.AssociatePeers))
	def rowCount(self, parentidx):
		applogger.log(log.VERBOSE, 'Rowcount %d', len(self.peers))
		return len(self.peers)
	def columnCount(self, parentidx):
		return 4 #addr, peer, lastact, lastsent
	def PeerAt(self, row):
		return self.peers[row]
	def AssociatePeers(self):
		oldset=set(self.peers)
		newset=set(self.dpeer.peers.values())
		toadd=newset-oldset
		toremove=oldset-newset
		if toadd:
			self.beginInsertRows(QModelIndex(), len(self.peers), len(self.peers)+len(toadd)-1)
			self.peers.extend(toadd)
			self.endInsertRows()
		if toremove:
			#XXX since we can't guarantee contiguity, this is as optimized as we can make this call.
			for peer in toremove:
				idx=self.peers.index(peer)
				self.beginRemoveRows(QModelIndex(), idx, idx)
				self.peers=self.peers[:idx]+self.peers[idx+1:]
				self.endRemoveRows()
		applogger.log(log.VERBOSE, 'AssociatePeers: peer list %r', self.peers)
		if len(self.peers)!=len(self.dpeer.peers):
			applogger.warning('self.peers not the same length as drizzle reported peers (%r).', self.dpeer.peers.values())
		self.dataChanged.emit(self.createIndex(0, 0), self.createIndex(self.rowCount(QModelIndex()), self.columnCount(QModelIndex())))
	def data(self, idx, role):
		if not idx.isValid():
			return QVariant()
		col=idx.column()
		peer=self.peers[idx.row()]
		applogger.log(log.VERBOSE, 'Data access: %d, %d, peer %r', col, idx.row(), peer)
		if role==Qt.DisplayRole:
			if col==0:
				return QString(repr(peer.addr))
			elif col==1:
				return QString(STATE.LOOKUP[peer.state])
			elif col==2:
				return QString(str(int(time.time()-peer.lastact))+'s')
			elif col==3:
				return QString(str(int(time.time()-peer.lastsent))+'s')
			else:
				return QVariant()
		elif role==Qt.DecorationRole:
			if col==0:
				return self.PEER_IMG
			elif col==1:
				return self.ICON_MAP[peer.state]
			else:
				return QVariant()
		elif role==Qt.BackgroundRole:
			if col==2:
				if peer.lastact+peer.KA_INTERVAL+self.dpeer.PT_RESOLUTION<time.time():
					return QColor(255, 255, 0)
			return QVariant()
		else:
			return QVariant()
	def headerData(self, idx, orient, role):
		if role==Qt.DisplayRole:
			if orient==Qt.Horizontal:
				return ['Peer', 'State', 'Last RX', 'Last TX'][idx]
		return QVariant()

if __name__=='__main__':
	import threading
	import sys
	pc=DrizzlePeer()
	if len(sys.argv)<2:
		sys.argv.append('9652')
	pc.sock.bind(('', int(sys.argv[1])))
	#XXX Since this is only a modelviewer, this should be somewhat
	#threadsafe (given the GIL), right?
	thr=threading.Thread(target=pc.Run)
	thr.daemon=True
	thr.start()
	app=QApplication(sys.argv)
	w=DPeerView(pc)
	w.show()
	sys.exit(app.exec_())