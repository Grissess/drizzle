'''
drizzle -- Drizzle
log -- Local logging

Just a wrapper around logging that provides the basic setup needed.
'''

import sys
from logging import *

#basicConfig(format='%(asctime)-15s %(levelname)-10s %(name)-16s %(message)s', level=NOTSET)

NETWORK=3
addLevelName(NETWORK, 'NETWORK')
STATEMACHINE=2
addLevelName(STATEMACHINE, 'STATEMACHINE')
VERBOSE=1
addLevelName(VERBOSE, 'VERBOSE')

COLORS={VERBOSE: 0,
        STATEMACHINE: 2,
        DEBUG: 4,
        INFO: 6,
        WARNING: 3,
        ERROR: 1,
        CRITICAL: 1}

SGI='\x1b[1;%dm'

class ANSIFormatter(Formatter):
	def format(self, record):
		res=Formatter.format(self, record)
		if record.levelno in COLORS:
			res=(SGI%(30+COLORS[record.levelno],))+res+(SGI%(0,))
		return res

fmt=ANSIFormatter('%(asctime)-15s %(levelname)-10s %(name)-16s %(message)s')
hdl=StreamHandler(sys.stdout)
hdl.setFormatter(fmt)
rl=getLogger()
rl.addHandler(hdl)
rl.setLevel(NETWORK)

del fmt, hdl, rl
