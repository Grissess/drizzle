'''
drizzle -- Drizzle
sm -- State Machine

A powerful, general-purpose state machine.

Yes, I know, Qt provides such a framework too. But, among other flaws,
it fails to provide a way by which the current state or states can be
retrieved, and fails to provide an easy way to clone a machine (since
our clients will each contain a machine model, not one for the whole
UI as Qt intends).
'''

class Machine(object):
	def __init__(self, *states):
		self.states=set(states)
		self.state=None
		self.initial=None
	def Add(self, cls):
		self.states.add(cls(self))
		return cls
	def AddInitial(self, cls):
		inst=cls(self)
		self.states.add(inst)
		self.initial=inst
		return cls
	def Start(self):
		oldst=self.state
		if self.state is not None:
			self.state.Exit(self.initial)
		self.state=self.initial
		if oldst is not None:
			self.state.Enter(oldst)
	def Input(self, obj):
		st=self.state.Input(obj)
		if st is not None:
			self.Transition(st)
	def Transition(self, st):
		self.state.Exit(st)
		oldst=self.state
		self.state=st
		self.state.Enter(oldst)
	def Clone(self):
		newmachine=type(self)()
		for state in self.states:
			if state is self.initial:
				newmachine.AddInitial(type(state))
			else:
				newmachine.Add(type(state))
		return newmachine
		
class State(object):
	def __init__(self, machine):
		self.machine=machine
	def Input(self, obj):
		raise NotImplementedError('State derivative must implement .Input()')
