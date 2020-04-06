import enum

class MSLDAPClientStatus(enum.Enum):
	RUNNING = 'RUNNING'
	STOPPED = 'STOPPED'
	ERROR = 'ERROR'
