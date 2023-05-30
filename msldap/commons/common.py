import enum

class MSLDAPClientStatus(enum.Enum):
	CONNECTED = 'CONNECTED'
	RUNNING = 'RUNNING'
	STOPPED = 'STOPPED'
	ERROR = 'ERROR'
