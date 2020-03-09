
import datetime

def timestamp2datetime(dt):
	"""
	Converting Windows timestamps to datetime.datetime format
	:param dt: Windows timestamp as array of bytes
	:type dt: bytearray
	:return: datetime.datetime
	"""
	us = int.from_bytes(dt, byteorder='little')/ 10.
	return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)
	
	
def datetime2timestamp(dt):
	delta = dt - datetime.datetime(1601, 1, 1)
	ns = int((delta / datetime.timedelta(microseconds=1)) * 10)
	return ns.to_bytes(8, 'little', signed = False)