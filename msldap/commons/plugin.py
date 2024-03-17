from abc import ABC, abstractmethod

class MSLDAPConsolePlugin(ABC):
	def __init__(self, console, connection):
		self.console = console
		self.connection = connection
	
	@abstractmethod
	async def run(self, runargs:str):
		pass



class SamplePlugin(MSLDAPConsolePlugin):
	async def run(self, runargs:str):
		print("Hello World")
		print("Runargs: %s" % runargs)
		await self.console.do_ls()