import os
from typing import Callable, Iterable, List, Optional

from prompt_toolkit.completion import CompleteEvent, Completer, Completion
from prompt_toolkit.document import Document
import traceback

class PathCompleter(Completer):
	"""
	Complete for Path variables.

	:param get_paths: Callable which returns a list of directories to look into
					  when the user enters a relative path.
	:param file_filter: Callable which takes a filename and returns whether
						this file should show up in the completion. ``None``
						when no filtering has to be done.
	:param min_input_len: Don't do autocompletion when the input string is shorter.
	"""
	def __init__(self, only_directories: bool = False,
				 get_current_dirs: Optional[Callable[[], List[str]]] = None,
				 file_filter: Optional[Callable[[str], bool]] = None,
				 min_input_len: int = 0,
				 expanduser: bool = False) -> None:

		self.only_directories = only_directories
		self.get_current_dirs = get_current_dirs or (lambda: ['.'])
		self.file_filter = file_filter or (lambda _: True)
		self.min_input_len = min_input_len
		self.expanduser = expanduser

	def get_completions(self, document: Document,
						complete_event: CompleteEvent) -> Iterable[Completion]:
		text = document.text_before_cursor

		# Complete only when we have at least the minimal input length,
		# otherwise, we can too many results and autocompletion will become too
		# heavy.
		if len(text) < self.min_input_len:
			return

		try:
			#print('Called!')
			# Do tilde expansion.
			#if self.expanduser:
			#	text = os.path.expanduser(text)

			# Directories where to look.
			dirnames = self.get_current_dirs()
			#print(text)
			for dirname in dirnames:
				if dirname.startswith(text):
					completion = dirname[len(text):]
					yield Completion(completion, 0, display=dirname)
				#elif dirname.find('=') != -1:
				#	m = dirname.find('=') + 1
				#	if dirname[m:].startswith(text):
				#		completion = dirname
				#		yield Completion(completion, 0, display=dirname)
		except Exception as e:
			traceback.print_exc()