import io
import base64
from typing import Dict, List

class LDIFIdx:
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.length = end - start

class MSLDAPLdiff:
    def __init__(self, max_cache_size:int = 10000):
        self.filename:str = None
        self.filehandle:io.BytesIO = None
        self.dn_index:Dict[str, LDIFIdx] = {}
        self.objectclass_index = {}
        self.samaccounttype_index = {}
        self.objecttype_index = {}

        self.max_cache_size = max_cache_size
        self.dncache:Dict[str, List[Dict[str, str]]] = {}

    @staticmethod
    async def from_file(filename:str):
        ldiff = MSLDAPLdiff()
        ldiff.filename = filename
        await ldiff.parse()

    async def open_or_handle(self):
        if self.filehandle is None:
            self.filehandle = open(self.filename, 'r', encoding='utf-8')
        return self.filehandle
    
    async def build_index(self):
        print('[+] Building index...')
        with open(self.filename, 'r', encoding='utf-8') as f:
            while True:
                pos = f.tell()  # Current position in the file
                line = f.readline()

                if not line:  # End of file
                    if current_dn is not None:
                        # Store the end position for the last entry
                        self.dn_index[current_dn] = LDIFIdx(start_pos, pos)
                    break

                if line.startswith('dn: '):
                    if current_dn is not None:
                        # Store the end position for the previous entry
                        self.dn_index[current_dn] = LDIFIdx(start_pos, pos)

                    current_dn = line.strip().upper()
                    start_pos = pos
                if line.startswith('objectClass: '):
                    objectclass = line.strip().upper()
                    if objectclass not in self.objectclass_index:
                        self.objectclass_index[objectclass] = []
                    self.objectclass_index[objectclass].append(current_dn)
                
                if line.startswith('sAMAccountType: '):
                    objectclass = line.strip().upper()
                    if objectclass not in self.objectclass_index:
                        self.objectclass_index[objectclass] = []
                    self.samaccounttype_index[objectclass].append(current_dn)
                
                if line.startswith('objectType: '):
                    objectclass = line.strip().upper()
                    if objectclass not in self.objectclass_index:
                        self.objectclass_index[objectclass] = []
                    self.objecttype_index[objectclass].append(current_dn)

                elif not line.strip() and current_dn is not None:
                    # Optional: Handle blank lines between entries if needed
                    self.dn_index[current_dn] = LDIFIdx(start_pos, pos)
                    current_dn = None


    async def fetch(self, dn:str):
        dn = dn.upper()
        if dn in self.dncache:
            return self.dncache[dn]
        
        if dn not in self.dn_index:
            return None
        
        raw_entry = []
        f = await self.open_or_handle()
        idx = self.dn_index[dn]
        f.seek(idx.start)
        data = f.read(idx.length)
        for line in data.split('\n'):
            line = line.strip()
            if line == '':
                continue
            if line.startswith('#'):
                continue
            raw_entry.append(line)
        
        entry = self.parse_entry(raw_entry)
        if len(self.dncache) > self.max_cache_size:
            self.dncache.popitem()

    def parse_entry(self, raw_entry:List[str]):
        ed = {}
        for line in raw_entry:
            line = line.strip()
            if line == '':
                continue
            if line.startswith('#'):
                continue

            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            if line.split(':', 1)[0].endswith('::'):
                value = base64.b64decode(value)
            
            if key not in ed:
                ed[key] = []

            ed[key].append(value)
        return ed

    async def parse(self):
        await self.build_index()
        