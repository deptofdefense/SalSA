
import os
import pprint
import struct

class PE(object):

  _DOS_HEADER = {
    'len': 64,
    'fmt': [
      ('e_magic','H'),    # (WORD)
      ('e_cblp','H'),     # (WORD)
      ('e_cp','H'),       # (WORD)
      ('e_crlc','H'),     # (WORD)
      ('e_cparhdr','H'),  # (WORD)
      ('e_minalloc','H'), # (WORD)
      ('e_maxalloc','H'), # (WORD)
      ('e_ss','H'),       # (WORD)
      ('e_sp','H'),       # (WORD)
      ('e_csum','H'),     # (WORD)
      ('e_ip','H'),       # (WORD)
      ('e_cs','H'),       # (WORD)
      ('e_lfarlc','H'),   # (WORD)
      ('e_ovno','H'),     # (WORD)
      ('e_res','8s'),     # (WORD[4])
      ('e_oemid','H'),    # (WORD)
      ('e_oeminfo','H'),  # (WORD)
      ('e_res2','20s'),   # (WORD[10])
      ('e_lfanew','I'),   # (DWORD)
    ]
  }

  _PE_HEADER = {
    'len': 24,
    'fmt': [
      ('Signature', 'I'),           # (DWORD)
      ('Machine','H'),              # (WORD)
      ('NumberOfSections','H'),     # (WORD)
      ('TimeDateStamp','I'),        # (DWORD)
      ('PointerToSymbolTable','I'), # (DWORD)
      ('NumberOfSymbols','I'),      # (DWORD)
      ('SizeOfOptionalHeader','H'), # (WORD)
      ('Characteristics','H'),      # (WORD)
    ]
  }

  def __init__(self, filename):
    """ extract PE file pieces piece by piece """
    self.file = open(filename, 'rb')
    self.d = {}
    # parse DOS header
    self._unpack(self._DOS_HEADER, 'DOS_HEADER', 0)
    # extract DOS stub
    self.file.seek(self._DOS_HEADER['len'])
    stub_len = self.d['DOS_HEADER']['e_lfanew'] - self._DOS_HEADER['len']
    self.d['DOS_STUB'] = struct.unpack('{0}s'.format(stub_len), self.file.read(stub_len))[0]
    # parse PE header
    self._unpack(self._PE_HEADER, 'PE_HEADER', self.d['DOS_HEADER']['e_lfanew'])

  def __str__(self):
    """ display header internals as hex strings """
    def _recurse(d, r):
      for k in d.keys():
        if isinstance(d[k], dict):
          r[k] = {}
          _recurse(d[k], r[k])
        elif isinstance(d[k], int):
          r[k] = hex(d[k])
        elif isinstance(d[k], str):
          r[k] = '0x' + ''.join(["{0:02x}".format(ord(x)) for x in d[k]])
    output = {}
    _recurse(self.d, output)
    return pprint.pformat(output, indent=2)

  def _unpack(self, src, dst, offset):
    """ internal function to unpack a given struct/header """
    self.d[dst] = {}
    self.file.seek(offset)
    unpacked = struct.unpack(''.join([f[1] for f in src['fmt']]), self.file.read(src['len']))
    for i in range(len(unpacked)):
      self.d[dst][src['fmt'][i][0]] = unpacked[i]
    self.file.seek(0)


