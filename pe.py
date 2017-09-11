import pprint
import struct
import binascii


class PE(object):

  # size in bytes of a WORD and DWORD to windows systems
  _BYTE = 1
  _WORD = 2
  _DWORD = 4
  _QWORD = 8

  _DOS_HEADER = {
    'len': 64, # in bytes
    'fmt': [
      ('e_magic',   '{0}s'.format(_WORD)),
      ('e_cblp',    '{0}s'.format(_WORD)),
      ('e_cp',      '{0}s'.format(_WORD)),
      ('e_crlc',    '{0}s'.format(_WORD)),
      ('e_cparhdr', '{0}s'.format(_WORD)),
      ('e_minalloc','{0}s'.format(_WORD)),
      ('e_maxalloc','{0}s'.format(_WORD)),
      ('e_ss',      '{0}s'.format(_WORD)),
      ('e_sp',      '{0}s'.format(_WORD)),
      ('e_csum',    '{0}s'.format(_WORD)),
      ('e_ip',      '{0}s'.format(_WORD)),
      ('e_cs',      '{0}s'.format(_WORD)),
      ('e_lfarlc',  '{0}s'.format(_WORD)),
      ('e_ovno',    '{0}s'.format(_WORD)),
      ('e_res',     '{0}s'.format(_WORD * 4)),
      ('e_oemid',   '{0}s'.format(_WORD)),
      ('e_oeminfo', '{0}s'.format(_WORD)),
      ('e_res2',    '{0}s'.format(_WORD * 10)),
      ('e_lfanew',  '{0}s'.format(_DWORD)),
    ]
  }

  _PE_HEADER = {
    'len': 24, # in bytes
    'fmt': [
      ('Signature',           '{0}s'.format(_DWORD)),
      ('Machine',             '{0}s'.format(_WORD)),
      ('NumberOfSections',    '{0}s'.format(_WORD)),
      ('TimeDateStamp',       '{0}s'.format(_DWORD)),
      ('PointerToSymbolTable','{0}s'.format(_DWORD)),
      ('NumberOfSymbols',     '{0}s'.format(_DWORD)),
      ('SizeOfOptionalHeader','{0}s'.format(_WORD)),
      ('Characteristics',     '{0}s'.format(_WORD)),
    ]
  }

  _32_IMAGE_HEADER = {
    'len': 96, # in bytes
    'fmt': [
      ('Magic',                      '{0}s'.format(_WORD)),
      ('MajorLinkerVersion',         '{0}s'.format(_BYTE)),
      ('MinorLinkerVersion',         '{0}s'.format(_BYTE)),
      ('SizeOfCode',                 '{0}s'.format(_DWORD)),
      ('SizeOfInitializedData',      '{0}s'.format(_DWORD)),
      ('SizeOfUninitializedData',    '{0}s'.format(_DWORD)),
      ('AddressOfEntryPoint',        '{0}s'.format(_DWORD)),
      ('BaseOfCode',                 '{0}s'.format(_DWORD)),
      ('BaseOfData',                 '{0}s'.format(_DWORD)),
      ('ImageBase',                  '{0}s'.format(_DWORD)),
      ('SectionAlignment',           '{0}s'.format(_DWORD)),
      ('FileAlignment',              '{0}s'.format(_DWORD)),
      ('MajorOperatingSystemVersion','{0}s'.format(_WORD)),
      ('MinorOperatingSystemVersion','{0}s'.format(_WORD)),
      ('MajorImageVersion',          '{0}s'.format(_WORD)),
      ('MinorImageVersion',          '{0}s'.format(_WORD)),
      ('MajorSubsystemVersion',      '{0}s'.format(_WORD)),
      ('MinorSubsystemVersion',      '{0}s'.format(_WORD)),
      ('Win32VersionValue',          '{0}s'.format(_DWORD)),
      ('SizeOfImage',                '{0}s'.format(_DWORD)),
      ('SizeOfHeaders',              '{0}s'.format(_DWORD)),
      ('CheckSum',                   '{0}s'.format(_DWORD)),
      ('Subsystem',                  '{0}s'.format(_WORD)),
      ('DllCharacteristics',         '{0}s'.format(_WORD)),
      ('SizeOfStackReserve',         '{0}s'.format(_DWORD)),
      ('SizeOfStackCommit',          '{0}s'.format(_DWORD)),
      ('SizeOfHeapReserve',          '{0}s'.format(_DWORD)),
      ('SizeOfHeapCommit',           '{0}s'.format(_DWORD)),
      ('LoaderFlags',                '{0}s'.format(_DWORD)),
      ('NumberOfRvaAndSizes',        '{0}s'.format(_DWORD)),
    ]
  }

  _64_IMAGE_HEADER = {
    'len': 112, # in bytes
    'fmt': [
      ('Magic',                      '{0}s'.format(_WORD)),
      ('MajorLinkerVersion',         '{0}s'.format(_BYTE)),
      ('MinorLinkerVersion',         '{0}s'.format(_BYTE)),
      ('SizeOfCode',                 '{0}s'.format(_DWORD)),
      ('SizeOfInitializedData',      '{0}s'.format(_DWORD)),
      ('SizeOfUninitializedData',    '{0}s'.format(_DWORD)),
      ('AddressOfEntryPoint',        '{0}s'.format(_DWORD)),
      ('BaseOfCode',                 '{0}s'.format(_DWORD)),
      ('ImageBase',                  '{0}s'.format(_QWORD)),
      ('SectionAlignment',           '{0}s'.format(_DWORD)),
      ('FileAlignment',              '{0}s'.format(_DWORD)),
      ('MajorOperatingSystemVersion','{0}s'.format(_WORD)),
      ('MinorOperatingSystemVersion','{0}s'.format(_WORD)),
      ('MajorImageVersion',          '{0}s'.format(_WORD)),
      ('MinorImageVersion',          '{0}s'.format(_WORD)),
      ('MajorSubsystemVersion',      '{0}s'.format(_WORD)),
      ('MinorSubsystemVersion',      '{0}s'.format(_WORD)),
      ('Win32VersionValue',          '{0}s'.format(_DWORD)),
      ('SizeOfImage',                '{0}s'.format(_DWORD)),
      ('SizeOfHeaders',              '{0}s'.format(_DWORD)),
      ('CheckSum',                   '{0}s'.format(_DWORD)),
      ('Subsystem',                  '{0}s'.format(_WORD)),
      ('DllCharacteristics',         '{0}s'.format(_WORD)),
      ('SizeOfStackReserve',         '{0}s'.format(_QWORD)),
      ('SizeOfStackCommit',          '{0}s'.format(_QWORD)),
      ('SizeOfHeapReserve',          '{0}s'.format(_QWORD)),
      ('SizeOfHeapCommit',           '{0}s'.format(_QWORD)),
      ('LoaderFlags',                '{0}s'.format(_DWORD)),
      ('NumberOfRvaAndSizes',        '{0}s'.format(_DWORD)),
    ]
  }

  _DATA_DIRECTORY = {
    'len': 128, # in bytes
    'fmt': [
      ('Export',                       '{0}s'.format(_DWORD)),
      ('Export_size',                  '{0}s'.format(_DWORD)),
      ('Import',                       '{0}s'.format(_DWORD)),
      ('Import_size',                  '{0}s'.format(_DWORD)),
      ('Resource',                     '{0}s'.format(_DWORD)),
      ('Resource_size',                '{0}s'.format(_DWORD)),
      ('Exception',                    '{0}s'.format(_DWORD)),
      ('Exception_size',               '{0}s'.format(_DWORD)),
      ('Security',                     '{0}s'.format(_DWORD)),
      ('Security_size',                '{0}s'.format(_DWORD)),
      ('BaseRelocationTable',          '{0}s'.format(_DWORD)),
      ('BaseRelocationTable_size',     '{0}s'.format(_DWORD)),
      ('Debug',                        '{0}s'.format(_DWORD)),
      ('Debug_size',                   '{0}s'.format(_DWORD)),
      ('ArchitectureSpecificData',     '{0}s'.format(_DWORD)),
      ('ArchitectureSpecificData_size','{0}s'.format(_DWORD)),
      ('GlobalPointerRegister',        '{0}s'.format(_DWORD)),
      ('GlobalPointerRegister_size',   '{0}s'.format(_DWORD)),
      ('ThreadLocalStorage',           '{0}s'.format(_DWORD)),
      ('ThreadLocalStorage_size',      '{0}s'.format(_DWORD)),
      ('LoadConfiguration',            '{0}s'.format(_DWORD)),
      ('LoadConfiguration_size',       '{0}s'.format(_DWORD)),
      ('BoundImport',                  '{0}s'.format(_DWORD)),
      ('BoundImport_size',             '{0}s'.format(_DWORD)),
      ('ImportAddressTable',           '{0}s'.format(_DWORD)),
      ('ImportAddressTable_size',      '{0}s'.format(_DWORD)),
      ('DelayImportTable',             '{0}s'.format(_DWORD)),
      ('DelayImportTable_size',        '{0}s'.format(_DWORD)),
      ('COMDescriptorTable',           '{0}s'.format(_DWORD)),
      ('COMDescriptorTable_size',      '{0}s'.format(_DWORD)),
      ('Reserved',                     '{0}s'.format(_DWORD)),
      ('Reserved_size',                '{0}s'.format(_DWORD)),
    ]
  }


  def __init__(self, filename):
    """ extract PE file pieces piece by piece """
    offset = 0
    self.file = open(filename, 'rb')
    self.d = {}
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse DOS header
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    self._unpack(self._DOS_HEADER, 'DOS_HEADER', offset)
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # extract DOS stub
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    self.file.seek(self._DOS_HEADER['len'])
    stub_len = self._uint(self.d['DOS_HEADER']['e_lfanew']) - self._DOS_HEADER['len']
    self.d['DOS_STUB'] = bytearray(struct.unpack('{0}s'.format(stub_len), self.file.read(stub_len))[0])
    offset += self._uint(self.d['DOS_HEADER']['e_lfanew'])
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse PE header
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    self._unpack(self._PE_HEADER, 'PE_HEADER', offset)
    offset += self._PE_HEADER['len']
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse optional image header
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if self._uint(self.d['PE_HEADER']['SizeOfOptionalHeader']) > 0:
      self.file.seek(offset)
      if self._uint(self.file.read(self._WORD)) == 0x20b:
        # parse 64 bit binary
        self._unpack(self._64_IMAGE_HEADER, 'IMAGE_HEADER', offset)
        offset += self._64_IMAGE_HEADER['len']
      else:
        # parse 32 bit binary
        self._unpack(self._32_IMAGE_HEADER, 'IMAGE_HEADER', offset)
        offset += self._32_IMAGE_HEADER['len']
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # parse data directory (number of directories varies by compiler)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      num_dirs = self._uint(self.d['IMAGE_HEADER']['NumberOfRvaAndSizes'])
      dirs_fmt = {
        'len': num_dirs * (2 * self._DWORD),
        'fmt': self._DATA_DIRECTORY['fmt'][:(num_dirs * 2)]
      }
      self._unpack(dirs_fmt, 'DATA_DIRECTORY', offset)
    else:
      self.d['IMAGE_HEADER'] = {}
      self.d['DATA_DIRECTORY'] = {}

  def __str__(self):
    """ display header internals as hex strings """
    def _recurse(d, r):
      for k in d.keys():
        if isinstance(d[k], dict):
          r[k] = {}
          _recurse(d[k], r[k])
        else:
          r[k] = binascii.hexlify(d[k])
    output = {}
    _recurse(self.d, output)
    return pprint.pformat(output, indent=2)

  def _unpack(self, src, dst, offset):
    """ internal function to unpack a given struct/header into an array of bytes """
    self.d[dst] = {}
    self.file.seek(offset)
    raw = struct.unpack(''.join([f[1] for f in src['fmt']]), self.file.read(src['len']))
    for i in range(len(raw)):
      self.d[dst][src['fmt'][i][0]] = bytearray(raw[i])
    self.file.seek(0)

  def _uint(self, f):
    """ inteprets a raw byte array as an int """
    if len(f) == 2:
      return struct.unpack('<H', f)[0]
    elif len(f) == 4:
      return struct.unpack('<I', f)[0]
    elif len(f) == 8:
      return struct.unpack('<Q', f)[0]

  def _int(self, f):
    """ inteprets a raw byte array as an unsigned int """
    if len(f) == 2:
      return struct.unpack('<h', f)[0]
    elif len(f) == 4:
      return struct.unpack('<i', f)[0]
    elif len(f) == 8:
      return struct.unpack('<q', f)[0]

  def _str(self, f):
    """ interprets a raw byte array as a string """
    return f.decode('UTF-8')
