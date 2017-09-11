
import copy
import pprint
import struct
import binascii


class PE(object):

  _DOS_HEADER = {
    'len': 64, # in bytes
    'fmt': [
      ('e_magic',   'H'),
      ('e_cblp',    'H'),
      ('e_cp',      'H'),
      ('e_crlc',    'H'),
      ('e_cparhdr', 'H'),
      ('e_minalloc','H'),
      ('e_maxalloc','H'),
      ('e_ss',      'H'),
      ('e_sp',      'H'),
      ('e_csum',    'H'),
      ('e_ip',      'H'),
      ('e_cs',      'H'),
      ('e_lfarlc',  'H'),
      ('e_ovno',    'H'),
      ('e_res',     '8s'),
      ('e_oemid',   'H'),
      ('e_oeminfo', 'H'),
      ('e_res2',    '20s'),
      ('e_lfanew',  'I'),
    ]
  }

  _PE_HEADER = {
    'len': 24, # in bytes
    'fmt': [
      ('Signature',           'I'),
      ('Machine',             'H'),
      ('NumberOfSections',    'H'),
      ('TimeDateStamp',       'I'),
      ('PointerToSymbolTable','I'),
      ('NumberOfSymbols',     'I'),
      ('SizeOfOptionalHeader','H'),
      ('Characteristics',     'H'),
    ]
  }

  _32_IMAGE_HEADER = {
    'len': 96, # in bytes
    'fmt': [
      ('Magic',                      'H'),
      ('MajorLinkerVersion',         'B'),
      ('MinorLinkerVersion',         'B'),
      ('SizeOfCode',                 'I'),
      ('SizeOfInitializedData',      'I'),
      ('SizeOfUninitializedData',    'I'),
      ('AddressOfEntryPoint',        'I'),
      ('BaseOfCode',                 'I'),
      ('BaseOfData',                 'I'),
      ('ImageBase',                  'I'),
      ('SectionAlignment',           'I'),
      ('FileAlignment',              'I'),
      ('MajorOperatingSystemVersion','H'),
      ('MinorOperatingSystemVersion','H'),
      ('MajorImageVersion',          'H'),
      ('MinorImageVersion',          'H'),
      ('MajorSubsystemVersion',      'H'),
      ('MinorSubsystemVersion',      'H'),
      ('Win32VersionValue',          'I'),
      ('SizeOfImage',                'I'),
      ('SizeOfHeaders',              'I'),
      ('CheckSum',                   'I'),
      ('Subsystem',                  'H'),
      ('DllCharacteristics',         'H'),
      ('SizeOfStackReserve',         'I'),
      ('SizeOfStackCommit',          'I'),
      ('SizeOfHeapReserve',          'I'),
      ('SizeOfHeapCommit',           'I'),
      ('LoaderFlags',                'I'),
      ('NumberOfRvaAndSizes',        'I'),
    ]
  }

  _64_IMAGE_HEADER = {
    'len': 112, # in bytes
    'fmt': [
      ('Magic',                      'H'),
      ('MajorLinkerVersion',         'B'),
      ('MinorLinkerVersion',         'B'),
      ('SizeOfCode',                 'I'),
      ('SizeOfInitializedData',      'I'),
      ('SizeOfUninitializedData',    'I'),
      ('AddressOfEntryPoint',        'I'),
      ('BaseOfCode',                 'I'),
      ('ImageBase',                  'Q'),
      ('SectionAlignment',           'I'),
      ('FileAlignment',              'I'),
      ('MajorOperatingSystemVersion','H'),
      ('MinorOperatingSystemVersion','H'),
      ('MajorImageVersion',          'H'),
      ('MinorImageVersion',          'H'),
      ('MajorSubsystemVersion',      'H'),
      ('MinorSubsystemVersion',      'H'),
      ('Win32VersionValue',          'I'),
      ('SizeOfImage',                'I'),
      ('SizeOfHeaders',              'I'),
      ('CheckSum',                   'I'),
      ('Subsystem',                  'H'),
      ('DllCharacteristics',         'H'),
      ('SizeOfStackReserve',         'Q'),
      ('SizeOfStackCommit',          'Q'),
      ('SizeOfHeapReserve',          'Q'),
      ('SizeOfHeapCommit',           'Q'),
      ('LoaderFlags',                'I'),
      ('NumberOfRvaAndSizes',        'I'),
    ]
  }

  _DATA_DIRECTORY = {
    'len': 128, # in bytes
    'fmt': [
      ('Export',                       'I'),
      ('Export_size',                  'I'),
      ('Import',                       'I'),
      ('Import_size',                  'I'),
      ('Resource',                     'I'),
      ('Resource_size',                'I'),
      ('Exception',                    'I'),
      ('Exception_size',               'I'),
      ('Security',                     'I'),
      ('Security_size',                'I'),
      ('BaseRelocationTable',          'I'),
      ('BaseRelocationTable_size',     'I'),
      ('Debug',                        'I'),
      ('Debug_size',                   'I'),
      ('ArchitectureSpecificData',     'I'),
      ('ArchitectureSpecificData_size','I'),
      ('GlobalPointerRegister',        'I'),
      ('GlobalPointerRegister_size',   'I'),
      ('ThreadLocalStorage',           'I'),
      ('ThreadLocalStorage_size',      'I'),
      ('LoadConfiguration',            'I'),
      ('LoadConfiguration_size',       'I'),
      ('BoundImport',                  'I'),
      ('BoundImport_size',             'I'),
      ('ImportAddressTable',           'I'),
      ('ImportAddressTable_size',      'I'),
      ('DelayImportTable',             'I'),
      ('DelayImportTable_size',        'I'),
      ('COMDescriptorTable',           'I'),
      ('COMDescriptorTable_size',      'I'),
      ('Reserved',                     'I'),
      ('Reserved_size',                'I'),
    ]
  }

  _SECTION_HEADER = {
    'len': 40, # in bytes
    'fmt': [
      ('Name',                '8s'),
      ('VirtualSize',         'I'),
      ('VirtualAddress',      'I'),
      ('SizeOfRawData',       'I'),
      ('PointerToRawData',    'I'),
      ('PointerToRelocations','I'),
      ('PointerToLinenumbers','I'),
      ('NumberOfRelocations', 'H'),
      ('NumberOfLinenumbers', 'H'),
      ('Characteristics',     'I'),
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
    self._unpack(self._DOS_HEADER, self.d, 'DOS_HEADER', offset)
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # extract DOS stub
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    self.file.seek(self._DOS_HEADER['len'])
    stub_len = self.d['DOS_HEADER']['e_lfanew'] - self._DOS_HEADER['len']
    self.d['DOS_STUB'] = struct.unpack('{0}s'.format(stub_len), self.file.read(stub_len))[0]
    offset += self.d['DOS_HEADER']['e_lfanew']
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse PE header
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    self._unpack(self._PE_HEADER, self.d, 'PE_HEADER', offset)
    offset += self._PE_HEADER['len']
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse optional image header
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if self.d['PE_HEADER']['SizeOfOptionalHeader'] > 0:
      self.file.seek(offset)
      if self.file.read(2) == 0x20b:
        # parse 64 bit binary
        self._unpack(self._64_IMAGE_HEADER, self.d, 'IMAGE_HEADER', offset)
        offset += self._64_IMAGE_HEADER['len']
      else:
        # parse 32 bit binary
        self._unpack(self._32_IMAGE_HEADER, self.d, 'IMAGE_HEADER', offset)
        offset += self._32_IMAGE_HEADER['len']
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # parse data directory (number of directories varies by compiler)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      num_dirs = self.d['IMAGE_HEADER']['NumberOfRvaAndSizes']
      dirs_fmt = {
        'len': num_dirs * 8,
        'fmt': self._DATA_DIRECTORY['fmt'][:(num_dirs * 2)]
      }
      self._unpack(dirs_fmt, self.d['IMAGE_HEADER'], 'DATA_DIRECTORY', offset)
      offset += dirs_fmt['len']
    else:
      self.d['IMAGE_HEADER'] = {}
      self.d['IMAGE_HEADER']['DATA_DIRECTORY'] = {}
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse section headers
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    self.d['SECTIONS'] = []
    for i in range(self.d['PE_HEADER']['NumberOfSections']):
      section = {}
      self._unpack(self._SECTION_HEADER, section, 'data', offset)
      offset += self._SECTION_HEADER['len']
      self.d['SECTIONS'].append(section['data'])

  def _unpack(self, src, dst, key, offset):
    """ internal function to unpack a given struct/header into an array of bytes """
    dst[key] = {}
    self.file.seek(offset)
    raw = struct.unpack('<' + ''.join([f[1] for f in src['fmt']]), self.file.read(src['len']))
    for i in range(len(raw)):
      dst[key][src['fmt'][i][0]] = raw[i]
    self.file.seek(0)

  def tohex(self):
    """ display internals as hex strings """
    def _recurse(d):
      if isinstance(d, dict):
        for k in d.keys():
          d[k] = _recurse(d[k])
        return d
      elif isinstance(d, list):
        for i in range(len(d)):
          d[i] = _recurse(d[i])
        return d
      elif isinstance(d, int):
        return hex(d)
      elif isinstance(d, str):
        # return raw ascii strings with . for unknwown bytes
        return ''.join([x if ((31 < ord(x)) and (ord(x) < 127)) else '.' for x in d])
    output = copy.deepcopy(self.d)
    _recurse(output)
    return pprint.pformat(output, indent=2)
