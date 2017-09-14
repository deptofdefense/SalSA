
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

  _EXPORT_DIRECTORY = {
    'len': 40, # in bytes
    'fmt': [
      ('Characteristics',      'I'),
      ('TimeDateStamp',        'I'),
      ('MajorVersion',         'H'),
      ('MinorVersion',         'H'),
      ('Name',                 'I'),
      ('Base',                 'I'),
      ('NumberOfFunctions',    'I'),
      ('NumberOfNames',        'I'),
      ('AddressOfFunctions',   'I'),
      ('AddressOfNames',       'I'),
      ('AddressOfNameOrdinals','I'),
    ]
  }

  _DEBUG_DIRECTORY = {
    'len': 28, # in bytes
    'fmt': [
      ('Characteristics', 'I'),
      ('TimeDateStamp',   'I'),
      ('MajorVersion',    'H'),
      ('MinorVersion',    'H'),
      ('Type',            'I'),
      ('SizeOfData',      'I'),
      ('AddressOfRawData','I'),
      ('PointerToRawData','I'),
    ]
  }

  _IMPORT_DESCRIPTOR = {
    'len': 20, # in bytes
    'fmt': [
      ('OriginalFirstThunk','I'),
      ('TimeDateStamp',     'I'),
      ('ForwarderChain',    'I'),
      ('Name',              'I'),
      ('FirstThunk',        'I'),
    ]
  }

  _IMPORT_ENTRY = {
    'len': 20, # in bytes
    'fmt': [
      ('OriginalFirstThunk','I'),
      ('TimeDateStamp',     'I'),
      ('ForwarderChain',    'I'),
      ('Name',              'I'),
      ('FirstThunk',        'I'),
    ]
  }

  def __init__(self, filename):
    """ extract PE file piece by piece """
    offset = 0
    self.b64 = False
    self.file = open(filename, 'rb')
    self.d = {}
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse DOS header
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    self._unpack(self._DOS_HEADER, self.d, 'DOS_HEADER', offset)
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # extract DOS stub
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    stub_len = self.d['DOS_HEADER']['e_lfanew'] - self._DOS_HEADER['len']
    stub_program = self._read(self._DOS_HEADER['len'], stub_len)
    self.d['DOS_STUB'] = struct.unpack('{0}s'.format(stub_len), stub_program)[0]
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
      if struct.unpack('<H', self._read(offset, 2))[0] == 0x20b:
        # parse 64 bit binary
        self.b64 = True
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
         # only parse data directories we have specified/understand
        'len': min(num_dirs * 8, self._DATA_DIRECTORY['len']),
        'fmt': self._DATA_DIRECTORY['fmt'][:min((num_dirs * 2), len(self._DATA_DIRECTORY['fmt']))]
      }
      self._unpack(dirs_fmt, self.d, 'DATA_DIRECTORY', offset)
      offset += dirs_fmt['len']
    else:
      self.d['IMAGE_HEADER'] = {}
      self.d['DATA_DIRECTORY'] = {}
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse section headers
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    self.d['SECTIONS'] = []
    for i in range(self.d['PE_HEADER']['NumberOfSections']):
      section = {}
      self._unpack(self._SECTION_HEADER, section, 'data', offset)
      # fix section name to remove null byte padding
      section['data']['Name'] = section['data']['Name'].replace('\x00', '')
      offset += self._SECTION_HEADER['len']
      self.d['SECTIONS'].append(section['data'])
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse meaningful data directory entries (some not publicly documented)
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if self.d['DATA_DIRECTORY']:
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # debug directory (.debug)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['Debug_size'] > 0:
        # unpack debug directory
        debug_dir_offset = self.rva2offset(self.d['DATA_DIRECTORY']['Debug'])
        self._unpack(self._DEBUG_DIRECTORY, self.d, 'DEBUG_DIRECTORY', debug_dir_offset)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # export directory (.edata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['Export_size'] > 0:
        # unpack export directory
        export_dir_offset = self.rva2offset(self.d['DATA_DIRECTORY']['Export'])
        self._unpack(self._EXPORT_DIRECTORY, self.d, 'EXPORT_DIRECTORY', export_dir_offset)
        # get actual export file name from RVA
        self.d['EXPORT_DIRECTORY']['Name'] = self.rva2str(self.d['EXPORT_DIRECTORY']['Name'])
        self.d['EXPORTS'] = []
        # get offset to function array
        export_fun_offset = self.rva2offset(self.d['EXPORT_DIRECTORY']['AddressOfFunctions'])
        # unpack each 32 bit address
        for i in range(self.d['EXPORT_DIRECTORY']['NumberOfFunctions']):
          fun_rva = struct.unpack('<I', self._read(export_fun_offset + (i * 4), 4))[0]
          # check for forwarded export
          if fun_rva and ((self.d['DATA_DIRECTORY']['Export'] <= fun_rva) and
                          (fun_rva < (self.d['DATA_DIRECTORY']['Export'] +
                                      self.d['DATA_DIRECTORY']['Export_size']))):
            self.d['EXPORTS'].append({
              'offset': self.rva2str(fun_rva),
              'name': '',
              'ordinal': '',
            })
          # only include non-zero exports
          elif fun_rva:
            self.d['EXPORTS'].append({
              'offset': self.rva2offset(fun_rva),
              'name': '',
              'ordinal': self.d['EXPORT_DIRECTORY']['Base'] + i,
            })
        # fill out names/ordinals for exports if specified
        name_array_offset = self.rva2offset(self.d['EXPORT_DIRECTORY']['AddressOfNames'])
        ordinal_array_offset = self.rva2offset(self.d['EXPORT_DIRECTORY']['AddressOfNameOrdinals'])
        for i in range(self.d['EXPORT_DIRECTORY']['NumberOfNames']):
          # get RVA from array and then convert to actual offsets to get data from
          ordinal = struct.unpack('<H', self._read(ordinal_array_offset + (i * 2), 2))[0]
          name = self.rva2str(struct.unpack('<I', self._read(name_array_offset + (i * 4), 4))[0])
          # find the ordinal to place this name into
          for e in self.d['EXPORTS']:
            if e['ordinal'] == (ordinal + self.d['EXPORT_DIRECTORY']['Base']):
              e['name'] = name
              break
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # import directory (.idata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['Import_size'] > 0:
        import_desc = {}
        self.d['IMPORTS'] = []
        self.d['IMPORT_DIRECTORY'] = []
        import_desc_offset = self.rva2offset(self.d['DATA_DIRECTORY']['Import'])
        # unpack each import descriptor entry
        while True:
          self._unpack(self._IMPORT_DESCRIPTOR, import_desc, 'data', import_desc_offset)
          # check for empty entry
          if import_desc['data']['OriginalFirstThunk'] == 0:
            break
          # resolve the name of the import descriptor
          import_desc['data']['Name'] = self.rva2str(import_desc['data']['Name'])
          self.d['IMPORT_DIRECTORY'].append(import_desc['data'])
          # go to the next descriptor
          import_desc_offset += self._IMPORT_DESCRIPTOR['len']
          # parse all imports within the current descriptor
          imports = []
          import_entry_ptr = self.rva2offset(import_desc['data']['OriginalFirstThunk'])
          while True:
            import_entry = {'ordinal':'','name':'','hint':'','binding':''}
            # get the entry data pointer (32 or 64 bit pointer) and check for ordinal
            if self.b64:
              entry_rva = struct.unpack('<Q', self._read(import_entry_ptr, 8))[0]
              if entry_rva & (0x1 << 63):
                import_entry['ordinal'] = entry_rva & ~(0x1 << 63)
            else:
              entry_rva = struct.unpack('<I', self._read(import_entry_ptr, 4))[0]
              if entry_rva & (0x1 << 31):
                import_entry['ordinal'] = entry_rva & ~(0x1 << 31)
            # check for null entry
            if entry_rva == 0:
              break
            # if not an ordinal, then get entry data at pointer
            if not import_entry['ordinal']:
              # name pointer after hint which is 2 byes
              import_entry['hint'] = struct.unpack('<H', self._read(self.rva2offset(entry_rva), 2))[0]
              import_entry['name'] = self.rva2str(entry_rva + 2)
            # go to next pointer
            import_entry_ptr += 8 if (self.b64) else 4
            imports.append(import_entry)
          # add the current import entry to global dictionary
          self.d['IMPORTS'].append({
            'name': import_desc['data']['Name'],
            'functions': imports
          })
      # TODO: parse IAT
      if self.d['DATA_DIRECTORY']['Resource_size'] > 0:
        pass # TODO
      if self.d['DATA_DIRECTORY']['ThreadLocalStorage_size'] > 0:
        pass # TODO
      if self.d['DATA_DIRECTORY']['BaseRelocationTable_size'] > 0:
        pass # TODO

  def _read(self, addr, num_bytes):
    """ read bytes from file at a certain offset """
    self.file.seek(addr)
    d = self.file.read(num_bytes)
    return d

  def _unpack(self, src, dst, key, offset):
    """ internal function to unpack a given struct/header into an array of bytes """
    dst[key] = {}
    self.file.seek(offset)
    raw = struct.unpack('<' + ''.join([f[1] for f in src['fmt']]), self._read(offset, src['len']))
    for i in range(len(raw)):
      dst[key][src['fmt'][i][0]] = raw[i]

  def rva2str(self, rva):
    """ extract a null terminated string given an RVA """
    offset = self.rva2offset(rva)
    count = 0
    self.file.seek(offset)
    while ord(self.file.read(1)):
      count += 1
    return struct.unpack('{0}s'.format(count), self._read(offset, count))[0]

  def rva2offset(self, rva):
    """ get raw file offset from RVA """
    target = 0
    for section in self.d['SECTIONS']:
      if (rva < section['VirtualAddress']) and target:
        return target['PointerToRawData'] + (rva - target['VirtualAddress'])
      target = section
    return 0

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
