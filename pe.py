
import copy
import struct
import pprint


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

  _DELAY_IMPORT_DESCRIPTOR = {
    'len': 32, # in bytes
    'fmt': [
      ('Attributes',             'I'),
      ('Name',                   'I'),
      ('ModuleHandle',           'I'),
      ('ImportAddressTable',     'I'),
      ('ImportNameTable',        'I'),
      ('BoundImportAddressTable','I'),
      ('UnloadInformationTable', 'I'),
      ('TimeDateStamp',          'I'),
    ]
  }

  _BOUND_IMPORT_DESCRIPTOR = {
    'len': 8, # in bytes
    'fmt': [
      ('TimeDateStamp',              'I'),
      ('OffsetModuleName',           'H'),
      ('NumberOfModuleForwarderRefs','H'),
    ]
  }

  _BASE_RELOCATION = {
    'len': 8, # in bytes
    'fmt': [
      ('VirtualAddress','I'),
      ('SizeOfBlock',   'I'),
    ]
  }

  _EXCEPTION_FUNCTION_ENTRY = {
    'len': 12, # in bytes
    'fmt': [
      ('StartingAddress',  'I'),
      ('EndingAddress',    'I'),
      ('UnwindInfoAddress','I'),
    ]
  }

  _32_TLS_DIRECTORY = {
    'len': 24, # in bytes
    'fmt': [
      ('StartAddressOfRawData','I'),
      ('EndAddressOfRawData',  'I'),
      ('AddressOfIndex',       'I'),
      ('AddressOfCallBacks',   'I'),
      ('SizeOfZeroFill',       'I'),
      ('Characteristics',      'I'),
    ]
  }

  _64_TLS_DIRECTORY = {
    'len': 40, # in bytes
    'fmt': [
      ('StartAddressOfRawData','Q'),
      ('EndAddressOfRawData',  'Q'),
      ('AddressOfIndex',       'Q'),
      ('AddressOfCallBacks',   'Q'),
      ('SizeOfZeroFill',       'I'),
      ('Characteristics',      'I'),
    ]
  }

  _32_LOAD_CONFIG_DIRECTORY = {
    'len': 72, # in bytes
    'fmt': [
      ('Size',                         'I'),
      ('TimeDateStamp',                'I'),
      ('MajorVersion',                 'H'),
      ('MinorVersion',                 'H'),
      ('GlobalFlagsClear',             'I'),
      ('GlobalFlagsSet',               'I'),
      ('CriticalSectionDefaultTimeout','I'),
      ('DeCommitFreeBlockThreshold',   'I'),
      ('DeCommitTotalFreeThreshold',   'I'),
      ('LockPrefixTable',              'I'),
      ('MaximumAllocationSize',        'I'),
      ('VirtualMemoryThreshold',       'I'),
      ('ProcessHeapFlags',             'I'),
      ('ProcessAffinityMask',          'I'),
      ('CSDVersion',                   'H'),
      ('Reserved1',                    'H'),
      ('EditList',                     'I'),
      ('SecurityCookie',               'I'),
      ('SEHandlerTable',               'I'),
      ('SEHandlerCount',               'I'),
    ]
  }

  _64_LOAD_CONFIG_DIRECTORY = {
    'len': 112, # in bytes
    'fmt': [
      ('Size',                         'I'),
      ('TimeDateStamp',                'I'),
      ('MajorVersion',                 'H'),
      ('MinorVersion',                 'H'),
      ('GlobalFlagsClear',             'I'),
      ('GlobalFlagsSet',               'I'),
      ('CriticalSectionDefaultTimeout','I'),
      ('DeCommitFreeBlockThreshold',   'Q'),
      ('DeCommitTotalFreeThreshold',   'Q'),
      ('LockPrefixTable',              'Q'),
      ('MaximumAllocationSize',        'Q'),
      ('VirtualMemoryThreshold',       'Q'),
      ('ProcessAffinityMask',          'Q'),
      ('ProcessHeapFlags',             'I'),
      ('CSDVersion',                   'H'),
      ('Reserved1',                    'H'),
      ('EditList',                     'Q'),
      ('SecurityCookie',               'Q'),
      ('SEHandlerTable',               'Q'),
      ('SEHandlerCount',               'Q'),
    ]
  }

  _RESOURCE_DIRECTORY = {
    'len': 16, # in bytes
    'fmt': [
      ('Characteristics',     'I'),
      ('TimeDateStamp',       'I'),
      ('MajorVersion',        'H'),
      ('MinorVersion',        'H'),
      ('NumberOfNamedEntries','H'),
      ('NumberOfIdEntries',   'H'),
    ]
  }


  def __init__(self, filename):
    """ extract PE file piece by piece """
    offset = 0
    self.d = {}
    self.b64 = False
    self.file = open(filename, 'rb')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse DOS header
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    self._unpack(self._DOS_HEADER, self.d, 'DOS_HEADER', offset)
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # extract DOS stub
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    stub_len = self.d['DOS_HEADER']['e_lfanew'] - self._DOS_HEADER['len']
    stub_program = self.read(self._DOS_HEADER['len'], stub_len)
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
      if struct.unpack('<H', self.read(offset, 2))[0] == 0x20b:
        # parse 64 bit binary
        self.b64 = True
        self._unpack(self._64_IMAGE_HEADER, self.d, 'IMAGE_HEADER', offset)
        offset += self._64_IMAGE_HEADER['len']
      else:
        # parse 32 bit binary (0x10b)
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
    # extract data directory entries (some not publicly documented...)
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if self.d['DATA_DIRECTORY']:
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # debug directory (.debug)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['Debug_size'] > 0:
        self._unpack(self._DEBUG_DIRECTORY, self.d, 'DEBUG_DIRECTORY',
                     self.rva2offset(self.d['DATA_DIRECTORY']['Debug']))
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # export directory (.edata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['Export_size'] > 0:
        self._unpack(self._EXPORT_DIRECTORY, self.d, 'EXPORT_DIRECTORY',
                     self.rva2offset(self.d['DATA_DIRECTORY']['Export']))
        # get actual export file name from RVA
        self.d['EXPORT_DIRECTORY']['Name'] = self.rva2str(self.d['EXPORT_DIRECTORY']['Name'])
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # import directory (.idata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['Import_size'] > 0:
        import_desc = {}
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
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # bound import directory (.idata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['BoundImport_size'] > 0:
        self.d['BOUND_IMPORTS_DIRECTORY'] = []
        bound_import_offset = self.rva2offset(self.d['DATA_DIRECTORY']['BoundImport'])
        # unpack array of BOUND_IMPORT_DESCRIPTORs
        while True:
          bound_import_desc = {}
          self._unpack(self._BOUND_IMPORT_DESCRIPTOR, bound_import_desc, 'data', bound_import_offset)
          # check for null terminator
          if bound_import_desc['data']['TimeDateStamp'] == 0:
            break
          # goto next descriptor
          bound_import_offset += self._BOUND_IMPORT_DESCRIPTOR['len']
          # replace name field with actual string
          bound_import_desc['data']['OffsetModuleName'] = self.rva2str(self.d['DATA_DIRECTORY']['BoundImport'] +
                                                                       bound_import_desc['data']['OffsetModuleName'])
          # add to class dictionary
          self.d['BOUND_IMPORTS_DIRECTORY'].append(bound_import_desc['data'])
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # relocation directory (.reloc)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['BaseRelocationTable_size'] > 0:
        self.d['RELOCATION_DIRECTORY'] = []
        base_offset = self.rva2offset(self.d['DATA_DIRECTORY']['BaseRelocationTable'])
        block_offset = base_offset
        # unpack array of BASE_RELOCATION
        while block_offset < (base_offset + self.d['DATA_DIRECTORY']['BaseRelocationTable_size']):
          reloc_entry = {}
          self._unpack(self._BASE_RELOCATION, reloc_entry, 'data', block_offset)
          # goto next descriptor
          block_offset += reloc_entry['data']['SizeOfBlock']
          # add to class dictionary
          self.d['RELOCATION_DIRECTORY'].append(reloc_entry['data'])
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # exception directory (.pdata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['Exception_size'] > 0:
        # parse as many as the size dictates
        self.d['EXCEPTION_DIRECTORY'] = []
        entry_offset = self.rva2offset(self.d['DATA_DIRECTORY']['Exception'])
        # unpack array of EXCEPTION_FUNCTION_ENTRY
        base_offset = entry_offset
        while entry_offset < (base_offset + self.d['DATA_DIRECTORY']['Exception_size']):
          exception_entry = {}
          self._unpack(self._EXCEPTION_FUNCTION_ENTRY, exception_entry, 'data', entry_offset)
          # goto next entry
          entry_offset += self._EXCEPTION_FUNCTION_ENTRY['len']
          # add to class dictionary
          self.d['EXCEPTION_DIRECTORY'].append(exception_entry['data'])
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # TLS directory (.tls)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['ThreadLocalStorage_size'] > 0:
        if self.b64:
          self._unpack(self._64_TLS_DIRECTORY, self.d, 'TLS_DIRECTORY',
                     self.rva2offset(self.d['DATA_DIRECTORY']['ThreadLocalStorage']))
        else:
          self._unpack(self._32_TLS_DIRECTORY, self.d, 'TLS_DIRECTORY',
                     self.rva2offset(self.d['DATA_DIRECTORY']['ThreadLocalStorage']))
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # delay imports directory (.idata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['DelayImportTable_size'] > 0:
        import_desc = {}
        self.d['DELAY_IMPORT_DIRECTORY'] = []
        import_desc_offset = self.rva2offset(self.d['DATA_DIRECTORY']['DelayImportTable'])
        # unpack each delay import descriptor entry
        while True:
          self._unpack(self._DELAY_IMPORT_DESCRIPTOR, import_desc, 'data', import_desc_offset)
          # check for empty entry
          if import_desc['data']['Name'] == 0:
            break
          # resolve the name of the import descriptor
          import_desc['data']['Name'] = self.rva2str(import_desc['data']['Name'])
          self.d['DELAY_IMPORT_DIRECTORY'].append(import_desc['data'])
          # go to the next descriptor
          import_desc_offset += self._DELAY_IMPORT_DESCRIPTOR['len']
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # configuration directory (.rdata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['LoadConfiguration_size'] > 0:
        if self.b64:
          self._unpack(self._64_LOAD_CONFIG_DIRECTORY, self.d, 'LOAD_CONFIG_DIRECTORY',
                     self.rva2offset(self.d['DATA_DIRECTORY']['LoadConfiguration']))
        else:
          self._unpack(self._32_LOAD_CONFIG_DIRECTORY, self.d, 'LOAD_CONFIG_DIRECTORY',
                     self.rva2offset(self.d['DATA_DIRECTORY']['LoadConfiguration']))
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # configuration directory (.rsrc)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self.d['DATA_DIRECTORY']['Resource_size'] > 0:
        self._unpack(self._RESOURCE_DIRECTORY, self.d, 'RESOURCE_DIRECTORY',
                     self.rva2offset(self.d['DATA_DIRECTORY']['Resource']))

  def __str__(self):
    """ format internals as hex strings """
    output = copy.deepcopy(self.d)
    self._fmt2hex(output)
    return pprint.pformat(output)

  def _unpack(self, src, dst, key, offset):
    """ internal function to unpack a given struct/header into an array of bytes """
    dst[key] = {}
    self.file.seek(offset)
    raw = struct.unpack('<' + ''.join([f[1] for f in src['fmt']]), self.read(offset, src['len']))
    for i in range(len(raw)):
      dst[key][src['fmt'][i][0]] = raw[i]

  def _fmt2hex(self, d):
    """ format dictionary 'd' into a readable hex format """
    if isinstance(d, dict):
      for k in d.keys():
        d[k] = self._fmt2hex(d[k])
      return d
    elif isinstance(d, list):
      for i in range(len(d)):
        d[i] = self._fmt2hex(d[i])
      return d
    elif isinstance(d, int):
      return hex(d)
    elif isinstance(d, str):
      # return raw ascii strings with . for unknwown bytes
      return ''.join([x if ((31 < ord(x)) and (ord(x) < 127)) else '.' for x in d])

  def _parseINT(self, rva):
    """ internal helper to parse the Import Name Table (INT) for
        delay import tables and normal (static) import tables """
    desc_imports = []
    # parse all imports within the current descriptor
    import_entry_ptr = self.rva2offset(rva)
    while True:
      import_entry = {'ordinal':'','name':'','hint':''}
      # get the entry data pointer (32 or 64 bit pointer) and check for ordinal
      if self.b64:
        entry_rva = struct.unpack('<Q', self.read(import_entry_ptr, 8))[0]
        if entry_rva & (0x1 << 63):
          import_entry['ordinal'] = entry_rva & ~(0x1 << 63)
      else:
        entry_rva = struct.unpack('<I', self.read(import_entry_ptr, 4))[0]
        if entry_rva & (0x1 << 31):
          import_entry['ordinal'] = entry_rva & ~(0x1 << 31)
      # check for null entry
      if entry_rva == 0:
        break
      # if not an ordinal, then get entry data at pointer
      if not import_entry['ordinal']:
        # name pointer after hint which is 2 byes
        import_entry['hint'] = struct.unpack('<H', self.read(self.rva2offset(entry_rva), 2))[0]
        import_entry['name'] = self.rva2str(entry_rva + 2)
      # go to next pointer
      import_entry_ptr += 8 if (self.b64) else 4
      desc_imports.append(import_entry)
    return desc_imports

  def _parseResourceRecursive(self, dir_rva, nodes, path):
    """ take a base RVA to an _RESOURCE_DIRECTORY and extract
        all RESOURCE_ENTRYs inside recursively into nodes """
    # get info from _RESOURCE_DIRECTORY
    base = self.rva2offset(dir_rva)
    num_names = struct.unpack('<H', self.read(base + 12, 2))[0]
    num_ids = struct.unpack('<H', self.read(base + 14, 2))[0]
    # parse each RESOURCE_DIRECTORY_ENTRY
    entry_offset = base + self._RESOURCE_DIRECTORY['len']
    for i in range(num_names + num_ids):
      # extract Name and OffsetToData for this RESOURCE_DIRECTORY_ENTRY
      ename =  struct.unpack('<I', self.read(entry_offset, 4))[0]
      eoffset = struct.unpack('<I', self.read(entry_offset + 4, 4))[0]
      # parse name/id for entry
      next_path = path
      if ename & (0x1 << 31):
        # name is a string RVA
        ename_base = self.rva2offset(self.d['DATA_DIRECTORY']['Resource'] + (ename & ~(0x1 << 31)))
        ename_len = struct.unpack('<H', self.read(ename_base, 2))[0]
        # decode UTF-16LE string
        ename_raw = struct.unpack('{0}s'.format(ename_len * 2), self.read(ename_base + 2, ename_len * 2))[0]
        next_path += ename_raw.decode('UTF-16LE')
      else:
        # name is an ID
        next_path += str(ename & 0xFFFF)
      # check for another directory to parse
      if eoffset & (0x1 << 31):
        # directory offset. recurse downwards
        self._parseResourceRecursive(self.d['DATA_DIRECTORY']['Resource'] + (eoffset & ~(0x1 << 31)), nodes, next_path + '/')
      else:
        node = {}
        # data offset. extract codepage, data, and language
        data_base = self.rva2offset(self.d['DATA_DIRECTORY']['Resource'] + (eoffset & ~(0x1 << 31)))
        data_rva = struct.unpack('<I', self.read(data_base, 4))[0]
        data_len = struct.unpack('<I', self.read(data_base + 4, 4))[0]
        node['codepage'] = struct.unpack('<I', self.read(data_base + 8, 4))[0]
        node['data'] = struct.unpack('{0}s'.format(data_len), self.read(self.rva2offset(data_rva), data_len))[0]
        node['lang'] = ename & 0xFFFF
        node['path'] = path
        # append data to the current level in recursion
        nodes.append(node)
      # goto the next directory entry
      entry_offset += 8

  def read(self, addr, num_bytes):
    """ read bytes from file at a certain offset """
    self.file.seek(addr)
    d = self.file.read(num_bytes)
    return d

  def dict(self):
    """ returns a copy of internal PE headers for user modification as
        a python dictionary """
    return copy.deepcopy(self.d)

  def rva2str(self, rva):
    """ extract a null terminated string given an RVA """
    offset = self.rva2offset(rva)
    count = 0
    self.file.seek(offset)
    while ord(self.file.read(1)):
      count += 1
    return struct.unpack('{0}s'.format(count), self.read(offset, count))[0]

  def rva2offset(self, rva):
    """ get raw file offset from RVA """
    for section in self.d['SECTIONS']:
      if (section['VirtualAddress'] <= rva) and (rva < (section['VirtualAddress'] + section['VirtualSize'])):
        return section['PointerToRawData'] + (rva - section['VirtualAddress'])
    print('[-] WARNING: Relative Virtual Address: ' + hex(rva) + ' does not fall inside any specified section')
    return 0

  def va2rva(self, va):
    """ take a virtual address and scale it back by the
        imagebase in the image optional header """
    return va - self.d['IMAGE_HEADER']['ImageBase']

  def parse_exports(self):
    """ try and follow the export directory and return PE exports """
    exports = []
    if self.d['DATA_DIRECTORY'] and (self.d['DATA_DIRECTORY']['Export_size'] > 0):
      # get offset to function array
      export_fun_offset = self.rva2offset(self.d['EXPORT_DIRECTORY']['AddressOfFunctions'])
      # unpack each 32 bit address
      for i in range(self.d['EXPORT_DIRECTORY']['NumberOfFunctions']):
        fun_rva = struct.unpack('<I', self.read(export_fun_offset + (i * 4), 4))[0]
        # check for forwarded export
        if fun_rva and ((self.d['DATA_DIRECTORY']['Export'] <= fun_rva) and
                        (fun_rva < (self.d['DATA_DIRECTORY']['Export'] +
                                    self.d['DATA_DIRECTORY']['Export_size']))):
          exports.append({
            'offset': self.rva2str(fun_rva),
            'name': '',
            'ordinal': '',
          })
        # only include non-zero exports
        elif fun_rva:
          exports.append({
            'offset': self.rva2offset(fun_rva),
            'name': '',
            'ordinal': self.d['EXPORT_DIRECTORY']['Base'] + i,
          })
      # fill out names/ordinals for exports if specified
      name_array_offset = self.rva2offset(self.d['EXPORT_DIRECTORY']['AddressOfNames'])
      ordinal_array_offset = self.rva2offset(self.d['EXPORT_DIRECTORY']['AddressOfNameOrdinals'])
      for i in range(self.d['EXPORT_DIRECTORY']['NumberOfNames']):
        # get RVA from array and then convert to actual offsets to get data from
        ordinal = struct.unpack('<H', self.read(ordinal_array_offset + (i * 2), 2))[0]
        name = self.rva2str(struct.unpack('<I', self.read(name_array_offset + (i * 4), 4))[0])
        # find the ordinal to place this name into
        for e in exports:
          if e['ordinal'] == (ordinal + self.d['EXPORT_DIRECTORY']['Base']):
            e['name'] = name
            break
    return exports

  def parse_imports(self):
    """ try and follow the delay-load and static import directories
        and return PE imports """
    imports = []
    if self.d['DATA_DIRECTORY'] and (self.d['DATA_DIRECTORY']['Import_size'] > 0):
      # go through each import descriptor and get list of imports
      for import_desc in self.d['IMPORT_DIRECTORY']:
        desc_imports = self._parseINT(import_desc['OriginalFirstThunk'])
        imports.append({
          'dll': import_desc['Name'],
          'functions': desc_imports,
        })
    if self.d['DATA_DIRECTORY'] and (self.d['DATA_DIRECTORY']['DelayImportTable_size'] > 0):
      # go through each import descriptor and get list of imports
      for import_desc in self.d['DELAY_IMPORT_DIRECTORY']:
        desc_imports = self._parseINT(import_desc['ImportNameTable'])
        imports.append({
          'dll': import_desc['Name'],
          'functions': desc_imports,
        })
    return imports

  def parse_relocations(self):
    """ try and follow the relocations directory and return PE relocations """
    relocs = []
    if self.d['DATA_DIRECTORY'] and (self.d['DATA_DIRECTORY']['BaseRelocationTable_size'] > 0):
      # go through each relocation block
      block_offset = self.rva2offset(self.d['DATA_DIRECTORY']['BaseRelocationTable'])
      for reloc_block in self.d['RELOCATION_DIRECTORY']:
        reloc_entries = []
        # parse all relocations within the current block
        block_base = block_offset
        block_offset += self._BASE_RELOCATION['len']
        while block_offset < (block_base + reloc_block['SizeOfBlock']):
          reloc = {}
          # unpack specific relocation
          page_offset = struct.unpack('<H', self.read(block_offset, 2))[0] & ~0xF000
          reloc['type'] = (struct.unpack('<H', self.read(block_offset, 2))[0] & 0xF000) >> 12
          reloc['rva'] = page_offset + reloc_block['VirtualAddress']
          # goto next relocation
          block_offset += 2
          reloc_entries.append(reloc)
        # get section RVA for this relocation block
        section_name = None
        for section in self.d['SECTIONS']:
          if ((section['VirtualAddress'] <= reloc_block['VirtualAddress']) and
              (reloc_block['VirtualAddress'] < (section['VirtualAddress'] + section['VirtualSize']))):
            section_name = section['Name']
            break
        if not section_name:
          print('[-] WARNING: Relocation Relative Virtual Address: ' + hex(reloc_block['VirtualAddress']) +
                ' does not fall inside any specified section')
          section_name = ''
        relocs.append({
          'relocations': reloc_entries,
          'section': section_name,
        })
    return relocs

  def parse_tls(self):
    """ simply return any TLS RVA function pointers in the array
        'AddressOfCallBacks' and any TLS data """
    data = ''
    callbacks = []
    if self.d['DATA_DIRECTORY'] and (self.d['DATA_DIRECTORY']['ThreadLocalStorage_size'] > 0):
      # extract binary data for TLS storage
      data_len = abs(self.d['TLS_DIRECTORY']['EndAddressOfRawData'] - self.d['TLS_DIRECTORY']['StartAddressOfRawData'])
      if data_len:
        data_start_offset = self.rva2offset(self.va2rva(self.d['TLS_DIRECTORY']['StartAddressOfRawData']))
        data = struct.unpack('{0}s'.format(data_len), self.read(data_start_offset, data_len))[0]
      # follow array and get each function pointer
      array_offset = self.rva2offset(self.va2rva(self.d['TLS_DIRECTORY']['AddressOfCallBacks']))
      while True:
        if self.b64:
          callback = struct.unpack('<Q', self.read(array_offset, 8))[0]
          array_offset += 8
        else:
          callback = struct.unpack('<I', self.read(array_offset, 4))[0]
          array_offset += 4
        # check for null
        if callback == 0:
          break
        callbacks.append(self.rva2offset(self.va2rva((callback))))
    return {'data': data, 'callback_offsets': callbacks}

  def parse_resources(self):
    """ parse resources filesystem and return all information serialized """
    rdir = []
    if self.d['DATA_DIRECTORY'] and (self.d['DATA_DIRECTORY']['Resource_size'] > 0):
      # recurse down the resource directory
      self._parseResourceRecursive(self.d['DATA_DIRECTORY']['Resource'], rdir, '/')
    return rdir
