
import os
import re
import copy
import struct
import pprint


class PE(object):

  _h = {
    'DOS_HEADER': {
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
    },

    'PE_HEADER': {
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
    },

    'IMAGE_HEADER_32': {
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
    },

    'IMAGE_HEADER_64': {
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
    },

    'DATA_DIRECTORY': {
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
        ('CertificateTable',             'I'),
        ('CertificateTable_size',        'I'),
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
        ('CLRRuntimeHeader',             'I'),
        ('CLRRuntimeHeader_size',        'I'),
        ('Reserved',                     'I'),
        ('Reserved_size',                'I'),
      ]
    },

    'SECTION_HEADER': {
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
    },

    'EXPORT_DIRECTORY': {
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
    },

    'DEBUG_DIRECTORY': {
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
    },

    'IMPORT_DESCRIPTOR': {
      'len': 20, # in bytes
      'fmt': [
        ('OriginalFirstThunk','I'),
        ('TimeDateStamp',     'I'),
        ('ForwarderChain',    'I'),
        ('Name',              'I'),
        ('FirstThunk',        'I'),
      ]
    },

    'DELAY_IMPORT_DESCRIPTOR': {
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
    },

    'BOUND_IMPORT_DESCRIPTOR': {
      'len': 8, # in bytes
      'fmt': [
        ('TimeDateStamp',              'I'),
        ('OffsetModuleName',           'H'),
        ('NumberOfModuleForwarderRefs','H'),
      ]
    },

    'BASE_RELOCATION': {
      'len': 8, # in bytes
      'fmt': [
        ('VirtualAddress','I'),
        ('SizeOfBlock',   'I'),
      ]
    },

    'EXCEPTION_FUNCTION_ENTRY': {
      'len': 12, # in bytes
      'fmt': [
        ('StartingAddress',  'I'),
        ('EndingAddress',    'I'),
        ('UnwindInfoAddress','I'),
      ]
    },

    'TLS_DIRECTORY_32': {
      'len': 24, # in bytes
      'fmt': [
        ('StartAddressOfRawData','I'),
        ('EndAddressOfRawData',  'I'),
        ('AddressOfIndex',       'I'),
        ('AddressOfCallBacks',   'I'),
        ('SizeOfZeroFill',       'I'),
        ('Characteristics',      'I'),
      ]
    },

    'TLS_DIRECTORY_64': {
      'len': 40, # in bytes
      'fmt': [
        ('StartAddressOfRawData','Q'),
        ('EndAddressOfRawData',  'Q'),
        ('AddressOfIndex',       'Q'),
        ('AddressOfCallBacks',   'Q'),
        ('SizeOfZeroFill',       'I'),
        ('Characteristics',      'I'),
      ]
    },

    'LOAD_CONFIG_DIRECTORY_32': {
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
    },

    'LOAD_CONFIG_DIRECTORY_64': {
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
    },

    'RESOURCE_DIRECTORY': {
      'len': 16, # in bytes
      'fmt': [
        ('Characteristics',     'I'),
        ('TimeDateStamp',       'I'),
        ('MajorVersion',        'H'),
        ('MinorVersion',        'H'),
        ('NumberOfNamedEntries','H'),
        ('NumberOfIdEntries',   'H'),
      ]
    },
  }

  def __init__(self, filename):
    """ extract PE file piece by piece """
    offset = 0
    self._d = {}
    self._b64 = False
    self._file = open(filename, 'rb')
    try:
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # parse DOS header
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      self._d['DOS_HEADER'] = self._unpack(self._h['DOS_HEADER'], offset)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # extract DOS stub
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      stub_len = self._d['DOS_HEADER']['e_lfanew'] - self._h['DOS_HEADER']['len']
      stub_program = self.read(self._h['DOS_HEADER']['len'], stub_len)
      self._d['DOS_STUB'] = struct.unpack('{0}s'.format(stub_len), stub_program)[0]
      offset += self._d['DOS_HEADER']['e_lfanew']
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # parse PE header
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      self._d['PE_HEADER'] = self._unpack(self._h['PE_HEADER'], offset)
      offset += self._h['PE_HEADER']['len']
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # parse optional image header
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self._d['PE_HEADER']['SizeOfOptionalHeader'] > 0:
        if struct.unpack('<H', self.read(offset, 2))[0] == 0x20b:
          # parse 64 bit binary
          self._b64 = True
          self._d['IMAGE_HEADER'] = self._unpack(self._h['IMAGE_HEADER_64'], offset)
          offset += self._h['IMAGE_HEADER_64']['len']
        else:
          # parse 32 bit binary (0x10b)
          self._d['IMAGE_HEADER'] = self._unpack(self._h['IMAGE_HEADER_32'], offset)
          offset += self._h['IMAGE_HEADER_32']['len']
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # parse data directory (number of directories varies by compiler)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        num_dirs = self._d['IMAGE_HEADER']['NumberOfRvaAndSizes']
        dirs_fmt = {
           # only parse data directories we have specified/understand
          'len': min(num_dirs * 8, self._h['DATA_DIRECTORY']['len']),
          'fmt': self._h['DATA_DIRECTORY']['fmt'][:min((num_dirs * 2), len(self._h['DATA_DIRECTORY']['fmt']))]
        }
        self._d['DATA_DIRECTORY'] = self._unpack(dirs_fmt, offset)
        offset += dirs_fmt['len']
      else:
        self._d['IMAGE_HEADER'] = {}
        self._d['DATA_DIRECTORY'] = {}
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # parse section headers
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      self._d['SECTIONS'] = []
      for i in range(self._d['PE_HEADER']['NumberOfSections']):
        section = self._unpack(self._h['SECTION_HEADER'], offset)
        # fix section name to remove null byte padding
        section['Name'] = section['Name'].replace('\x00', '')
        offset += self._h['SECTION_HEADER']['len']
        self._d['SECTIONS'].append(section)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # extract data directory entries (some not publicly documented...)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if self._d['DATA_DIRECTORY']:
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # debug directory (.debug)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if self._d['DATA_DIRECTORY']['Debug_size'] > 0:
          self._d['DEBUG_DIRECTORY'] = self._unpack(self._h['DEBUG_DIRECTORY'], self.rva2offset(self._d['DATA_DIRECTORY']['Debug']))
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # export directory (.edata)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if self._d['DATA_DIRECTORY']['Export_size'] > 0:
          self._d['EXPORT_DIRECTORY'] = self._unpack(self._h['EXPORT_DIRECTORY'], self.rva2offset(self._d['DATA_DIRECTORY']['Export']))
          # get actual export file name from RVA
          self._d['EXPORT_DIRECTORY']['Name'] = self.rva2str(self._d['EXPORT_DIRECTORY']['Name'])
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # import directory (.idata)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if self._d['DATA_DIRECTORY']['Import_size'] > 0:
          self._d['IMPORT_DIRECTORY'] = []
          import_desc_offset = self.rva2offset(self._d['DATA_DIRECTORY']['Import'])
          # unpack each import descriptor entry
          while True:
            import_desc = self._unpack(self._h['IMPORT_DESCRIPTOR'], import_desc_offset)
            # check for empty entry
            if import_desc['OriginalFirstThunk'] == 0:
              break
            # resolve the name of the import descriptor
            import_desc['Name'] = self.rva2str(import_desc['Name'])
            self._d['IMPORT_DIRECTORY'].append(import_desc)
            # go to the next descriptor
            import_desc_offset += self._h['IMPORT_DESCRIPTOR']['len']
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # bound import directory (.idata)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if self._d['DATA_DIRECTORY']['BoundImport_size'] > 0:
          self._d['BOUND_IMPORTS_DIRECTORY'] = []
          bound_import_offset = self.rva2offset(self._d['DATA_DIRECTORY']['BoundImport'])
          # unpack array of BOUND_IMPORT_DESCRIPTORs
          while True:
            bound_import_desc = self._unpack(self._h['BOUND_IMPORT_DESCRIPTOR'], bound_import_offset)
            # check for null terminator
            if bound_import_desc['TimeDateStamp'] == 0:
              break
            # goto next descriptor
            bound_import_offset += self._h['BOUND_IMPORT_DESCRIPTOR']['len']
            # replace name field with actual string
            bound_import_desc['OffsetModuleName'] = self.rva2str(self._d['DATA_DIRECTORY']['BoundImport'] + bound_import_desc['OffsetModuleName'])
            # add to class dictionary
            self._d['BOUND_IMPORTS_DIRECTORY'].append(bound_import_desc)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # relocation directory (.reloc)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if self._d['DATA_DIRECTORY']['BaseRelocationTable_size'] > 0:
          self._d['RELOCATION_DIRECTORY'] = []
          base_offset = self.rva2offset(self._d['DATA_DIRECTORY']['BaseRelocationTable'])
          block_offset = base_offset
          # unpack array of BASE_RELOCATION
          while block_offset < (base_offset + self._d['DATA_DIRECTORY']['BaseRelocationTable_size']):
            reloc_entry = self._unpack(self._h['BASE_RELOCATION'], block_offset)
            # goto next descriptor
            block_offset += reloc_entry['SizeOfBlock']
            # add to class dictionary
            self._d['RELOCATION_DIRECTORY'].append(reloc_entry)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # exception directory (.pdata)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if self._d['DATA_DIRECTORY']['Exception_size'] > 0:
          # parse as many as the size dictates
          self._d['EXCEPTION_DIRECTORY'] = []
          entry_offset = self.rva2offset(self._d['DATA_DIRECTORY']['Exception'])
          # unpack array of EXCEPTION_FUNCTION_ENTRY
          base_offset = entry_offset
          while entry_offset < (base_offset + self._d['DATA_DIRECTORY']['Exception_size']):
            exception_entry = self._unpack(self._h['EXCEPTION_FUNCTION_ENTRY'], entry_offset)
            # goto next entry
            entry_offset += self._h['EXCEPTION_FUNCTION_ENTRY']['len']
            # add to class dictionary
            self._d['EXCEPTION_DIRECTORY'].append(exception_entry)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # TLS directory (.tls)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if self._d['DATA_DIRECTORY']['ThreadLocalStorage_size'] > 0:
          if self._b64:
            self._d['TLS_DIRECTORY'] = self._unpack(self._h['TLS_DIRECTORY_64'], self.rva2offset(self._d['DATA_DIRECTORY']['ThreadLocalStorage']))
          else:
            self._d['TLS_DIRECTORY'] = self._unpack(self._h['TLS_DIRECTORY_32'], self.rva2offset(self._d['DATA_DIRECTORY']['ThreadLocalStorage']))
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # delay imports directory (.idata)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if self._d['DATA_DIRECTORY']['DelayImportTable_size'] > 0:
          self._d['DELAY_IMPORT_DIRECTORY'] = []
          import_desc_offset = self.rva2offset(self._d['DATA_DIRECTORY']['DelayImportTable'])
          # unpack each delay import descriptor entry
          while True:
            import_desc = self._unpack(self._h['DELAY_IMPORT_DESCRIPTOR'], import_desc_offset)
            # check for empty entry
            if import_desc['Name'] == 0:
              break
            # resolve the name of the import descriptor
            import_desc['Name'] = self.rva2str(import_desc['Name'])
            self._d['DELAY_IMPORT_DIRECTORY'].append(import_desc)
            # go to the next descriptor
            import_desc_offset += self._h['DELAY_IMPORT_DESCRIPTOR']['len']
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # configuration directory (.rdata)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if self._d['DATA_DIRECTORY']['LoadConfiguration_size'] > 0:
          if self._b64:
            self._d['LOAD_CONFIG_DIRECTORY'] = self._unpack(self._h['LOAD_CONFIG_DIRECTORY_64'], self.rva2offset(self._d['DATA_DIRECTORY']['LoadConfiguration']))
          else:
            self._d['LOAD_CONFIG_DIRECTORY'] = self._unpack(self._h['LOAD_CONFIG_DIRECTORY_32'], self.rva2offset(self._d['DATA_DIRECTORY']['LoadConfiguration']))
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # configuration directory (.rsrc)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if self._d['DATA_DIRECTORY']['Resource_size'] > 0:
          self._d['RESOURCE_DIRECTORY'] =  self._unpack(self._h['RESOURCE_DIRECTORY'], self.rva2offset(self._d['DATA_DIRECTORY']['Resource']))
    except:
      print('[-] !!WARNING!! Failed to parse standard PE headers for file {0}. Possible malformed PE file or malicious tampering to prevent analysis.'.format(filename))
      # this requires a program exit...
      quit()

  def __str__(self):
    """ format internals as hex strings """
    output = copy.deepcopy(self._d)
    self._fmt2hex(output)
    return pprint.pformat(output)

  def _unpack(self, src, offset):
    """ internal function to unpack a given struct/header into an array of bytes """
    dst = {}
    self._file.seek(offset)
    try:
      raw = struct.unpack('<' + ''.join([f[1] for f in src['fmt']]), self.read(offset, src['len']))
      for i in range(len(raw)):
        dst[src['fmt'][i][0]] = raw[i]
    except:
      # set dst to null values
      raw = struct.unpack('<' + ''.join([f[1] for f in src['fmt']]), b'\x00' * src['len'])
      for i in range(len(raw)):
        dst[src['fmt'][i][0]] = raw[i]
      # get header name we were trying to unpack
      h = [x for x in self._h if self._h[x] is src][0]
      print('[-] !!WARNING!! Failed to unpack struct {0} at file offset {1}. Possible malformed PE file or malicious tampering to prevent analysis.'.format(h, hex(offset)))
    finally:
      return dst

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
      if self._b64:
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
      import_entry_ptr += 8 if (self._b64) else 4
      desc_imports.append(import_entry)
    return desc_imports

  def _parseResourceRecursive(self, dir_rva, nodes, path):
    """ take a base RVA to an _RESOURCE_DIRECTORY and extract
        all RESOURCE_ENTRYs inside recursively into nodes """
    # get info from RESOURCE_DIRECTORY
    base = self.rva2offset(dir_rva)
    num_names = struct.unpack('<H', self.read(base + 12, 2))[0]
    num_ids = struct.unpack('<H', self.read(base + 14, 2))[0]
    # parse each RESOURCE_DIRECTORY_ENTRY
    entry_offset = base + self._h['RESOURCE_DIRECTORY']['len']
    for i in range(num_names + num_ids):
      # extract Name and OffsetToData for this RESOURCE_DIRECTORY_ENTRY
      ename =  struct.unpack('<I', self.read(entry_offset, 4))[0]
      eoffset = struct.unpack('<I', self.read(entry_offset + 4, 4))[0]
      # parse name/id for entry
      next_path = path
      if ename & (0x1 << 31):
        # name is a string RVA
        ename_base = self.rva2offset(self._d['DATA_DIRECTORY']['Resource'] + (ename & ~(0x1 << 31)))
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
        self._parseResourceRecursive(self._d['DATA_DIRECTORY']['Resource'] + (eoffset & ~(0x1 << 31)), nodes, next_path + '/')
      else:
        node = {}
        # data offset. extract codepage, data, and language
        data_base = self.rva2offset(self._d['DATA_DIRECTORY']['Resource'] + (eoffset & ~(0x1 << 31)))
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
    self._file.seek(addr)
    d = self._file.read(num_bytes)
    return d

  def dict(self):
    """ returns a copy of internal PE headers for user modification as
        a python dictionary """
    return copy.deepcopy(self._d)

  def rva2str(self, rva):
    """ extract a null terminated string given an RVA """
    offset = self.rva2offset(rva)
    count = 0
    self._file.seek(offset)
    while ord(self._file.read(1)):
      count += 1
    return struct.unpack('{0}s'.format(count), self.read(offset, count))[0]

  def rva2offset(self, rva):
    """ get raw file offset from RVA """
    for section in self._d['SECTIONS']:
      if (section['VirtualAddress'] <= rva) and (rva < (section['VirtualAddress'] + section['VirtualSize'])):
        return section['PointerToRawData'] + (rva - section['VirtualAddress'])
    print('[-] !!WARNING!! Relative Virtual Address: ' + hex(rva) + ' does not fall inside specified sections. Possible malformed PE file or malicious tampering.')
    return 0

  def va2rva(self, va):
    """ take a virtual address and scale it back by the
        imagebase in the image optional header """
    return va - self._d['IMAGE_HEADER']['ImageBase']

  def parse_exports(self):
    """ try and follow the export directory and return PE exports """
    exports = []
    try:
      if self._d['DATA_DIRECTORY'] and (self._d['DATA_DIRECTORY']['Export_size'] > 0):
        # get offset to function array
        export_fun_offset = self.rva2offset(self._d['EXPORT_DIRECTORY']['AddressOfFunctions'])
        # unpack each 32 bit address
        for i in range(self._d['EXPORT_DIRECTORY']['NumberOfFunctions']):
          fun_rva = struct.unpack('<I', self.read(export_fun_offset + (i * 4), 4))[0]
          # check for forwarded export
          if fun_rva and ((self._d['DATA_DIRECTORY']['Export'] <= fun_rva) and
                          (fun_rva < (self._d['DATA_DIRECTORY']['Export'] +
                                      self._d['DATA_DIRECTORY']['Export_size']))):
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
              'ordinal': self._d['EXPORT_DIRECTORY']['Base'] + i,
            })
        # fill out names/ordinals for exports if specified
        name_array_offset = self.rva2offset(self._d['EXPORT_DIRECTORY']['AddressOfNames'])
        ordinal_array_offset = self.rva2offset(self._d['EXPORT_DIRECTORY']['AddressOfNameOrdinals'])
        for i in range(self._d['EXPORT_DIRECTORY']['NumberOfNames']):
          # get RVA from array and then convert to actual offsets to get data from
          ordinal = struct.unpack('<H', self.read(ordinal_array_offset + (i * 2), 2))[0]
          name = self.rva2str(struct.unpack('<I', self.read(name_array_offset + (i * 4), 4))[0])
          # find the ordinal to place this name into
          for e in exports:
            if e['ordinal'] == (ordinal + self._d['EXPORT_DIRECTORY']['Base']):
              e['name'] = name
              break
    except:
      print('[-] !!WARNING!! Failed to parse exports. Possible malformed PE file or malicious tampering to prevent analysis.')
    finally:
      return exports

  def parse_imports(self):
    """ try and follow the delay-load and static import directories
        and return PE imports """
    imports = []
    try:
      if self._d['DATA_DIRECTORY'] and (self._d['DATA_DIRECTORY']['Import_size'] > 0):
        # go through each import descriptor and get list of imports
        for import_desc in self._d['IMPORT_DIRECTORY']:
          desc_imports = self._parseINT(import_desc['OriginalFirstThunk'])
          imports.append({
            'dll': import_desc['Name'],
            'functions': desc_imports,
          })
      if self._d['DATA_DIRECTORY'] and (self._d['DATA_DIRECTORY']['DelayImportTable_size'] > 0):
        # go through each import descriptor and get list of imports
        for import_desc in self._d['DELAY_IMPORT_DIRECTORY']:
          desc_imports = self._parseINT(import_desc['ImportNameTable'])
          imports.append({
            'dll': import_desc['Name'],
            'functions': desc_imports,
          })
    except:
      print('[-] !!WARNING!! Failed to parse imports. Possible malformed PE file or malicious tampering to prevent analysis.')
    finally:
      return imports

  def parse_relocations(self):
    """ try and follow the relocations directory and return PE relocations """
    relocs = []
    try:
      if self._d['DATA_DIRECTORY'] and (self._d['DATA_DIRECTORY']['BaseRelocationTable_size'] > 0):
        # go through each relocation block
        block_offset = self.rva2offset(self._d['DATA_DIRECTORY']['BaseRelocationTable'])
        for reloc_block in self._d['RELOCATION_DIRECTORY']:
          reloc_entries = []
          # parse all relocations within the current block
          block_base = block_offset
          block_offset += self._h['BASE_RELOCATION']['len']
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
          for section in self._d['SECTIONS']:
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
    except:
      print('[-] !!WARNING!! Failed to parse relocations. Possible malformed PE file or malicious tampering to prevent analysis.')
    finally:
      return relocs

  def parse_tls(self):
    """ simply return any TLS RVA function pointers in the array
        'AddressOfCallBacks' and any TLS data """
    data = ''
    callbacks = []
    try:
      if self._d['DATA_DIRECTORY'] and (self._d['DATA_DIRECTORY']['ThreadLocalStorage_size'] > 0):
        # extract binary data for TLS storage
        data_len = abs(self._d['TLS_DIRECTORY']['EndAddressOfRawData'] - self._d['TLS_DIRECTORY']['StartAddressOfRawData'])
        if data_len:
          data_start_offset = self.rva2offset(self.va2rva(self._d['TLS_DIRECTORY']['StartAddressOfRawData']))
          data = struct.unpack('{0}s'.format(data_len), self.read(data_start_offset, data_len))[0]
        # follow array and get each function pointer
        array_offset = self.rva2offset(self.va2rva(self._d['TLS_DIRECTORY']['AddressOfCallBacks']))
        while True:
          if self._b64:
            callback = struct.unpack('<Q', self.read(array_offset, 8))[0]
            array_offset += 8
          else:
            callback = struct.unpack('<I', self.read(array_offset, 4))[0]
            array_offset += 4
          # check for null
          if callback == 0:
            break
          callbacks.append(self.rva2offset(self.va2rva((callback))))
    except:
      print('[-] !!WARNING!! Failed to parse thread local storage. Possible malformed PE file or malicious tampering to prevent analysis.')
    finally:
      return {'data': data, 'callback_offsets': callbacks}

  def parse_resources(self):
    """ parse resources filesystem and return all information serialized """
    rdir = []
    try:
      if self._d['DATA_DIRECTORY'] and (self._d['DATA_DIRECTORY']['Resource_size'] > 0):
        # recurse down the resource directory
        self._parseResourceRecursive(self._d['DATA_DIRECTORY']['Resource'], rdir, '/')
    except:
      print('[-] !!WARNING!! Failed to parse resources. Possible malformed PE file or malicious tampering to prevent analysis.')
    finally:
      return rdir

  def parse_strings(self, start=0, size=0, min_length=4):
    """ extract strings from file starting at offset 'start'.
        if size is -1, then the whole file is searched. """
    result = {}
    _lang = {
      'ascii':    r'[0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~ ]',
      # languages are encoded in little endian for windows
      'latin':    r'(?:[\x20-\x7E][\x00])',               # 0020-007F (includes space)
      'cyrillic': r'(?:[\x00-\xFF][\x04]|\x20\x00)',      # 0400-04FF with space
      'arabic':   r'(?:[\x00-\xFF][\x06]|\x20\x00)',      # 0600-06FF with space
      'hebrew':   r'(?:[\x90-\xFF][\x05]|\x20\x00)',      # 0590-05FF with space
      'cjk':      r'(?:[\x00-\xFF][\x4E-\x9F]|\x20\x00)', # 4E00-9FFF with space
    }
    # figure out target size
    if size < 0:
      size = os.stat(self._file.name).st_size - start
    # extract data
    data = self.read(start, size)
    # extract ASCII/UTF strings accross each language set
    for l in _lang.keys():
      regex = re.compile('{0}{{{1},}}'.format(_lang[l], min_length).encode('ascii'))
      result[l] = [b.decode('UTF-16LE') if (l != 'ascii') else b for b in regex.findall(data)]
    return result
