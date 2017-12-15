
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

  def __init__(self, filename, verbose):
    """ extract PE file piece by piece """
    offset = 0
    self._d = {}
    self._err = False
    self._v = verbose
    self._b64 = False
    self._file = open(filename, 'rb')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse DOS header
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    try:
      self._d['DOS_HEADER'] = self._unpack(self._h['DOS_HEADER'], offset)
    except:
      self._error('Failed to parse DOS header.')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # extract DOS stub
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    try:
      stub_len = self._d['DOS_HEADER']['e_lfanew'] - self._h['DOS_HEADER']['len']
      stub_program = self.read(self._h['DOS_HEADER']['len'], stub_len)
      self._d['DOS_STUB'] = struct.unpack('{0}s'.format(stub_len), stub_program)[0]
      offset += self._d['DOS_HEADER']['e_lfanew']
    except:
      self._error('Failed to extract DOS program.')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse PE header
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    try:
      self._d['PE_HEADER'] = self._unpack(self._h['PE_HEADER'], offset)
      offset += self._h['PE_HEADER']['len']
    except:
      self._error('Failed to parse PE header.')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse optional image header
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    try:
      if self._d['PE_HEADER']['SizeOfOptionalHeader'] > 0:
        optional_header_base = offset
        if struct.unpack('<H', self.read(offset, 2))[0] == 0x20b:
          # parse 64 bit binary
          self._b64 = True
          self._d['IMAGE_HEADER'] = self._unpack(self._h['IMAGE_HEADER_64'], offset)
          offset += self._h['IMAGE_HEADER_64']['len']
        else:
          # parse 32 bit binary (0x10b)
          self._d['IMAGE_HEADER'] = self._unpack(self._h['IMAGE_HEADER_32'], offset)
          offset += self._h['IMAGE_HEADER_32']['len']
    except:
      self._error('Failed to parse optional image header.')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse data directory (number of directories varies by compiler)
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    try:
      num_dirs = self._d['IMAGE_HEADER']['NumberOfRvaAndSizes']
      dirs_fmt = {
         # only parse data directories we have specified/understand
        'len': min(num_dirs * 8, self._h['DATA_DIRECTORY']['len']),
        'fmt': self._h['DATA_DIRECTORY']['fmt'][:min((num_dirs * 2), len(self._h['DATA_DIRECTORY']['fmt']))]
      }
      self._d['DATA_DIRECTORY'] = self._unpack(dirs_fmt, offset)
      offset = optional_header_base + self._d['PE_HEADER']['SizeOfOptionalHeader']
    except:
      self._error('Failed to parse data directories.')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # parse section headers
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    try:
      self._d['SECTIONS'] = []
      for i in range(self._d['PE_HEADER']['NumberOfSections']):
        section = self._unpack(self._h['SECTION_HEADER'], offset)
        offset += self._h['SECTION_HEADER']['len']
        # fix section name to remove null byte padding
        section['Name'] = section['Name'].replace('\x00', '')
        self._d['SECTIONS'].append(section)
    except:
      self._error('Failed to parse section headers.')
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # extract data directory entries (some not publicly documented...)
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if 'DATA_DIRECTORY' in self._d:
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # debug directory (.debug)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      try:
        if self._d['DATA_DIRECTORY']['Debug']:
          self._d['DEBUG_DIRECTORY'] = self._unpack(self._h['DEBUG_DIRECTORY'], self.rva2offset(self._d['DATA_DIRECTORY']['Debug']))
      except:
        self._error('Failed to parse debug data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['Debug'])))
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # export directory (.edata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      try:
        if self._d['DATA_DIRECTORY']['Export']:
          self._d['EXPORT_DIRECTORY'] = self._unpack(self._h['EXPORT_DIRECTORY'], self.rva2offset(self._d['DATA_DIRECTORY']['Export']))
          self._d['EXPORT_DIRECTORY']['Name'] = self.offset2str(self.rva2offset(self._d['EXPORT_DIRECTORY']['Name']))
      except:
        self._error('Failed to parse export data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['Export'])))
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # import directory (.idata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      try:
        if self._d['DATA_DIRECTORY']['Import']:
          self._d['IMPORT_DIRECTORY'] = []
          import_desc_offset = self.rva2offset(self._d['DATA_DIRECTORY']['Import'])
          # unpack each import descriptor entry
          while True:
            import_desc = self._unpack(self._h['IMPORT_DESCRIPTOR'], import_desc_offset)
            # check for empty entry
            if self._isZero(import_desc):
              break
            # resolve the name of the import descriptor
            import_desc['Name'] = self.offset2str(self.rva2offset(import_desc['Name']))
            self._d['IMPORT_DIRECTORY'].append(import_desc)
            # go to the next descriptor
            import_desc_offset += self._h['IMPORT_DESCRIPTOR']['len']
      except:
        self._error('Failed to parse import data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['Import'])))
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # bound import directory (.idata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      try:
        if self._d['DATA_DIRECTORY']['BoundImport']:
          self._d['BOUND_IMPORTS_DIRECTORY'] = []
          bound_import_offset = self._d['DATA_DIRECTORY']['BoundImport']
          # unpack array of BOUND_IMPORT_DESCRIPTORs
          while True:
            bound_import_desc = self._unpack(self._h['BOUND_IMPORT_DESCRIPTOR'], bound_import_offset)
            # check for null terminator
            if self._isZero(bound_import_desc):
              break
            # goto next descriptor
            bound_import_offset += self._h['BOUND_IMPORT_DESCRIPTOR']['len']
            # replace name field with actual string
            bound_import_desc['OffsetModuleName'] =  self.offset2str(self._d['DATA_DIRECTORY']['BoundImport'] + bound_import_desc['OffsetModuleName'])
            # add to class dictionary
            self._d['BOUND_IMPORTS_DIRECTORY'].append(bound_import_desc)
      except:
        self._error('Failed to parse bound import data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['BoundImport'])))
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # relocation directory (.reloc)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      try:
        if self._d['DATA_DIRECTORY']['BaseRelocationTable']:
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
      except:
        self._error('Failed to parse relocation data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['BaseRelocationTable'])))
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # exception directory (.pdata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      try:
        if self._d['DATA_DIRECTORY']['Exception']:
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
      except:
        self._error('Failed to parse exception data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['Exception'])))
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # TLS directory (.tls)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      try:
        if self._d['DATA_DIRECTORY']['ThreadLocalStorage']:
          if self._b64:
            self._d['TLS_DIRECTORY'] = self._unpack(self._h['TLS_DIRECTORY_64'], self.rva2offset(self._d['DATA_DIRECTORY']['ThreadLocalStorage']))
          else:
            self._d['TLS_DIRECTORY'] = self._unpack(self._h['TLS_DIRECTORY_32'], self.rva2offset(self._d['DATA_DIRECTORY']['ThreadLocalStorage']))
      except:
        self._error('Failed to parse thread local storage data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['ThreadLocalStorage'])))
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # delay imports directory (.idata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      try:
        if self._d['DATA_DIRECTORY']['DelayImportTable']:
          self._d['DELAY_IMPORT_DIRECTORY'] = []
          import_desc_offset = self.rva2offset(self._d['DATA_DIRECTORY']['DelayImportTable'])
          # unpack each delay import descriptor entry
          while True:
            import_desc = self._unpack(self._h['DELAY_IMPORT_DESCRIPTOR'], import_desc_offset)
            # check for empty entry
            if self._isZero(import_desc):
              break
            # resolve the name of the import descriptor and check for RVA bug:
            # https://reverseengineering.stackexchange.com/questions/16261/should-the-delay-import-directory-contain-virtual-addresses
            if not (import_desc['Attributes'] & 0x1):
              import_desc['Name'] = self.va2rva(import_desc['Name'])
            import_desc['Name'] = self.offset2str(self.rva2offset(import_desc['Name']))
            self._d['DELAY_IMPORT_DIRECTORY'].append(import_desc)
            # go to the next descriptor
            import_desc_offset += self._h['DELAY_IMPORT_DESCRIPTOR']['len']
      except:
        self._error('Failed to parse delay imports data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['DelayImportTable'])))
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # configuration directory (.rdata)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      try:
        if self._d['DATA_DIRECTORY']['LoadConfiguration']:
          if self._b64:
            self._d['LOAD_CONFIG_DIRECTORY'] = self._unpack(self._h['LOAD_CONFIG_DIRECTORY_64'], self.rva2offset(self._d['DATA_DIRECTORY']['LoadConfiguration']))
          else:
            self._d['LOAD_CONFIG_DIRECTORY'] = self._unpack(self._h['LOAD_CONFIG_DIRECTORY_32'], self.rva2offset(self._d['DATA_DIRECTORY']['LoadConfiguration']))
      except:
        self._error('Failed to parse load configuration data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['LoadConfiguration'])))
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      # resource directory (.rsrc)
      # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      try:
        if self._d['DATA_DIRECTORY']['Resource']:
          self._d['RESOURCE_DIRECTORY'] =  self._unpack(self._h['RESOURCE_DIRECTORY'], self.rva2offset(self._d['DATA_DIRECTORY']['Resource']))
      except:
        self._error('Failed to parse resource data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['Resource'])))

  def __str__(self):
    """ format internals as hex strings """
    output = copy.deepcopy(self._d)
    self._fmt2hex(output)
    return pprint.pformat(output)

  def _error(self, desc, prefix='-'):
    """ display the error and verbose description formatted """
    if not self._err:
      self._err = True
      # only print this once
      print('[-] WARNING: Possible malformed PE file or malicious tampering to prevent analysis.')
    if self._v:
      print('[-]  ' + prefix + ' ' + desc)

  def _unpack(self, src, offset):
    """ internal function to unpack a given struct/header into an array of bytes """
    dst = {}
    self._file.seek(offset)
    raw = struct.unpack('<' + ''.join([f[1] for f in src['fmt']]), self.read(offset, src['len']))
    for i in range(len(raw)):
      dst[src['fmt'][i][0]] = raw[i]
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

  def _isZero(self, d):
    """ checks a dictionary to see if it is all zeros """
    for k in d:
      if isinstance(d[k], int) and (d[k] != 0):
        return False
      if isinstance(d[k], str) and ('\x00' not in d[k]):
        return False
    return True

  def read(self, addr, num_bytes):
    """ read bytes from file at a certain offset """
    self._file.seek(addr)
    d = self._file.read(num_bytes)
    return d

  def dict(self):
    """ returns a copy of internal PE headers for user modification as
        a python dictionary """
    return copy.deepcopy(self._d)

  def rva2offset(self, rva):
    """ get raw file offset from RVA """
    for section in self._d['SECTIONS']:
      if (section['VirtualAddress'] <= rva) and (rva < (section['VirtualAddress'] + section['VirtualSize'])):
        return section['PointerToRawData'] + (rva - section['VirtualAddress'])
    # this means the RVA is invalid
    raise Exception

  def va2rva(self, va):
    """ take a virtual address and scale it back by the
        imagebase in the image optional header """
    return va - self._d['IMAGE_HEADER']['ImageBase']

  def offset2str(self, offset):
    """ take a raw file offset and extract the string there """
    count = 0
    self._file.seek(offset)
    while ord(self._file.read(1)):
      count += 1
    return struct.unpack('{0}s'.format(count), self.read(offset, count))[0]

  def parse_exports(self):
    """ try and follow the export directory and return PE exports """
    exports = []
    try:
      if 'EXPORT_DIRECTORY' in self._d:
        # get offset to function array
        export_fun_offset = self.rva2offset(self._d['EXPORT_DIRECTORY']['AddressOfFunctions'])
        # unpack each 32 bit address
        for i in range(self._d['EXPORT_DIRECTORY']['NumberOfFunctions']):
          fun_rva = struct.unpack('<I', self.read(export_fun_offset + (i * 4), 4))[0]
          # check for forwarded export
          if fun_rva and (self._d['DATA_DIRECTORY']['Export'] <= fun_rva) and (fun_rva < (self._d['DATA_DIRECTORY']['Export'] + self._d['DATA_DIRECTORY']['Export_size'])):
            exports.append({
              'offset': 0,
              'name': self.offset2str(self.rva2offset(fun_rva)),
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
          name = self.offset2str(self.rva2offset(struct.unpack('<I', self.read(name_array_offset + (i * 4), 4))[0]))
          # find the ordinal to place this name into
          for e in exports:
            if e['ordinal'] == (ordinal + self._d['EXPORT_DIRECTORY']['Base']):
              e['name'] = name
              break
    except:
      self._error('Failed to extract export data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['Export'])))
      for l in pprint.pformat(self._fmt2hex(self._d['EXPORT_DIRECTORY']), indent=2).split('\n'):
        self._error(l, prefix='')
    finally:
      return exports

  def parse_imports(self):
    """ try and follow the delay-load and static import directories
        and return PE imports """
    imports = []
    def _parseIAT(rva, attr=0x1):
      """ internal helper to parse the Import Address Table (IAT) for
          delay import tables and normal (static) import tables. The attr
          argument only applies to bound import tables (see bug below) """
      # parse all imports within the current descriptor and check for
      # Microsoft C++ 6.0 bug to convert virtual address to RVA:
      # https://reverseengineering.stackexchange.com/questions/16261/should-the-delay-import-directory-contain-virtual-addresses
      desc_imports = []
      import_entry_ptr = self.rva2offset(rva) if (attr & 0x1) else self.rva2offset(self.va2rva(rva))
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
          # if not (attr & 0x1):
          #   print 'b delay: ', hex(entry_rva)
          # name pointer after hint which is 2 bytes
          entry_rva = entry_rva if (attr & 0x1) else self.va2rva(entry_rva)
          import_entry['hint'] = struct.unpack('<H', self.read(self.rva2offset(entry_rva), 2))[0]
          # if not (attr & 0x1):
          #   print 'a delay: ', hex(entry_rva), '\n'
          import_entry['name'] = self.offset2str(self.rva2offset(entry_rva + 2))
        # go to next pointer (8 for x86-64 and 4 for x86)
        import_entry_ptr += 8 if (self._b64) else 4
        desc_imports.append(import_entry)
      return desc_imports
    if 'IMPORT_DIRECTORY' in self._d:
      # go through each import descriptor and get list of imports
      for import_desc in self._d['IMPORT_DIRECTORY']:
        # try FT array first because malware will put bogus data in OFT
        functions = []
        try:
          functions = _parseIAT(import_desc['FirstThunk'])
        except:
          functions = _parseIAT(import_desc['OriginalFirstThunk'])
        finally:
          if functions:
            imports.append({
              'dll': import_desc['Name'],
              'functions': functions,
            })
          else:
            elf._error('Failed to extract import data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['Import'])))
            for d in self._d['IMPORT_DIRECTORY']:
              for l in pprint.pformat(self._fmt2hex(d), indent=2).split('\n'):
                self._error(l, prefix='')
    if 'DELAY_IMPORT_DIRECTORY' in self._d:
      # go through each delay import descriptor and get list of imports
      for import_desc in self._d['DELAY_IMPORT_DIRECTORY']:
        # this isn't documented anywhere but it looks like the INT is more reliable than IAT here
        functions = []
        try:
          functions = _parseIAT(import_desc['ImportNameTable'], attr=import_desc['Attributes'])
        except:
          functions = _parseIAT(import_desc['ImportAddressTable'], attr=import_desc['Attributes'])
        finally:
          if functions:
            imports.append({
              'dll': import_desc['Name'],
              'functions': functions,
            })
          else:
            self._error('Failed to extract delay import data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['DelayImportTable'])))
            for d in self._d['DELAY_IMPORT_DIRECTORY']:
              for l in pprint.pformat(self._fmt2hex(d), indent=2).split('\n'):
                self._error(l, prefix='')
    return imports

  def parse_relocations(self):
    """ try and follow the relocations directory and return PE relocations """
    relocs = []
    try:
      if 'RELOCATION_DIRECTORY' in self._d:
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
            if (section['VirtualAddress'] <= reloc_block['VirtualAddress']) and (reloc_block['VirtualAddress'] < (section['VirtualAddress'] + section['VirtualSize'])):
              section_name = section['Name']
              break
          if not section_name:
            print('[-] WARNING! Relocation Relative Virtual Address: {0} does not fall inside any specified section'.format(hex(reloc_block['VirtualAddress'])))
            section_name = ''
          relocs.append({
            'relocations': reloc_entries,
            'section': section_name,
          })
    except:
      self._error('Failed to extract relocation data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['BaseRelocationTable'])))
      for d in self._d['RELOCATION_DIRECTORY']:
        for l in pprint.pformat(self._fmt2hex(d), indent=2).split('\n'):
          self._error(l, prefix='')
    finally:
      return relocs

  def parse_tls(self):
    """ simply return any TLS RVA function pointers in the array
        'AddressOfCallBacks' and any TLS data """
    data = ''
    callbacks = []
    try:
      if 'TLS_DIRECTORY' in self._d:
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
      self._error('Failed to extract thread local storage data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['ThreadLocalStorage'])))
      for l in pprint.pformat(self._fmt2hex(self._d['TLS_DIRECTORY']), indent=2).split('\n'):
        self._error(l, prefix='')
    finally:
      return {'data': data, 'callback_offsets': callbacks}

  def parse_resources(self):
    """ parse resources file system and return all information serialized """
    rdir = []
    def _recurseOnDirectoryEntry(resource_data_entry_rva, nodes, path):
      """ take a base RVA to an RESOURCE_DIRECTORY and extract
          all RESOURCE_ENTRYs inside recursively into nodes """
      # get info from RESOURCE_DIRECTORY
      base = self.rva2offset(resource_data_entry_rva)
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
          _recurseOnDirectoryEntry(self._d['DATA_DIRECTORY']['Resource'] + (eoffset & ~(0x1 << 31)), nodes, next_path + '/')
        else:
          node = {}
          # data offset. extract codepage, data, and language
          data_base = self.rva2offset(self._d['DATA_DIRECTORY']['Resource'] + (eoffset & ~(0x1 << 31)))
          data_rva = struct.unpack('<I', self.read(data_base, 4))[0]
          data_len = struct.unpack('<I', self.read(data_base + 4, 4))[0]
          node['codepage'] = struct.unpack('<I', self.read(data_base + 8, 4))[0]
          # try to extract the data
          try:
            node['data'] = struct.unpack('{0}s'.format(data_len), self.read(self.rva2offset(data_rva), data_len))[0]
          except:
            node['data'] = ''
          node['lang'] = ename & 0xFFFF
          node['path'] = path
          # append data to the current level in recursion
          nodes.append(node)
        # goto the next directory entry
        entry_offset += 8
    try:
      if 'RESOURCE_DIRECTORY' in self._d:
        # recurse down the resource directory
        _recurseOnDirectoryEntry(self._d['DATA_DIRECTORY']['Resource'], rdir, '/')
    except:
      self._error('Failed to extract resource data directory at RVA {0}'.format(hex(self._d['DATA_DIRECTORY']['Resource'])))
      for l in pprint.pformat(self._fmt2hex(self._d['RESOURCE_DIRECTORY']), indent=2).split('\n'):
        self._error(l, prefix='')
    finally:
      return rdir

  def parse_strings(self, start=0, size=0, min_length=4):
    """ extract strings from file starting at offset 'start'.
        if size is -1, then the whole file is searched. """
    result = {}
    _lang = {
      'ascii':    r'[0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"\\#$%&\'()*+,\-./:;<=>?@[\]^_`{|}~ ]',
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
