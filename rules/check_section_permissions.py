"""
Check for sections with write & execute permissions
"""

# constants from WINNT.H
IMAGE_SCN_CNT_CODE               = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_SHARED             = 0x10000000
IMAGE_SCN_MEM_EXECUTE            = 0x20000000
IMAGE_SCN_MEM_WRITE              = 0x80000000


def run(peobject):
  # array to hold list of final alerts
  alerts = []
  # loop through each section
  d = peobject.dict()
  if 'SECTIONS' in d:
    for s in d['SECTIONS']:
      # check for writeable code sections
      if ((s['Characteristics'] & IMAGE_SCN_MEM_WRITE) and
          (s['Characteristics'] & IMAGE_SCN_MEM_EXECUTE)):
        # check for section type
        types = []
        if (s['Characteristics'] & IMAGE_SCN_CNT_CODE):
          types.append('Section {0} marked as containing code at file offset {1} ({2} bytes long). Executable may be changing functionality at runtime.'.format(s['Name'], hex(s['PointerToRawData']), s['SizeOfRawData']))
        if (s['Characteristics'] & IMAGE_SCN_CNT_INITIALIZED_DATA):
          types.append('Section {0} marked as containing initialized data at file offset {1} ({2} bytes long). Executable may be modifying important configuration data at runtime.'.format(s['Name'], hex(s['PointerToRawData']), s['SizeOfRawData']))
        if (s['Characteristics'] & IMAGE_SCN_CNT_UNINITIALIZED_DATA):
          types.append('Section {0} marked as containing uninitialized data at file offset {1} ({2} bytes long). Executable may be setting important configuration data at runtime.'.format(s['Name'], hex(s['PointerToRawData']), s['SizeOfRawData']))
        if (s['Characteristics'] & IMAGE_SCN_MEM_SHARED):
          types.append('Section {0} marked as sharable between processes at file offset {1} ({2} bytes long). This is bad for DLLs because it allows for code injection into processes who share a DLL.'.format(s['Name'],hex(s['PointerToRawData']), s['SizeOfRawData']))
        if types:
          alerts.append({
            'title': 'Self-Modifying Code',
            'description': 'Sections in the executable have indicators for self-modifying code based on the permissions for each section.',
            'data': types,
            'code': '',
          })
  return alerts
