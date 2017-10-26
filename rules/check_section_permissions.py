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

# alert for self-modifying code
WRITABLE_CODE_ALERT = """
Self-Modifying Code:

  The following sections are marked as executable and writeable.
  Malware can use this to change functionality or self-inject code at
  runtime:

{0}
"""
ALERT_FMT = """  \t- Section {0} at file offset {1} ({2} bytes long):
{3}"""

# alert breakdowns for different section types
SECTION_SHARED = """  \t\t- Section marked as sharable between processes. This is bad
  \t\t  for DLLs because it allows for code injection into processes
  \t\t  who use the DLL."""
SECTION_INITALIZED = """  \t\t- Marked as containing initialized data. Executable may be
  \t\t  modifying important configuration data at runtime."""
SECTION_UNINITALIZED = """  \t\t- Marked as containing uninitalized data. Executable may be
  \t\t  setting important configuration data at runtime."""
SECTION_CODE = """  \t\t- Marked as containing code. Executable may be changing
  \t\t  functionality at runtime."""

def run(peobject):
  # array to hold list of final alerts
  alerts = []
  # loop through each section
  alerts_fmt = []
  for s in peobject.dict()['SECTIONS']:
    # check for writeable code sections
    if ((s['Characteristics'] & IMAGE_SCN_MEM_WRITE) and
        (s['Characteristics'] & IMAGE_SCN_MEM_EXECUTE)):
      # check for section type
      types = []
      if (s['Characteristics'] & IMAGE_SCN_CNT_CODE):
        types.append(SECTION_CODE)
      if (s['Characteristics'] & IMAGE_SCN_CNT_INITIALIZED_DATA):
        types.append(SECTION_INITALIZED)
      if (s['Characteristics'] & IMAGE_SCN_CNT_UNINITIALIZED_DATA):
        types.append(SECTION_UNINITALIZED)
      if (s['Characteristics'] & IMAGE_SCN_MEM_SHARED):
        types.append(SECTION_SHARED)
      # generate alert
      alerts_fmt.append(ALERT_FMT.format(s['Name'], hex(s['PointerToRawData']), s['SizeOfRawData'], '\n'.join(types)))
  if alerts_fmt:
    alerts.append(WRITABLE_CODE_ALERT.format('\n\n'.join(alerts_fmt)))
  return alerts
