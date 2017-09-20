"""
Check for sections with write & execute permissions

Self-Modifying Mode Explanation:
https://malwaremusings.com/2012/10/15/self-modifying-code-changing-exe-file-section-characteristics/

Shared DLLs:
https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/dll-shared-sections/DLL%20shared%20sections%20(update%201).pdf
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

PE file section {0} has been marked as executable and writable.
Malware can use this to change functionality or self-inject code at
runtime. Section begins at file offset {1} and is {2} bytes long.

  Section Type:
{3}
"""

# alert breakdowns for different section types
SECTION_SHARED = """\t- Section marked as sharable between processes. This
\t  is bad for DLLs because it allows for code injection into processes
\t  who use the DLL."""
SECTION_INITALIZED = """\t- Section marked as containing initalized data.
\t  Executable may be modifying important configuration data at runtime."""
SECTION_UNINITALIZED = """\t- Section marked as containing uninitalized data.
\t  Executable may be setting important configuration data at runtime."""
SECTION_CODE = """\t- Section marked as containing code. Executable may
\t  be changing functionality at runtime."""

def run(peobject):
  # array to hold list of final alerts
  alerts = []
  # loop through each section
  for s in peobject.dict()['SECTIONS']:
    # check for writable code sections
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
      alerts.append(WRITABLE_CODE_ALERT.format(s['Name'], s['PointerToRawData'], s['VirtualSize'], '\n'.join(types)))
  return alerts
