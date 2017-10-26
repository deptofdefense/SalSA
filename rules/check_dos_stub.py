"""
Check DOS stub and make sure it complies with the standard microsoft linker
"""
import re
import string

# the standard stub included by the microsoft linker
STANDARD_STUB = b'\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00'

STUB_ALERT = """
Uncommon DOS Program:

Executable does not contain the standard DOS stub program included by the
microsoft linker. This is uncommon and may indicate malware obfuscation
or attempts to store data in the DOS stub by the malware since it is
overlooked by the Windows loader at runtime.

DOS Stub (displayed as hex bytes and ASCII):
{0}
"""

RICH_ALERT = """
Uncommon DOS Program Rich Header:

Executable does not contain a standard 'Rich' header for the DOS stub
program. This is uncommon and may indicate malware obfuscation or
attempts to store data in the DOS stub by the malware since it is
overlooked by the Windows loader at runtime.

DOS Stub (displayed as hex bytes and ASCII):
{0}
"""

PRINTABLE = string.digits + string.letters

def run(peobject):
  # array to hold list of final alerts
  alerts = []
  # get the DOS stub from the exectuable and check if it isn't what we expect
  stub = peobject.dict()['DOS_STUB']
  stub_fmt = '\n'.join(re.findall(r'.{1,80}', ':'.join('{:02x}'.format(ord(c)) if c not in PRINTABLE else c for c in stub)))
  if (STANDARD_STUB not in stub):
    alerts.append(STUB_ALERT.format(stub_fmt))
  if ('Rich' not in stub):
    alerts.append(RICH_ALERT.format(stub_fmt))
  return alerts
