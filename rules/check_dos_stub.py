"""
Check DOS stub and make sure it complies with the standard microsoft linker

Rich Header Whitepaper:
https://www.sec.in.tum.de/assets/Uploads/RichHeader.pdf

DOS stub explained:
http://www.reverse-engineering.info/PE_Information/dosstub.htm
"""

# the standard stub included by the microsoft linker
STANDARD_STUB = b'\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00'

STUB_ALERT = """
Malware Obfuscation:

Executable does not contain the standard DOS stub program included by the
microsoft linker. This is uncommon and may indicate malware obfuscation
or attempts to store data in the DOS stub by the malware since it is
overlooked by the Windows loader at runtime.
"""

RICH_ALERT = """
Malware Obfuscation:

Executable does not contain a standard 'Rich' header for the DOS stub
program. This is uncommon and may indicate malware obfuscation or
attempts to store data in the DOS stub byt he malware since it is
overlooked by the Windows loader at runtime.
"""

def run(peobject):
  # array to hold list of final alerts
  alerts = []
  # get the DOS stub from the exectuable and check if it isn't what we expect
  stub = peobject.dict()['DOS_STUB']
  if (STANDARD_STUB in stub):
    alerts.append(STUB_ALERT)
  if ('Rich' not in stub):
    alerts.append(STUB_ALERT)
  return alerts
