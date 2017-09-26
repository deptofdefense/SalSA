"""
checks section sizes on disk and in virtual meory to indicate a packer
"""

ALERT_FMT = """
Possible Malware Obfuscation:

Section {0} has a disk size of {1} bytes but a virtual size of {2} bytes.
This indicates a packer using this section to hold unpacked code at runtime.
"""


def run(peobject):
  alerts = []
  # loop through each section
  for s in peobject.dict()['SECTIONS']:
    # check for a raw size of 0 on disk but a non-zero size in virtual memory
    if (s['SizeOfRawData'] == 0) and (s['VirtualSize'] > 0):
      alerts.append(ALERT_FMT.format(s['Name'], s['SizeOfRawData'], s['VirtualSize']))
  return alerts
