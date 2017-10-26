"""
checks section sizes on disk and in virtual meory to indicate a packer
"""

ALERT_TITLE = """
Possible Malware Packer Used:

  This indicates a packer may be using the following sections to hold
  unpacked code at runtime:

{0}
"""

ALERT_FMT = '\t- Section {0} has a disk size of {1} bytes but a virtual size of {2} bytes'

def run(peobject):
  alerts = []
  # loop through each section
  alert_fmts = []
  for s in peobject.dict()['SECTIONS']:
    # check for a raw size of 0 on disk but a non-zero size in virtual memory
    if (s['SizeOfRawData'] == 0) and (s['VirtualSize'] > 0):
      alert_fmts.append(ALERT_FMT.format(s['Name'], s['SizeOfRawData'], s['VirtualSize']))
  if alert_fmts:
    alerts.append(ALERT_TITLE.format('\n'.join(alert_fmts)))
  return alerts
