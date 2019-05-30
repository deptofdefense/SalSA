"""
checks section sizes on disk and in virtual meory to indicate a packer
"""

def run(peobject):
  alerts = []
  found = []
  # loop through each section
  d = peobject.dict()
  if 'SECTIONS' in d:
    for s in d['SECTIONS']:
      # check for a raw size of 0 on disk but a non-zero size in virtual memory
      if (s['SizeOfRawData'] == 0) and (s['VirtualSize'] > 0):
        found.append('Section {0} has a disk size of {1} bytes but a virtual size of {2} bytes'.format(s['Name'], s['SizeOfRawData'], s['VirtualSize']))
  # this rule generates only one alert
  if found:
    alerts.append({
      'title': 'Possible Malware Packer Used',
      'description': 'This indicates a packer may be using the following sections to hold unpacked code at runtime.',
      'data': found,
      'code': '',
    })
  return alerts
