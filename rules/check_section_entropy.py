"""
calculate the entropy of the file sections for randomness
"""
import math

# threshold for entropy before alerting. This value
# was taken by reading a few whitepapers on entropy analysis
# and noticing that malware that does attempt to evade
# entropy analysis
THRESHOLD = 6.5

ALERT_TITLE = """
Possible Malware Obfuscation:

  The following sections may contain encrypted/packed data that will be
  decrypted or unpacked at runtime since they have entropy over {0:.2f}%:

{1}
"""

ALERT_FMT = '\t- Entropy for section {0} is {1:.2f}%'


# performs shannon analysis:
# https://en.wikipedia.org/wiki/Entropy_(information_theory)
def byte_entropy(data):
  # array of zeroes
  c = [0 for x in range(256)]
  # sum up occurances of each byte from 0 to 255
  for b in data:
    c[ord(b)] = c[ord(b)] + 1
  # calculate entropy of occurances
  e = abs(sum([(float(x) / len(data)) * math.log(float(x) / len(data), 2) for x in c if (x != 0)]))
  return e


def run(peobject):
  # array to hold list of final alerts
  alerts = []
  # loop through all sections and calculate entropy
  alert_fmts = []
  d = peobject.dict()
  for s in d['SECTIONS']:
    # get bytes from section
    data = peobject.read(s['PointerToRawData'], s['SizeOfRawData'])
    # calculate entropy and see if it exceeds the threshold
    e = byte_entropy(data)
    if e > THRESHOLD:
      alert_fmts.append(ALERT_FMT.format(s['Name'], (e / 8.0) * 100))
  # return list of alerts for display
  if alert_fmts:
    alerts.append(ALERT_TITLE.format((THRESHOLD / 8.0) * 100, '\n'.join(alert_fmts)))
  return alerts

