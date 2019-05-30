"""
calculate the entropy of the file sections for randomness
"""
import math


# performs shannon analysis:
# https://en.wikipedia.org/wiki/Entropy_(information_theory)
def byte_entropy(data):
  # array of zeroes
  c = [0 for x in range(256)]
  # sum up occurances of each byte from 0 to 255
  for b in data:
    c[b] = c[b] + 1
  # calculate entropy of occurances
  e = abs(sum([(float(x) / len(data)) * math.log(float(x) / len(data), 2) for x in c if (x != 0)]))
  return e


def run(peobject):
  found = []
  alerts = []
  d = peobject.dict()
  for s in d['SECTIONS']:
    # get bytes from section
    data = peobject.read(s['PointerToRawData'], s['SizeOfRawData'])
    # calculate entropy and see if it exceeds the threshold
    e = byte_entropy(data)
    found.append('Entropy for section {0} is {1:.2f}%'.format(s['Name'], (e / 8.0) * 100))
  # this rule generates only one alert
  if found:
    alerts.append({
      'title': 'Malware Obfuscation',
      'description': 'The following sections may contain encrypted/packed data that will be decrypted or unpacked at runtime if they have high Entropy.',
      'data': found,
      'code': '',
    })
  return alerts

