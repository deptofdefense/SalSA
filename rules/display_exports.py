"""
simply display the exported functions from the executable if there are any
"""

def run(peobject):
  found = []
  alerts = []
  for e in peobject.parse_exports():
    if e['name']:
      if not e['offset']:
        found.append('ordinal({0}) | File Offset: N/A | [Fowarded Export] {1}'.format(e['ordinal'], e['name']))
      else:
        found.append('ordinal({0}) | File Offset: {1} | {2}'.format(e['ordinal'], hex(e['offset']).rstrip('L'), e['name']))
    else:
      found.append('ordinal({0}) | File Offset: {1} | [Exported by ordinal only]'.format(e['ordinal'], hex(e['offset']).rstrip('L'),))
  # this rule generates only one alert
  if found:
    alerts.append({
      'title': 'Executable Exported Functions',
      'description': 'Exported functions can indicate executable functionality.',
      'data': found,
      'code': '',
    })
  return alerts
