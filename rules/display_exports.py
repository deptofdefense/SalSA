"""
simply display the exported functions from the executable if there are any
"""

ALERT_FMT = """
Executable Exported Functions:

{0}
"""

def run(peobject):
  alerts = []
  alert_fmt = []
  for e in peobject.parse_exports():
    if e['name']:
      if not e['offset']:
        alert_fmt.append('\t- ordinal({0}) | File Offset: N/A | [Fowarded Export] {1}'.format(e['ordinal'], e['name']))
      else:
        alert_fmt.append('\t- ordinal({0}) | File Offset: {1} | {2}'.format(e['ordinal'], hex(e['offset']).rstrip('L'), e['name']))
    else:
      alert_fmt.append('\t- ordinal({0}) | File Offset:: {1} | [Exported by ordinal only]'.format(e['ordinal'], hex(e['offset']).rstrip('L'),))
  if alert_fmt:
    alerts.append(ALERT_FMT.format('\n'.join(alert_fmt)))
  return alerts
