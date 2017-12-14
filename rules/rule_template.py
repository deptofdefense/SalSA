"""
standard template for new rules
"""

def run(peobject):
  # see PE object spec for how to use the 'peobject' variable
  # array to hold list of final alerts
  alerts = []
  # adding an alert here
  alerts.append({
    'title': 'Alert title',
    'description': 'Description of alert',
    'data': ['list', 'of', 'data', 'for', 'alert'],
    'code': 'interesting code or binary data that triggered the alert',
  })
  # return list of alerts for display
  return alerts
