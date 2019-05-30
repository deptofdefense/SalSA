
"""
checks sections for common strings
"""
import re

# regex patterns to look for
patterns = {
  # local and remote filepaths
  re.compile(r'(?:[a-zA-Z]\:|[\w ]+)?\\+(?:[\w\- .\\$~]+)*[\w\- .]*'),
  # IP addresses
  re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'),
  # files
  re.compile(r'^[\w\- ]+\.\w+$'),
  # urls/protocols
  re.compile(r'(?:(?:http|HTTP|https|HTTPS|ftp|FTP|smtp|SMTP|irc|IRC|smb|SMB)?:\/\/)?[\w.-]+\.[\w.-]{2,6}[\/\w.-]*\??[\w.=\-]*'),
  # emails
  re.compile(r'(?:[a-z0-9_\.-]+)@(?:[\da-z\.-]+)\.(?:[a-z\.]{2,6})'),
}


# takes a list of strings and applies the patterns above to each string in the list
def match_patterns(strings):
  found = set()
  for string in strings:
    for p in patterns:
      for match in p.findall(string):
        if (len(match) > 2) and (match not in found):
          found.add(match)
  return found


def run(peobject):
  alerts = []
  non_section_ranges = [[0, -1]] # the whole file
  # loop through each section and keep track of non-section ranges
  d = peobject.dict()
  if 'SECTIONS' in d:
    for s in d['SECTIONS']:
      # extract strings from section
      strings = peobject.parse_strings(start=s['PointerToRawData'], size=s['SizeOfRawData'])
      # remove section from non-section range
      for r in non_section_ranges:
        start, end = r[0], r[1]
        if (start <= s['PointerToRawData']) and ((end < 0) or ((s['PointerToRawData'] + s['SizeOfRawData']) <= end)):
          non_section_ranges.append([s['PointerToRawData'] + s['SizeOfRawData'], r[1]])
          r[1] = s['PointerToRawData']
          break
      # search for string patterns in ascii/latin
      found = match_patterns(strings['ascii'] + strings['latin'])
      # add to overall alert if there is content
      if found:
        alerts.append({
          'title': 'Section {0} Possible Strings of Interest'.format(s['Name']),
          'description': 'Strings that match the following patterns: local/remote filepaths, IP addresses, filenames, urls, email addresses',
          'data': found,
          'code': '',
        })
    # find strings in non-section data
    for r in non_section_ranges:
      start, end = r[0], r[1]
      size = -1 if (end < start) else (end - start)
      strings = peobject.parse_strings(start=start, size=size)
      non_section_strings = match_patterns(strings['ascii'] + strings['latin'])
      # add to overall alert if there is content
      if non_section_strings:
        range_end = 'EOF' if (end < start) else hex(end)
        alerts.append({
          'title': 'Non-Section (File Offset Range {0} - {1}) Possible Strings of Interest'.format(hex(start), range_end),
          'description': 'These are not mapped into memory at runtime. Malware could place disk persistence here to be referenced by some other executable.',
          'data': non_section_strings,
          'code': '',
        })
  return alerts
