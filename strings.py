import argparse
import re

BANNER = """
*******************************************************************************
strings v0.1
*******************************************************************************

# help:
python strings.py -h

# ASCII & UTF-16LE strings (latin is default) with a min length of 6
python strings.py <file> -n 6

# ASCII & UTF-16LE cjk strings (chinese/japanese/korean)
python strings.py <file> -u cjk

*******************************************************************************
"""

# regex for ascii and supported languages
_ascii = '[0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~ ]'
_lang = { 
  # languages are encoded in little endian for windows
  'latin':    r'(?:[\x20-\x7E][\x00])',               # 0020-007F (includes space)
  'cyrillic': r'(?:[\x00-\xFF][\x04]|\x20\x00)',      # 0400-04FF with space
  'arabic':   r'(?:[\x00-\xFF][\x06]|\x20\x00)',      # 0600-06FF with space
  'hebrew':   r'(?:[\x90-\xFF][\x05]|\x20\x00)',      # 0590-05FF with space
  'cjk':      r'(?:[\x00-\xFF][\x4E-\x9F]|\x20\x00)', # 4E00-9FFF with space 
}


if __name__ == '__main__':
  # parse user arguments
  parser = argparse.ArgumentParser(usage=BANNER)
  # required arguments
  parser.add_argument('file', 
                      type=str, 
                      help='file to search through')
  # optional arguments
  parser.add_argument('-n', 
                      type=int, 
                      default=4,
                      dest='str_length', 
                      help='minimum length to be considered a string (default 4)')
  parser.add_argument('-u', 
                      type=str,
                      choices=_lang.keys(), 
                      default='latin',
                      dest='utf', 
                      help='find UTF-16LE strings for a given language (default latin)')
  args = parser.parse_args()
  regex_ascii = re.compile('{0}{{{1},}}'.format(_ascii, args.str_length).encode('UTF-8'))
  # parse files
  with open(args.file, 'rb') as f:
    data = f.read()
    # check for ASCII by default
    print('*' * 80)
    print('ASCII strings')
    print('*' * 80)
    for s in regex_ascii.findall(data):
      print(s.decode('UTF-8'))
    # check for UTF-16LE 
    if args.utf:
      print('\n')
      print('*' * 80)
      print('UTF-16LE strings (' + args.utf + ')')
      print('*' * 80)
      regex_utf = re.compile('{0}{{{1},}}'.format(_lang[args.utf], args.str_length).encode('UTF-8'))
      for s in [b.decode('UTF-16LE') for b in regex_utf.findall(data)]:
        print(s)
