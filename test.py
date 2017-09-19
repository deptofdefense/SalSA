
import pprint
import pe

pefile = pe.PE('malware.exe')


d = pefile.dict()
print pprint.pformat(d, indent=2)

print '*' * 80
print 'IMPORTS:'
print '*' * 80

print pprint.pformat(pefile.parse_imports(), indent=2)

print '*' * 80
print 'EXPORTS:'
print '*' * 80

print pprint.pformat(pefile.parse_exports(), indent=2)

print '*' * 80
print 'RELOCATIONS:'
print '*' * 80

print pprint.pformat(pefile.parse_relocations(), indent=2)

print '*' * 80
print 'TLS:'
print '*' * 80

print pprint.pformat(pefile.parse_tls(), indent=2)

print '*' * 80
print 'RESOURCES:'
print '*' * 80

print pprint.pformat(pefile.parse_resources(), indent=2)
