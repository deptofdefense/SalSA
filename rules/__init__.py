"""
 TODO:
 - check language codes from resources
 - check for x86 exception handler hijacking
 - check for code caves?
 - check for uncommon things
 - import hash calculations
 - sigcheck
"""

__all__ = [
  'check_dos_stub',
  'check_section_sizes',
  'check_section_names',
  'check_section_permissions',
  'check_section_strings',
  'check_entropy',
  'check_imported_dlls',
]

