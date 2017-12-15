## SalSA - (Salvaging Static Analysis)

Documentation available at: https://github.com/deptofdefense/SALSA/wiki

Malware analysis theory has been standardized in industry. It consists of 3 steps:

1. Static Analysis - not running the malware
2. Dynamic Analysis - running the malware
3. Debugging - stepping through the malware with a debugger (IDA pro, Olly Debug, etc)

The first step is often thought of as just running strings. This is only a small part of what industry considers static analysis. PE file format parsing alongside open-source intelligence is considered the industry standard for static analysis. PE file format parsing includes:

- Strings (ASCII and Unicode)
- Signature Checking
- File Hashing
- Import/Export Analysis
- ... (many more)

Just running strings limits the analyst to a small subset and often misleading portion of this vital step in malware analysis. Good static malware analysis can quickly triage executables, allowing for a subset of suspicious executables to be tested under dynamic analysis. As the analyst progresses to dynamic analysis and then debugging, the amount of time required drastically increases and the returns diminish rapidly.

This project parses the PE file format and presents it all to the analyst as a Python dictionary for easy analysis. Additionally, this project takes this further by creating a list of rules (in `rules` directory) that checks for certain malware behaviors. The hope is that this project allows for the analyst to automate the static analysis process and quickly triage malware based on a robust set of homebuilt rules based on current white-papers in industry.
