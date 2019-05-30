# SalSA - (`Sal`vaging `S`tatic `A`nalysis)

Documentation available at: https://github.com/deptofdefense/SALSA/wiki

Malware analysis theory has been standardized in industry. It consists of 3 steps:

* Static Analysis - not running the malware
* Dynamic Analysis - running the malware
* Debugging - stepping through the malware with a debugger (IDA pro, Olly Debug, etc)

The first step is often thought of as just looking at strings. This is only a small part of what industry considers static analysis. Just looking at strings limits the analyst to a small subset and often misleading portion of this vital step in malware analysis. Good static malware analysis can quickly triage executables, allowing for a subset of suspicious executables to be tested under dynamic analysis. Then as the analyst progresses through dynamic analysis to debugging, the amount of time required drastically increases and the returns diminish rapidly. This tool parses the PE file format and presents it all to the analyst for quick triage. Additionally, this project takes this further by using a list of rules that checks for certain malware behaviors.
