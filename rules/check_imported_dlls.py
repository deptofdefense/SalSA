"""
Align imported dlls/functions to executable functionality.
All function descriptions taken from offical MSDN documentation.

possible expansions:
http://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#article
"""

# list of targeted functions and their descriptions
targets = {
  '':'Unknown. Ordinal is decoded at runtime. To see ordinal mapping, Find the DLL and use the parse_exports() method of the PE class.',
  'CreateFile':'Creates or opens a file or I/O device.',
  'CreateMutex':'Creates or opens a named or unnamed mutex object.',
  'CreateProcess':'Creates a new process and its primary thread. The new process runs in the security context of the calling process.',
  'CreateRemoteThread':'Creates a thread that runs in the virtual address space of another process.',
  'CreateToolhelp32Snapshot':'Creates a thread that runs in the virtual address space of another process.',
  'EnumProcesses':'Retrieves the process identifier for each process object in the system.',
  'FindResource':'Determines the location of a resource with the specified type and name in the specified module.',
  'FindWindow':'Retrieves a handle to the top-level window whose class name and window name match the specified strings.',
  'GetAsyncKeyState':'Determines whether a key is up or down at the time the function is called',
  'GetClipboardData':'Retrieves data from the clipboard in a specified format.',
  'GetModuleHandle':'Retrieves a module handle for the specified module (gets a file handle to an executable file).',
  'GetProcAddress':'Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).',
  'GetWindowText':'Copies the text of the specified window title bar.',
  'HttpOpenRequest':'Creates an HTTP request handle.',
  'HttpSendRequest':'Sends the specified request to the HTTP server, allowing callers to send extra data beyond what is normally passed to HttpSendRequestEx.',
  'InternetOpen':'Initializes an use of the WinINet functions.',
  'InternetReadFile':'Reads data from a handle opened by the InternetOpenUrl, FtpOpenFile, or HttpOpenRequest function.',
  'LoadLibrary':'Loads the specified module into the address space of the calling process.',
  'LockResource':'Retrieves a pointer to the specified resource in memory.',
  'OpenProcess':'Opens an existing process object running on the system.',
  'ReadProcessMemory':'Reads data from an area of memory in a specified process.',
  'RegOpenKeyEx':'Opens the specified registry key.',
  'SetWindowsHookEx':'Installs an application-defined hook procedure into a hook chain. You would install a hook procedure to monitor the system for certain types of events. These events are associated either with a specific thread or with all threads in the same desktop as the calling thread.',
  'ShellExecute':'Performs an operation on a specified file.',
  'VirtualAlloc':'Determines the location of a resource with the specified type and name in the specified module.',
  'VirtualAllocEx':'Reserves, commits, or changes the state of a region of memory within the virtual address space of another process.',
  'VirtualProtect':'Changes the memory protection on a region of committed pages in the virtual address space of the calling process.',
  'WinExec':'Runs the specified application.',
  'WriteProcessMemory':'Writes data to an area of memory in a specified process.',
}


# matrix to represent functionality with DLL function imports
matrix = [
  {
    'imports': [''], # empty container to represent all functions imported by ordinal.
    'output': 'Executable Obfuscation: executable using ordinals to specify DLL imports, which prevents static import analysis',
  },
  {
    'imports': ['GetAsyncKeyState', 'SetWindowsHookEx'],
    'output': 'Keylogger: executable possibly hooking user keyboard input',
  },
  {
    'imports': ['LoadLibrary', 'GetProcAddress'],
    'output': 'Dynamic DLL Loading: executable possibly imports DLLs at runtime',
  },
  {
    'imports': ['CreateRemoteThread', 'OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'EnumProcesses'],
    'output': 'Code Injection: executable possibly creating threads in running processes',
  },
  {
    'imports': ['CreateToolhelp32Snapshot', 'OpenProcess', 'ReadProcessMemory', 'EnumProcesses'],
    'output': 'Memory Scraping: executable possibly trying to read RAM of running processes',
  },
  {
    'imports': ['GetClipboardData', 'GetWindowText'],
    'output': 'Data Stealing: executable possibly reading user data',
  },
  {
    'imports': ['FindResource', 'LockResource'],
    'output': 'Embedded Resources: executable possibly reading sensitive data from resources section of executable',
  },
  {
    'imports': ['VirtualAlloc', 'VirtualProtect'],
    'output': 'Unpacking/Self-Injection: executable possibly packed or injecting code at runtime into itself',
  },
  {
    'imports': ['CreateMutex', 'CreateFile', 'FindWindow', 'GetModuleHandle', 'RegOpenKeyEx'],
    'output': 'System Artifacts: executable possibly creating system artifacts',
  },
  {
    'imports': ['WinExec', 'ShellExecute', 'CreateProcess'],
    'output': 'Program Exection: executable possibly executing a shell or spawning another process',
  },
  {
    'imports': ['InternetOpen', 'HttpOpenRequest', 'HttpSendRequest', 'InternetReadFile'],
    'output': 'Web Interaction: executable possibly making HTTP web requests',
  },
]

ALERT_FMT = """
{0}

Imports:
{1}
"""

def run(peobject):
  # array to hold list of final alerts
  alerts = []
  # temp dictionary to hold list of (dll, function) tuples
  temp = {}
  # search for functionality in imports list
  for dll in peobject.parse_imports():
    # loop through each function in the DLL
    for f in dll['functions']:
      # check for function in matrix (by name)
      for x in matrix:
        if f['name'] in x['imports']:
          ordinal = hex(f['ordinal']) if f['ordinal'] else f['ordinal']
          # add to results array
          if x['output'] not in temp.keys():
            temp[x['output']] = [(dll['dll'], f['name'], ordinal)]
          else:
            temp[x['output']].append((dll['dll'], f['name'], ordinal))
          break
  # format each alert
  for a in temp.keys():
    # format the output for each import
    functions = '\n'.join([
      ''.join(['[',f[0],'] ',
               f[1] if f[1] else 'ordinal({0})'.format(f[2]), # check for import by ordinal
               ' - ',targets[f[1]]
              ]) for f in temp[a] if f[1] in targets.keys()
    ])
    alerts.append(ALERT_FMT.format(a, functions))
  return alerts
