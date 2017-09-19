"""
Align imported dlls/functions to executable functionality.
All function descriptions taken from offical MSDN documentation.

possible expansions:
http://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#article
"""

# list of functions and their descriptions
imports = [
  {
    'function':'CreateFile',
    'description':'Creates or opens a file or I/O device.',
  },
  {
    'function':'CreateMutex',
    'description':'Creates or opens a named or unnamed mutex object.',
  },
  {
    'function':'CreateProcess',
    'description':'Creates a new process and its primary thread. The new process runs in the security context of the calling process.',
  },
  {
    'function':'CreateRemoteThread',
    'description':'Creates a thread that runs in the virtual address space of another process.',
  },
  {
    'function':'CreateToolhelp32Snapshot',
    'description':'Creates a thread that runs in the virtual address space of another process.',
  },
  {
    'function':'EnumProcesses',
    'description':'Retrieves the process identifier for each process object in the system.',
  },
  {
    'function':'FindResource',
    'description':'Determines the location of a resource with the specified type and name in the specified module.',
  },
  {
    'function':'FindWindow',
    'description':'Retrieves a handle to the top-level window whose class name and window name match the specified strings.',
  },
  {
    'function':'GetAsyncKeyState',
    'description':'Determines whether a key is up or down at the time the function is called',
  },
  {
    'function':'GetClipboardData',
    'description':'Retrieves data from the clipboard in a specified format.',
  },
  {
    'function':'GetModuleHandle',
    'description':'Retrieves a module handle for the specified module (gets a file handle to an executable file).',
  },
  {
    'function':'GetProcAddress',
    'description':'Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).',
  },
  {
    'function':'GetWindowText',
    'description':'Copies the text of the specified window title bar.',
  },
  {
    'function':'HttpOpenRequest',
    'description':'Creates an HTTP request handle.',
  },
  {
    'function':'HttpSendRequest',
    'description':'Sends the specified request to the HTTP server, allowing callers to send extra data beyond what is normally passed to HttpSendRequestEx.',
  },
  {
    'function':'InternetOpen',
    'description':'Initializes an use of the WinINet functions.',
  },
  {
    'function':'InternetReadFile',
    'description':'Reads data from a handle opened by the InternetOpenUrl, FtpOpenFile, or HttpOpenRequest function.',
  },
  {
    'function':'LoadLibrary',
    'description':'Loads the specified module into the address space of the calling process.',
  },
  {
    'function':'LockResource',
    'description':'Retrieves a pointer to the specified resource in memory.',
  },
  {
    'function':'OpenProcess',
    'description':'Opens an existing process object running on the system.',
  },
  {
    'function':'ReadProcessMemory',
    'description':'Reads data from an area of memory in a specified process.',
  },
  {
    'function':'RegOpenKeyEx',
    'description':'Opens the specified registry key.',
  },
  {
    'function':'SetWindowsHookEx',
    'description':'Installs an application-defined hook procedure into a hook chain. You would install a hook procedure to monitor the system for certain types of events. These events are associated either with a specific thread or with all threads in the same desktop as the calling thread.',
  },
  {
    'function':'ShellExecute',
    'description':'Performs an operation on a specified file.',
  },
  {
    'function':'VirtualAlloc',
    'description':'Determines the location of a resource with the specified type and name in the specified module.',
  },
  {
    'function':'VirtualAllocEx',
    'description':'Reserves, commits, or changes the state of a region of memory within the virtual address space of another process.',
  },
  {
    'function':'VirtualProtect',
    'description':'Changes the memory protection on a region of committed pages in the virtual address space of the calling process.',
  },
  {
    'function':'WinExec',
    'description':'Runs the specified application.',
  },
  {
    'function':'WriteProcessMemory',
    'description':'Writes data to an area of memory in a specified process.',
  }
]


# matrix to represent functionality with DLL function imports
matrix = [
  {
    'imports': ['GetAsyncKeyState', 'SetWindowsHookEx'],
    'output': 'Keylogger (executable possibly hooking user keyboard input)',
  },
  {
    'imports': ['LoadLibrary', 'GetProcAddress'],
    'output': 'Dynamic DLL Loading (executable possibly imports DLLs at runtime)',
  },
  {
    'imports': ['CreateRemoteThread', 'OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'EnumProcesses'],
    'output': 'Code Injection (executable possibly creating threads in running processes)',
  },
  {
    'imports': ['CreateToolhelp32Snapshot', 'OpenProcess', 'ReadProcessMemory', 'EnumProcesses'],
    'output': 'Memory Scraping (executable possibly trying to read RAM of running processes)',
  },
  {
    'imports': ['GetClipboardData', 'GetWindowText'],
    'output': 'Data Stealing (executable possibly reading user data)',
  },
  {
    'imports': ['FindResource', 'LockResource'],
    'output': 'Embedded Resources (executable possibly reading sensitive data from resources section of executable)',
  },
  {
    'imports': ['VirtualAlloc', 'VirtualProtect'],
    'output': 'Unpacking/Self-Injection (executable possibly packed or injecting code at runtime into itself)',
  },
  {
    'imports': ['CreateMutex', 'CreateFile', 'FindWindow', 'GetModuleHandle', 'RegOpenKeyEx'],
    'output': 'System Artifacts (executable possibly creating system artifacts)',
  },
  {
    'imports': ['WinExec', 'ShellExecute', 'CreateProcess'],
    'output': 'Program Exection (executable possibly executing a shell or spawning another process)',
  },
  {
    'imports': ['InternetOpen', 'HttpOpenRequest', 'HttpSendRequest', 'InternetReadFile'],
    'output': 'Web Interaction (executable possibly making HTTP web requests)',
  },
]

ALERT_FMT = """
{0} (Level: {1})

Imports:
{2}
"""

def run(peobject):
  # array to hold list of final alaerts
  alerts = []
  # temp dictionary to hold list of offending functions
  temp = {}
  # search for functionality in imports list
  for dll in peobject.parse_imports():
    # loop through each function in the DLL
    for f in dll['functions']:
      # check for function in matrix (by name and odrinal)
      for x in matrix:
        # TODO: check for ordinal
        if f['name'] in x['imports']:
          # add to results array
          if x['output'] not in temp.keys():
            temp[x['output']] = [f['name']]
          else:
            temp[x['output']].append(f['name'])
  # format each alert
  for a in temp.keys():
    functions = '\n'.join([''.join([f['function'],' - ',f['description']]) for f in imports if f['function'] in temp[a]])
    alerts.append({
      'level': len(temp[a]),
      'text': ALERT_FMT.format(a, str(len(temp[a])), functions)
    })
  return alerts
