MAX_PATH: int = 260
"""
The maximum length for a path string.
"""

INFINITE: int = -1
"""
A numeric represantion of infinity.
"""

WAIT_OBJECT_0: int = 0x00000000
"""
The state of the specified object is signaled.
"""

WAIT_ABANDONED: int = 0x00000080
"""
The specified object is a mutex object that was not released by the thread that owned the mutex object before the owning
thread terminated. Ownership of the mutex object is granted to the calling thread and the mutex state is set to 
nonsignaled.
If the mutex was protecting persistent state information, you should check it for consistency.
"""

WAIT_TIMEOUT: int = 0x00000102
"""
The time-out interval elapsed, and the object's state is nonsignaled.
"""

WAIT_FAILED: int = 0xFFFFFFFF
"""
The function has failed. To get extended error information, call GetLastError.
"""

STATUS_SUCCESS: int = 0
"""
The operation completed successfully.
"""

STATUS_WAIT_0: int = 0
"""
The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the 
signaled state.
"""

STATUS_WAIT_1: int = 1
"""
The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the 
signaled state.
"""

STATUS_WAIT_2: int = 2
"""
The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the 
signaled state.
"""

STATUS_WAIT_3: int = 3
"""
The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the 
signaled state.
"""

STATUS_WAIT_63: int = 63
"""
The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the 
signaled state.
"""

STATUS_ABANDONED_WAIT_0: int = 128
"""
The caller attempted to wait for a mutex that has been abandoned.
"""

STATUS_ABANDONED_WAIT_63: int = 191
"""
The caller attempted to wait for a mutex that has been abandoned.
"""

STATUS_USER_APC: int = 192
"""
A user-mode APC was delivered before the given Interval expired.
"""

STATUS_TIMEOUT: int = 258
"""
The given Timeout interval expired.
"""

STATUS_PENDING: int = 259
"""
The operation that was requested is pending completion.
"""

STATUS_SEGMENT_NOTIFICATION: int = 1073741829
"""
{Segment Load} A virtual DOS machine (VDM) is loading, unloading, or moving an MS-DOS or Win16 program segment image. 
An exception is raised so that a debugger can load, unload, or track symbols and breakpoints within these 16-bit 
segments.
"""

STATUS_GUARD_PAGE_VIOLATION: int = -2147483647
"""
{EXCEPTION} Guard Page Exception A page of memory that marks the end of a data structure, such as a stack or an array, 
has been accessed.
"""

STATUS_DATATYPE_MISALIGNMENT: int = -2147483646
"""
{EXCEPTION} Alignment Fault A data type misalignment was detected in a load or store instruction.
"""

STATUS_BREAKPOINT: int = -2147483645
"""
{EXCEPTION} Breakpoint A breakpoint has been reached.
"""

STATUS_SINGLE_STEP: int = -2147483644
"""
{EXCEPTION} Single Step A single step or trace operation has just been completed.
"""

STATUS_ACCESS_VIOLATION: int = -1073741819
"""
The instruction at 0x%08lx referenced memory at 0x%08lx. The memory could not be %s.
"""

STATUS_IN_PAGE_ERROR: int = -1073741818
"""
The instruction at 0x%08lx referenced memory at 0x%08lx. The required data was not placed into memory because of an I/O
error status of 0x%08lx.
"""

STATUS_INVALID_HANDLE: int = -1073741816
"""
An invalid HANDLE was specified.
"""

STATUS_NO_MEMORY: int = -1073741801
"""
{Not Enough Quota} Not enough virtual memory or paging file quota is available to complete the specified operation.
"""

STATUS_ILLEGAL_INSTRUCTION: int = -1073741795
"""
{EXCEPTION} Illegal Instruction An attempt was made to execute an illegal instruction.
"""

STATUS_NONCONTINUABLE_EXCEPTION: int = -1073741787
"""
{EXCEPTION} Cannot Continue Windows cannot continue from this exception.
"""

STATUS_INVALID_DISPOSITION: int = -1073741786
"""
An invalid exception disposition was returned by an exception handler.
"""

STATUS_ARRAY_BOUNDS_EXCEEDED: int = -1073741684
"""
{EXCEPTION} Array bounds exceeded.
"""

STATUS_FLOAT_DENORMAL_OPERAND: int = -1073741683
"""
{EXCEPTION} Floating-point denormal operand.
"""

STATUS_FLOAT_DIVIDE_BY_ZERO: int = -1073741682
"""
{EXCEPTION} Floating-point division by zero.
"""

STATUS_FLOAT_INEXACT_RESULT: int = -1073741681
"""
{EXCEPTION} Floating-point inexact result.
"""

STATUS_FLOAT_INVALID_OPERATION: int = -1073741680
"""
{EXCEPTION} Floating-point invalid operation.
"""

STATUS_FLOAT_OVERFLOW: int = -1073741679
"""
{EXCEPTION} Floating-point overflow.
"""

STATUS_FLOAT_STACK_CHECK: int = -1073741678
"""
{EXCEPTION} Floating-point stack check.
"""

STATUS_FLOAT_UNDERFLOW: int = -1073741677
"""
{EXCEPTION} Floating-point stack check.
"""

STATUS_INTEGER_DIVIDE_BY_ZERO: int = -1073741676
"""
{EXCEPTION} Integer division by zero.
"""

STATUS_INTEGER_OVERFLOW: int = -1073741675
"""
{EXCEPTION} Integer overflow.
"""

STATUS_PRIVILEGED_INSTRUCTION: int = -1073741674
"""
{EXCEPTION} Privileged instruction.
"""

STATUS_STACK_OVERFLOW: int = -1073741571
"""
A new guard page for the stack cannot be created.
"""

STATUS_CONTROL_C_EXIT: int = -1073741510
"""
{Application Exit by CTRL+C} The application terminated as a result of a CTRL+C.
"""

STILL_ACTIVE: int = STATUS_PENDING
"""
The operation that was requested is pending completion.
"""


DEBUG_PROCESS: int = 0x00000001
"""
The calling thread starts and debugs the new process and all child processes created by the new process. It can receive
all related debug events using the WaitForDebugEvent function.
"""

DEBUG_ONLY_THIS_PROCESS: int = 0x000000082
"""
The calling thread starts and debugs the new process. It can receive all related debug events using the 
WaitForDebugEvent function.
"""

CREATE_SUSPENDED: int = 0x00000004
"""
The primary thread of the new process is created in a suspended state, and does not run until the ResumeThread function
is called.
"""

DETACHED_PROCESS: int = 0x00000008
"""
For console processes, the new process does not inherit its parent's console (the default). The new process can call 
the AllocConsole function at a later time to create a console. This value cannot be used with CREATE_NEW_CONSOLE.
"""

CREATE_NEW_CONSOLE: int = 0x00000010
"""
The new process has a new console, instead of inheriting its parent's console (the default). For more information, see 
Creation of a Console. This flag cannot be used with DETACHED_PROCESS.
"""

NORMAL_PRIORITY_CLASS: int = 0x00000020
"""
Process with no special scheduling needs.
"""

IDLE_PRIORITY_CLASS: int = 0x00000040
"""
Process whose threads run only when the system is idle. The threads of the process are preempted by the threads of any 
process running in a higher priority class. An example is a screen saver. The idle-priority class is inherited by child
processes.
"""

HIGH_PRIORITY_CLASS: int = 0x00000080
"""
Process that performs time-critical tasks that must be executed immediately. The threads of the process preempt the 
threads of normal or idle priority class processes. An example is the Task List, which must respond quickly when called 
by the user, regardless of the load on the operating system. Use extreme care when using the high-priority class, 
because a high-priority class application can use nearly all available CPU time.
"""

REALTIME_PRIORITY_CLASS: int = 0x00000100
"""
Process that has the highest possible priority. The threads of the process preempt the threads of all other processes, 
including operating system processes performing important tasks. For example, a real-time process that executes for more
than a very brief interval can cause disk caches not to flush or cause the mouse to be unresponsive.
"""

BELOW_NORMAL_PRIORITY_CLASS: int = 0x00004000
"""
Process that has priority above IDLE_PRIORITY_CLASS but below NORMAL_PRIORITY_CLASS.
"""

ABOVE_NORMAL_PRIORITY_CLASS: int = 0x00008000
"""
Process that has priority above NORMAL_PRIORITY_CLASS but below HIGH_PRIORITY_CLASS.
"""

PROCESS_MODE_BACKGROUND_BEGIN: int = 0x00100000
"""
Begin background processing mode. The system lowers the resource scheduling priorities of the process (and its threads) 
so that it can perform background work without significantly affecting activity in the foreground. This value can be 
specified only if hProcess is a handle to the current process. The function fails if the process is already in 
background processing mode.
"""

PROCESS_MODE_BACKGROUND_END: int = 0x00200000
"""
End background processing mode. The system restores the resource scheduling priorities of the process (and its threads) 
as they were before the process entered background processing mode. This value can be specified only if hProcess is a 
handle to the current process. The function fails if the process is not in background processing mode.
"""

CREATE_NEW_PROCESS_GROUP: int = 0x00000200
"""
The new process is the root process of a new process group. The process group includes all processes that are 
descendants of this root process. The process identifier of the new process group is the same as the process identifier,
which is returned in the lpProcessInformation parameter. Process groups are used by the GenerateConsoleCtrlEvent 
function to enable sending a CTRL+BREAK signal to a group of console processes.
If this flag is specified, CTRL+C signals will be disabled for all processes within the new process group.
This flag is ignored if specified with CREATE_NEW_CONSOLE.
"""

CREATE_UNICODE_ENVIRONMENT: int = 0x00000400
"""
If this flag is set, the environment block pointed to by lpEnvironment uses Unicode characters. Otherwise, the 
environment block uses ANSI characters.
"""

CREATE_SEPARATE_WOW_VDM: int = 0x00000800
"""
This flag is valid only when starting a 16-bit Windows-based application. If set, the new process runs in a private 
Virtual DOS Machine (VDM). By default, all 16-bit Windows-based applications run as threads in a single, shared VDM. 
The advantage of running separately is that a crash only terminates the single VDM; any other programs running in 
distinct VDMs continue to function normally. Also, 16-bit Windows-based applications that are run in separate VDMs have
separate input queues. That means that if one application stops responding momentarily, applications in separate VDMs 
continue to receive input. The disadvantage of running separately is that it takes significantly more memory to do so. 
You should use this flag only if the user requests that 16-bit applications should run in their own VDM.
"""

CREATE_SHARED_WOW_VDM: int = 0x00001000
"""
The flag is valid only when starting a 16-bit Windows-based application. If the DefaultSeparateVDM switch in the Windows
section of WIN.INI is TRUE, this flag overrides the switch. The new process is run in the shared Virtual DOS Machine.
"""

CREATE_DEFAULT_ERROR_MODE: int = 0x04000000
"""
The new process does not inherit the error mode of the calling process. Instead, the new process gets the default error 
mode. This feature is particularly useful for multithreaded shell applications that run with hard errors disabled.
The default behavior is for the new process to inherit the error mode of the caller. Setting this flag changes that 
default behavior.
"""

CREATE_NO_WINDOW: int = 0x08000000
"""
The process is a console application that is being run without a console window. Therefore, the console handle for the 
application is not set. This flag is ignored if the application is not a console application, or if it is used with 
either CREATE_NEW_CONSOLE or DETACHED_PROCESS.
"""


DELETE: int = 0x00010000
"""
The right to delete the object.
"""

READ_CONTROL: int = 0x00020000
"""
The right to read the information in the object's security descriptor, not including the information in the system 
access control list (SACL).
"""

WRITE_DAC: int = 0x00040000
"""
The right to modify the discretionary access control list (DACL) in the object's security descriptor.
"""

WRITE_OWNER: int = 0x00080000
"""
The right to change the owner in the object's security descriptor.
"""

SYNCHRONIZE: int = 0x00100000
"""
The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled 
state. Some object types do not support this access right.
"""

STANDARD_RIGHTS_REQUIRED: int = 0x000F0000
"""
Combines DELETE, READ_CONTROL, WRITE_DAC, and WRITE_OWNER access.
"""

STANDARD_RIGHTS_ALL: int = 0x001F0000
"""
Combines DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, and SYNCHRONIZE access.
"""


PROCESS_TERMINATE: int = 0x0001
"""
Required to terminate a process using TerminateProcess.
"""

PROCESS_CREATE_THREAD: int = 0x0002
"""
Required to create a thread in the process.
"""

PROCESS_SET_SESSIONID: int = 0x0004
"""
Unknown definition description.
"""

PROCESS_VM_OPERATION: int = 0x0008
"""
Required to perform an operation on the address space of a process (see VirtualProtectEx and WriteProcessMemory).
"""

PROCESS_VM_READ: int = 0x0010
"""
Required to read memory in a process using ReadProcessMemory.
"""

PROCESS_VM_WRITE: int = 0x0020
"""
Required to write to memory in a process using WriteProcessMemory.
"""

PROCESS_DUP_HANDLER: int = 0x0040
"""
Required to duplicate a handle using DuplicateHandle.
"""

PROCESS_CREATE_PROCESS: int = 0x0080
"""
Required to use this process as the parent process with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
"""

PROCESS_SET_QUOTA: int = 0x0100
"""
Required to set memory limits using SetProcessWorkingSetSize.
"""

PROCESS_SET_INFORMATION: int = 0x0200
"""
Required to set certain information about a process, such as its priority class (see SetPriorityClass).
"""

PROCESS_QUERY_INFORMATION: int = 0x0400
"""
Required to retrieve certain information about a process, such as its token, exit code, and priority class (see OpenProcessToken).
"""

PROCESS_SUSPEND_RESUME: int = 0x0800
"""
Required to suspend or resume a process.
"""

PROCESS_QUERY_LIMITED_INFORMATION: int = 0x1000
"""
Required to retrieve certain information about a process (see GetExitCodeProcess, GetPriorityClass, IsProcessInJob, 
QueryFullProcessImageName). A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted 
PROCESS_QUERY_LIMITED_INFORMATION.Windows Server 2003 and Windows XP: This access right is not supported.
"""

PROCESS_SET_LIMITED_INFORMATION: int = 0x2000
"""
Required using SetProcessDefaultCpuSets.
"""

PROCESS_ALL_ACCESS: int = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF
"""
All possible access rights for a process object.Windows Server 2003 and Windows XP: The size of the PROCESS_ALL_ACCESS 
flag increased on Windows Server 2008 and Windows Vista. If an application compiled for Windows Server 2008 and Windows 
Vista is run on Windows Server 2003 or Windows XP, the PROCESS_ALL_ACCESS flag is too large and the function specifying 
this flag fails with ERROR_ACCESS_DENIED. To avoid this problem, specify the minimum set of access rights required for 
the operation. If PROCESS_ALL_ACCESS must be used, set _WIN32_WINNT to the minimum operating system targeted by your 
application (for example, #define _WIN32_WINNT _WIN32_WINNT_WINXP). For more information, see Using the Windows Headers.
"""



PAGE_NOACCESS: int = 0x00000001
"""
Disables all access to the committed region of pages. An attempt to read from, write to, or execute the committed region
 results in an access violation. This flag is not supported by the CreateFileMapping function.
"""

PAGE_READONLY: int = 0x00000002
"""
Enables read-only access to the committed region of pages. An attempt to write to the committed region results in an 
access violation. If Data Execution Prevention is enabled, an attempt to execute code in the committed region results 
in an access violation.
"""

PAGE_READWRITE: int = 0x00000004
"""
Enables read-only or read/write access to the committed region of pages. If Data Execution Prevention is enabled, 
attempting to execute code in the committed region results in an access violation.
"""

PAGE_WRITECOPY: int = 0x00000008
"""
Enables read-only or copy-on-write access to a mapped view of a file mapping object. An attempt to write to a committed 
copy-on-write page results in a private copy of the page being made for the process. The private page is marked as 
PAGE_READWRITE, and the change is written to the new page. If Data Execution Prevention is enabled, attempting to 
execute code in the committed region results in an access violation. This flag is not supported by the VirtualAlloc or 
VirtualAllocEx functions.
"""

PAGE_EXECUTE: int = 0x00000010
"""
Enables execute access to the committed region of pages. An attempt to write to the committed region results in an 
access violation. This flag is not supported by the CreateFileMapping function.
"""

PAGE_EXECUTE_READ: int = 0x00000020
"""
Enables execute or read-only access to the committed region of pages. An attempt to write to the committed region 
results in an access violation. Windows Server 2003 and Windows XP: This attribute is not supported by the 
CreateFileMapping function until Windows XP with SP2 and Windows Server 2003 with SP1.
"""

PAGE_EXECUTE_READWRITE: int = 0x00000040
"""
Enables execute, read-only, or read/write access to the committed region of pages. Windows Server 2003 and Windows XP: 
This attribute is not supported by the CreateFileMapping function until Windows XP with SP2 and Windows Server 2003 
with SP1.
"""

PAGE_EXECUTE_WRITECOPY: int = 0x00000080
"""
Enables execute, read-only, or copy-on-write access to a mapped view of a file mapping object. An attempt to write to a
committed copy-on-write page results in a private copy of the page being made for the process. The private page is
marked as PAGE_EXECUTE_READWRITE, and the change is written to the new page. This flag is not supported by the 
VirtualAlloc or VirtualAllocEx functions. Windows Vista, Windows Server 2003 and Windows XP: This attribute is not 
supported by the CreateFileMapping function until Windows Vista with SP1 and Windows Server 2008.
"""

PAGE_GUARD: int = 0x00000100
"""
Pages in the region become guard pages. Any attempt to access a guard page causes the system to raise a 
STATUS_GUARD_PAGE_VIOLATION exception and turn off the guard page status. Guard pages thus act as a one-time access 
alarm. For more information, see Creating Guard Pages. When an access attempt leads the system to turn off guard page 
status, the underlying page protection takes over. If a guard page exception occurs during a system service, the service
typically returns a failure status indicator. This value cannot be used with PAGE_NOACCESS. This flag is not supported 
by the CreateFileMapping function.
"""

PAGE_NOCACHE: int = 0x00000200
"""
Sets all pages to be non-cachable. Applications should not use this attribute except when explicitly required for a 
device. Using the interlocked functions with memory that is mapped with SEC_NOCACHE can result in an 
EXCEPTION_ILLEGAL_INSTRUCTION exception. The PAGE_NOCACHE flag cannot be used with the PAGE_GUARD, PAGE_NOACCESS, or 
PAGE_WRITECOMBINE flags. The PAGE_NOCACHE flag can be used only when allocating private memory with the VirtualAlloc, 
VirtualAllocEx, or VirtualAllocExNuma functions. To enable non-cached memory access for shared memory, specify the 
SEC_NOCACHE flag when calling the CreateFileMapping function.
"""

PAGE_WRITECOMBINE: int = 0x00000400
"""
Sets all pages to be write-combined. Applications should not use this attribute except when explicitly required for a 
device. Using the interlocked functions with memory that is mapped as write-combined can result in an 
EXCEPTION_ILLEGAL_INSTRUCTION exception. The PAGE_WRITECOMBINE flag cannot be specified with the PAGE_NOACCESS, 
PAGE_GUARD, and PAGE_NOCACHE flags. The PAGE_WRITECOMBINE flag can be used only when allocating private memory with the 
VirtualAlloc, VirtualAllocEx, or VirtualAllocExNuma functions. To enable write-combined memory access for shared memory,
specify the SEC_WRITECOMBINE flag when calling the CreateFileMapping function. Windows Server 2003 and Windows XP: This
flag is not supported until Windows Server 2003 with SP1.
"""

PAGE_TARGETS_INVALID: int = 0x40000000
"""
Sets all locations in the pages as invalid targets for CFG. Used along with any execute page protection like 
PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE and PAGE_EXECUTE_WRITECOPY. Any indirect call to locations in 
those pages will fail CFG checks and the process will be terminated. The default behavior for executable pages allocated
is to be marked valid call targets for CFG. This flag is not supported by the VirtualProtect or CreateFileMapping 
functions.
"""

PAGE_TARGETS_NO_UPDATE: int = 0x40000000
"""
Pages in the region will not have their CFG information updated while the protection changes for VirtualProtect. For 
example, if the pages in the region was allocated using PAGE_TARGETS_INVALID, then the invalid information will be 
maintained while the page protection changes. This flag is only valid when the protection changes to an executable type
like PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE and PAGE_EXECUTE_WRITECOPY. The default behavior for
VirtualProtect protection change to executable is to mark all locations as valid call targets for CFG.
"""


MEM_COALESCE_PLACEHOLDERS: int = 0x00000001
"""
To coalesce two adjacent placeholders, specify MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS. When you coalesce placeholders,
lpAddress and dwSize must exactly match the overall range of the placeholders to be merged.
"""

MEM_PRESERVE_PLACEHOLDER: int = 0x00000002
"""
Frees an allocation back to a placeholder (after you've replaced a placeholder with a private allocation using 
VirtualAlloc2 or Virtual2AllocFromApp).
To split a placeholder into two placeholders, specify MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER.
"""

MEM_COMMIT: int = 0x00001000
"""
Allocates memory charges (from the overall size of memory and the paging files on disk) for the specified reserved 
memory pages. The function also guarantees that when the caller later initially accesses the memory, the contents will 
be zero. Actual physical pages are not allocated unless/until the virtual addresses are actually accessed.
To reserve and commit pages in one step, call VirtualAlloc with MEM_COMMIT | MEM_RESERVE.
"""

MEM_RESERVE: int = 0x00002000
"""
Reserves a range of the process's virtual address space without allocating any actual physical storage in memory or in 
the paging file on disk. You can commit reserved pages in subsequent calls to the VirtualAlloc function. To reserve and 
commit pages in one step, call VirtualAlloc with MEM_COMMIT | MEM_RESERVE.
"""

MEM_DECOMMIT: int = 0x00004000
"""
Decommits the specified region of committed pages. After the operation, the pages are in the reserved state.
The function does not fail if you attempt to decommit an uncommitted page. This means that you can decommit a range of 
pages without first determining the current commitment state.
"""

MEM_RELEASE: int = 0x00008000
"""
Releases the specified region of pages, or placeholder (for a placeholder, the address space is released and available 
for other allocations). After this operation, the pages are in the free state.
If you specify this value, dwSize must be 0 (zero), and lpAddress must point to the base address returned by the 
VirtualAlloc function when the region is reserved. The function fails if either of these conditions is not met.
"""

MEM_RESET: int = 0x00008000
"""
Indicates that data in the memory range specified by lpAddress and dwSize is no longer of interest. The pages should not
 be read from or written to the paging file. However, the memory block will be used again later, so it should not be 
 decommitted. This value cannot be used with any other value.
Using this value does not guarantee that the range operated on with MEM_RESET will contain zeros. If you want the range 
to contain zeros, decommit the memory and then recommit it.
"""

MEM_TOP_DOWN: int = 0x00100000
"""
Allocates memory at the highest possible address. This can be slower than regular allocations, especially when there are
 many allocations.
"""

MEM_WRITE_WATCH: int = 0x00200000
"""
Causes the system to track pages that are written to in the allocated region. If you specify this value, you must also 
specify MEM_RESERVE.
To retrieve the addresses of the pages that have been written to since the region was allocated or the write-tracking 
state was reset, call the GetWriteWatch function. To reset the write-tracking state, call GetWriteWatch or 
ResetWriteWatch. The write-tracking feature remains enabled for the memory region until the region is freed.
"""

MEM_PHYSICAL: int = 0x00400000
"""
Reserves an address range that can be used to map Address Windowing Extensions (AWE) pages.
This value must be used with MEM_RESERVE and no other values.
"""

MEM_RESET_UNDO: int = 0x01000000
"""
MEM_RESET_UNDO should only be called on an address range to which MEM_RESET was successfully applied earlier. It 
indicates that the data in the specified memory range specified by lpAddress and dwSize is of interest to the caller and
 attempts to reverse the effects of MEM_RESET. If the function succeeds, that means all data in the specified address 
 range is intact. If the function fails, at least some of the data in the address range has been replaced with zeroes.
This value cannot be used with any other value. If MEM_RESET_UNDO is called on an address range which was not MEM_RESET 
earlier, the behavior is undefined. When you specify MEM_RESET, the VirtualAlloc function ignores the value of 
flProtect. However, you must still set flProtect to a valid protection value, such as PAGE_NOACCESS.

Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  
The MEM_RESET_UNDO flag is not supported until Windows 8 and Windows Server 2012.
"""

MEM_LARGE_PAGES: int = 0x20000000
"""
Allocates memory using large page support.
The size and alignment must be a multiple of the large-page minimum. To obtain this value, use the GetLargePageMinimum 
function. If you specify this value, you must also specify MEM_RESERVE and MEM_COMMIT.
"""


TH32CS_SNAPHEAPLIST: int = 0x00000001
"""
Includes all heaps of the process specified in th32ProcessID in the snapshot. To enumerate the heaps, see Heap32ListFirst.
"""

TH32CS_SNAPPROCESS: int = 0x00000002
"""
Includes all processes in the system in the snapshot. To enumerate the processes, see Process32First.
"""

TH32CS_SNAPTHREAD: int = 0x00000004
"""
Includes all threads in the system in the snapshot. To enumerate the threads, see Thread32First.
To identify the threads that belong to a specific process, compare its process identifier to the th32OwnerProcessID 
member of the THREADENTRY32 structure when enumerating the threads.
"""

TH32CS_SNAPMODULE: int = 0x00000008
"""
Includes all modules of the process specified in th32ProcessID in the snapshot. To enumerate the modules, see 
Module32First. If the function fails with ERROR_BAD_LENGTH, retry the function until it succeeds.

64-bit Windows: 
Using this flag in a 32-bit process includes the 32-bit modules of the process specified in th32ProcessID, while using 
it in a 64-bit process includes the 64-bit modules. To include the 32-bit modules of the process specified in 
th32ProcessID from a 64-bit process, use the TH32CS_SNAPMODULE32 flag.
"""

TH32CS_SNAPMODULE32: int = 0x00000010
"""
Includes all 32-bit modules of the process specified in th32ProcessID in the snapshot when called from a 64-bit process.
This flag can be combined with TH32CS_SNAPMODULE or TH32CS_SNAPALL. If the function fails with ERROR_BAD_LENGTH, retry 
the function until it succeeds.
"""

TH32CS_SNAPALL: int = 0x000000FF
"""
Includes all processes and threads in the system, plus the heaps and modules of the process specified in th32ProcessID.
Equivalent to specifying the TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS, and TH32CS_SNAPTHREAD values
combined using an OR operation ('|').
"""

TH32CS_INHERIT: int = 0x80000000
"""
Indicates that the snapshot handle is to be inheritable.
"""


FILE_MAP_COPY: int = 0x00000001
"""
A copy-on-write view of the file is mapped. The file mapping object must have been created with PAGE_READONLY, 
PAGE_READ_EXECUTE, PAGE_WRITECOPY, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE, or PAGE_EXECUTE_READWRITE protection.
When a process writes to a copy-on-write page, the system copies the original page to a new page that is private to the 
process. The new page is backed by the paging file. The protection of the new page changes from copy-on-write to 
read/write.

When copy-on-write access is specified, the system and process commit charge taken is for the entire view because the 
calling process can potentially write to every page in the view, making all pages private. The contents of the new page 
are never written back to the original file and are lost when the view is unmapped.
"""

FILE_MAP_WRITE: int = 0x00000002
"""
A read/write view of the file is mapped. The file mapping object must have been created with PAGE_READWRITE or 
PAGE_EXECUTE_READWRITE protection. When used with MapViewOfFile, (FILE_MAP_WRITE | FILE_MAP_READ) and 
FILE_MAP_ALL_ACCESS are equivalent to FILE_MAP_WRITE.
"""

FILE_MAP_READ: int = 0x00000004
"""
A read-only view of the file is mapped. An attempt to write to the file view results in an access violation.
The file mapping object must have been created with PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, or 
PAGE_EXECUTE_READWRITE protection.
"""

FILE_MAP_EXECUTE: int = 0x00000020
"""
An executable view of the file is mapped (mapped memory can be run as code). The file mapping object must have been 
created with PAGE_EXECUTE_READ, PAGE_EXECUTE_WRITECOPY, or PAGE_EXECUTE_READWRITE protection.
Windows Server 2003 and Windows XP:  This value is available starting with Windows XP with SP2 and Windows Server 2003 
with SP1.
"""

FILE_MAP_ALL_ACCESS: int = 0x000F001F
"""
A read/write view of the file is mapped. The file mapping object must have been created with PAGE_READWRITE or 
PAGE_EXECUTE_READWRITE protection. When used with the MapViewOfFile function, FILE_MAP_ALL_ACCESS is equivalent to 
FILE_MAP_WRITE.
"""


# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
SECTION_INHERIT_VIEW_SHARE: int = 1
"""
The view will be mapped into any child processes that are created in the future.
"""

# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
SECTION_INHERIT_VIEW_UNMAP: int = 2
"""
The view will not be mapped into child processes.
Drivers should typically specify ViewUnmap for this parameter.
"""


DUPLICATE_CLOSE_SOURCE: int = 0x00000001
"""
Closes the source handle. This occurs regardless of any error status returned.
"""

DUPLICATE_SAME_ACCESS: int = 0x00000002
"""
Ignores the dwDesiredAccess parameter. The duplicate handle has the same access as the source handle.
"""


STD_INPUT_HANDLE: int = -10
"""
The standard input device. Initially, this is the console input buffer, CONIN$.
"""

STD_OUTPUT_HANDLE: int = -11
"""
The standard output device. Initially, this is the active console screen buffer, CONOUT$.
"""

STD_ERROR_HANDLE: int = -12
"""
The standard error device. Initially, this is the active console screen buffer, CONOUT$.
"""



THREAD_TERMINATE: int = 0x0001
"""
Required to terminate a thread using TerminateThread.
"""

THREAD_SUSPEND_RESUME: int = 0x0002
"""
Required to resume a thread
"""

THREAD_GET_CONTEXT: int = 0x0008
"""
Required to read the context of a thread using GetThreadContext.
"""

THREAD_SET_CONTEXT: int = 0x0010
"""
Required to write the context of a thread using SetThreadContext.
"""

THREAD_SET_INFORMATION: int = 0x0020
"""
Required to set certain information in the thread object.
"""

THREAD_QUERY_INFORMATION: int = 0x0040
"""
Required to read certain information from the thread object, such as the exit code (see GetExitCodeThread).
"""

THREAD_SET_THREAD_TOKEN: int = 0x0080
"""
Required to set the impersonation token for a thread using SetThreadToken.
"""

THREAD_IMPERSONATE: int = 0x0100
"""
Required to use a thread's security information directly without calling it by using a communication mechanism that 
provides impersonation services.
"""

THREAD_DIRECT_IMPERSONATION: int = 0x0200
"""
Required for a server thread that impersonates a client.
"""

THREAD_SET_LIMITED_INFORMATION: int = 0x0400
"""
Required to set certain information in the thread object. A handle that has the THREAD_SET_INFORMATION access right is 
automatically granted THREAD_SET_LIMITED_INFORMATION.
"""

THREAD_QUERY_LIMITED_INFORMATION: int = 0x0800
"""
Required to read certain information from the thread objects (see GetProcessIdOfThread). A handle that has the
THREAD_QUERY_INFORMATION access right is automatically granted THREAD_QUERY_LIMITED_INFORMATION.
"""


THREAD_ALL_ACCESS: int = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF
"""
All possible access rights for a thread object.
"""

WT_EXECUTEDEFAULT: int = 0x0
"""
By default, the callback function is queued to a non-I/O worker thread.
"""

WT_EXECUTEINWAITTHREAD: int = 0x4
"""
The callback function is invoked by the wait thread itself. This flag should be used only for short tasks or it could 
affect other wait operations.

Deadlocks can occur if some other thread acquires an exclusive lock and calls the UnregisterWait or UnregisterWaitEx 
function while the callback function is trying to acquire the same lock.
"""

WT_EXECUTEONLYONCE: int = 0x8
"""
The thread will no longer wait on the handle after the callback function has been called once. Otherwise, the timer is 
reset every time the wait operation completes until the wait operation is canceled.
"""

WT_EXECUTELONGFUNCTION: int = 0x10
"""
The callback function can perform a long wait. This flag helps the system to decide if it should create a new thread.
"""

WT_EXECUTEINPERSISTENTTHREAD: int = 0x80
"""
The callback function is queued to a thread that never terminates. It does not guarantee that the same thread is used 
each time. This flag should be used only for short tasks or it could affect other wait operations.
This flag must be set if the thread calls functions that use APCs.

Note that currently no worker thread is truly persistent, although no worker thread will terminate if there are any 
pending I/O requests.
"""

WT_TRANSFER_IMPERSONATION: int = 0x100
"""
Callback functions will use the current access token, whether it is a process or impersonation token. If this flag is 
not specified, callback functions execute only with the process token.
Windows XP:  This flag is not supported until Windows XP with SP2 and Windows Server 2003.
"""
