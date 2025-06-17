// helper.cpp - contains helper functions that are bonuses and not critical
// to shellcode execution
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

#include "helper.h"
#include "Windows.h"

#ifdef DEBUG_CHECK
#include <atomic>

// debug checks for here
// https://anti-debug.checkpoint.com/techniques/interactive.html
// GenerateConsoleCtrlEvent()
// When a user presses Ctrl+C or Ctrl+Break and a console window is in the focus, Windows checks if there 
// is a handler for this event. All console processes have a default handler function that calls the kernel32!ExitProcess() 
// function. However, we can register a custom handler for these events which neglects the Ctrl+C or Ctrl+Break signals.
//
// However, if a console process is being debugged and CTRL + C signals have not been disabled, the system generates a 
// DBG_CONTROL_C exception.Usually this exception is intercepted by a debugger, but if we register an exception handler,
// we will be able to check whether DBG_CONTROL_C is raised.If we intercepted the DBG_CONTROL_C exception in our own exception
// handler, it may indicate that the process is being debugged.


bool g_bDebugged{ false };
std::atomic<bool> g_bCtlCCatched{ false };

static LONG WINAPI CtrlEventExeptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == DBG_CONTROL_C)
    {
        g_bDebugged = true;
        g_bCtlCCatched.store(true);
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

static BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
    switch (fdwCtrlType)
    {
    case CTRL_C_EVENT:
        g_bCtlCCatched.store(true);
        return TRUE;
    default:
        return FALSE;
    }
}

BOOL isDebugged()
{
    PVOID hVeh = nullptr;
    BOOL bCtrlHadnlerSet = FALSE;

    __try
    {
        hVeh = AddVectoredExceptionHandler(TRUE, CtrlEventExeptionHandler);
        if (!hVeh)
            __leave;

        bCtrlHadnlerSet = SetConsoleCtrlHandler(CtrlHandler, TRUE);
        if (!bCtrlHadnlerSet)
            __leave;

        GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
        while (!g_bCtlCCatched.load())
            ;
    }
    __finally
    {
        if (bCtrlHadnlerSet)
            SetConsoleCtrlHandler(CtrlHandler, FALSE);

        if (hVeh)
            RemoveVectoredExceptionHandler(hVeh);
    }

    return g_bDebugged;
}


#endif

#ifdef RUN_ONCE_MUTEX

// includes a decoder to decode our mutex
#include "decode.h"
#include <stdio.h>

// creates a mutex, and if it already exists, then quits
BOOL mutex_check(char mutex_name[])
{
    // attempts to create a mutex, this is named for our choice; if it errors, we know the program is already
    // running
    HANDLE mutex_handle = CreateMutexA(NULL, TRUE, mutex_name);
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        // closes our handle to the mutex greacefully
        CloseHandle(mutex_handle);

        // if we have DEUBG mode enabled
#ifdef VERBOSE
        printf("[+] Mutex exists and runonce is enabled. Quitting.");
#endif

        // returns that mutex is running
        return TRUE;
    }
    return FALSE;
}

#endif
