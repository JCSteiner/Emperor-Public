// helper.h - function prototypes for bonuses that are extras and not
// critical to shellcode execution
// ___________
// \_   _____/ _____ ______   ___________  ___________ 
//  |    __)_ /     \\____ \_/ __ \_  __ \/  _ \_  __ \
//  |        \  Y Y  \  |_> >  ___/|  | \(  <_> )  | \/
// /_______  /__|_|  /   __/ \___  >__|   \____/|__|   
//         \/      \/|__|        \/                    

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
#pragma once
// include dependencies
#include "defs.h"
#include "Windows.h"


#ifdef DEBUG_CHECK
// anti debug techniques found from the repository below.
// https://anti-debug.checkpoint.com/techniques/interactive.html
// I've implemented the one that seemed the most OPSEC friendly, and worked the most reliably
// GenerateConsoleCtrlEvent()
// When a user presses Ctrl+C or Ctrl+Break and a console window is in the focus, Windows checks if there 
// is a handler for this event. All console processes have a default handler function that calls the kernel32!ExitProcess() 
// function. However, we can register a custom handler for these events which neglects the Ctrl+C or Ctrl+Break signals.
//
// However, if a console process is being debugged and CTRL + C signals have not been disabled, the system generates a 
// DBG_CONTROL_C exception.Usually this exception is intercepted by a debugger, but if we register an exception handler,
// we will be able to check whether DBG_CONTROL_C is raised.If we intercepted the DBG_CONTROL_C exception in our own exception
// handler, it may indicate that the process is being debugged.

// this will return true if either of the checks flag
BOOL isDebugged();
#endif

#ifdef RUN_ONCE_MUTEX
// this function will attempt to create a mutex, and if it cannot because it already exists, then it will return TRUE
BOOL mutex_check(char mutex_name[]);
#endif