// dllmain.cpp : Defines the entry point for the DLL application.
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
#include "Windows.h"
#include "..\src-common\start.h"
#include "..\src-common\syscalls.h"
#include "dllmain.h"

DWORD ThreadProc(LPVOID param) {
    start();
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        HANDLE hThread;
        Sw3NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), &ThreadProc, NULL, 0, 0, 0, 0, NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}