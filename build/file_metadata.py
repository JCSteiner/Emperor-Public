import subprocess

# imports for dllproxying
import pefile
import sys
import os.path

def get_strings(file = 'C:\\Windows\\Explorer.exe', n=12, build_dir = "."):

    strings = subprocess.run(f"{build_dir}\\strings.exe /accepteula /n {str(n)} file", capture_output=True)
    print()

    # decodes standard output so that we can get the strings as a list
    string_list = strings.stdout.decode('utf-8').split('\r\n')

    # final dictionary list
    final_list = []

    # loops through each string, skips the first few lines for OPSEC and getting rid of the
    # sysinternals output
    for s in string_list[6:]:

        # makes sure to escape backslashes
        new_s = s.replace('\\', '\\\\')
        # replaces quotes as well
        newer_s = new_s.replace('"', '')

        # we need each string to:
        # 1. not be empty
        # 2. be unique
        # 3. not append words after we reach 256
        # 4. not have weird characters that will break our c code
        if len(newer_s) > 0 and newer_s not in final_list and newer_s.isalnum():
            final_list.append(newer_s)

        if len(final_list) >= 256:
            break

    # if we don't have enough unique words
    if len(final_list) < 256:

        # open our penguin themed list to bridge the gap
        infile = open("penguin-dictionary.txt")
        for line in infile:
            if line.strip() not in final_list:
                final_list.append(line.strip())

            if len(final_list) >= 256:
                break

    # writes our output to a file
    outfile = open(f"{build_dir}\\dictionary.txt", "w")
    for line in final_list:
        outfile.write(line + "\n")
    outfile.close()


def get_resource(file = 'c:\\windows\\explorer.exe', build_dir = "."):

    resource = subprocess.run('exiftool.exe ' + str(file), capture_output=True)

    res_dict = dict()
    res_list = resource.stdout.decode('utf-8').split('\r\n')
    for res in res_list:
        res2 = res.split(':')
        if len(res2) == 2:
            res_dict[res2[0].strip(' ')] = res2[1].strip(' ').replace('\xA9', '\\xA9').replace('\xAE', '\\xAE')

    outfile = open(f'{build_dir}\\..\\src-main\\resource.rc', 'w')

    outfile.write('#include "winver.h"\n\n')
    outfile.write('#define IDI_ICON1                       101\n\n')
    outfile.write('/////////////////////////////////////////////////////////////////////////////\n')
    outfile.write('//\n')
    outfile.write('// Version\n')
    outfile.write('//\n\n')
    outfile.write(f'#define VER_FILEVERSION             {res_dict['File Version Number'].replace('.', ',')}\n')
    outfile.write(f'#define VER_FILEVERSION_STR         "{res_dict['File Version Number'].replace('.', ',')}\\0"\n\n')
    outfile.write(f'#define VER_PRODUCTVERSION          {res_dict['Product Version Number'].replace('.', ',')}\n')
    outfile.write(f'#define VER_PRODUCTVERSION_STR      "{res_dict['Product Version Number'].replace('.', ',')}\\0"\n\n')
    outfile.write('VS_VERSION_INFO VERSIONINFO\n')
    outfile.write('FILEVERSION     VER_FILEVERSION\n')
    outfile.write('PRODUCTVERSION  VER_PRODUCTVERSION\n')
    outfile.write('FILEFLAGSMASK   VS_FFI_FILEFLAGSMASK\n')
    outfile.write('FILEOS          VOS__WINDOWS32\n')
    outfile.write('FILETYPE        VFT_APP\n')
    outfile.write('FILESUBTYPE     VFT2_UNKNOWN\n')
    outfile.write('BEGIN\n')
    outfile.write('    BLOCK "StringFileInfo"\n')
    outfile.write('    BEGIN\n')
    outfile.write('        BLOCK "040904B0"\n')
    outfile.write('        BEGIN\n')
    outfile.write(f'            VALUE "CompanyName", "{res_dict['Company Name']}"\n')
    outfile.write(f'            VALUE "FileDescription", "{res_dict['File Description']}"\n')
    outfile.write(f'            VALUE "FileVersion", "{res_dict['File Version']}"\n')
    outfile.write(f'            VALUE "InternalName", "{res_dict['Internal Name']}"\n')
    outfile.write(f'            VALUE "LegalCopyright", "{res_dict['Legal Copyright']}"\n')
    outfile.write(f'            VALUE "OriginalFilename", "{res_dict['Original File Name']}"\n')
    outfile.write(f'            VALUE "ProductName", "{res_dict['Product Name']}"\n')
    outfile.write(f'            VALUE "ProductVersion", "{res_dict['Product Version']}"\n')
    outfile.write('        END\n')
    outfile.write('    END\n')
    outfile.write('    BLOCK "VarFileInfo"\n')
    outfile.write('    BEGIN\n')
    outfile.write('        VALUE "Translation", 0x409, 1266\n')
    outfile.write('    END\n')
    outfile.write('END\n\n')
    outfile.write('/////////////////////////////////////////////////////////////////////////////\n')
    outfile.write('//\n')
    outfile.write('// Icon\n')
    outfile.write('//\n\n')
    outfile.write('// Icon with lowest ID value placed first to ensure application icon\n')
    outfile.write('// remains consistent on all systems.\n')
    outfile.write('IDI_ICON1               ICON                    "icon.ico"')
    outfile.close()

# slight modification from what is seen in the github here:
# https://github.com/tothi/dll-hijack-by-proxying/tree/master
def dll_proxy(file_name, dll_export, outfile_path):

    # uses the pefile library to parse the dll
    dll = pefile.PE(file_name)
    dll_basename = os.path.splitext(file_name)[0]

    # writes our exports to the dll first and foremost
    outfile = open(outfile_path, "w")
    outfile.write("EXPORTS\n")
    outfile.write("DllMain\n")
    if dll_export:
        outfile.write(dll_export+"\n")

    # loops through each export we're parsing in the dll and formats them to be in our definition file
    for export in dll.DIRECTORY_ENTRY_EXPORT.symbols:
        if export.name:
            outfile.write(f'{export.name.decode()}={dll_basename}.{export.name.decode()} @{export.ordinal}\n')

    outfile.close()            
    