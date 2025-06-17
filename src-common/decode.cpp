// decoder.cpp - defines the decoder wrapper and functions that do the actual decodin
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

#include "decode.h"
#include "defs.h"
#include <stdio.h>
#include <iostream>

#ifdef ENCODE_DICT
// our dictionary decoding function, takes in a pointer to our buffer, a pointer to our dictionary, and the size of our buffer
unsigned char* dictionary_decode(const char** pBuf, const char** pDict, size_t buf_size)
{
	// allocates memory for a new array (the decoded buffer) and sets the memory in it to 0
	unsigned char* arr = new unsigned char[buf_size];
	memset(arr, 0, buf_size);

	// for each byte in the buffer
	for (int i = 0; i < buf_size; i++)
	{
		// gets the encoded byte from the pointer
		const char* enc_byte = *(pBuf + i);

		// for each entry in the dictionary
		for (int j = 0; j <= 255; j++)
		{

			// if the encoded byte is the same as the entry in the dictionary
			if (strcmp(enc_byte, *(pDict + j)) == 0)
			{
				unsigned char temp = (unsigned char)j;

				// sets the decoded value to the index
				arr[i] = temp;
			}
		}
	
	}

	//returns the decoded buffer
	return arr;
}
#endif

#ifdef ENCODE_DELTA
// defines our function to delta decode our key
void delta_decode(unsigned char* enc_key, size_t length)
{
	// decodes by setting the current byte of the key equal to itself, plus the last byte
	// the "delta" comes from the greek letter which means the difference in math
	// using this allows us not to have our key in plaintext
	unsigned char last = 0;
	for (int i = 0; i < length; i++)
	{
		unsigned char delta = enc_key[i];
		enc_key[i] = delta + last;
		last = enc_key[i];
	}
}
#endif

// wrapper function for our decoder, this way the runner functions can call one decodin function,
// and the wrapper can decide which decoder to use based on definitions
unsigned char* decode(const char** pBuf, const char** pDict, size_t buf_size)
{
#ifdef ENCODE_DICT
    return dictionary_decode(pBuf, pDict, buf_size);
#endif

#ifdef ENCODE_DELTA

    // decodes our key
	delta_decode((unsigned char*)pBuf, buf_size);
	

	return (unsigned char*)pBuf;
#endif
}

