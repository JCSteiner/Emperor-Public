# delta_encoding.py. Original code by:

# James Campbell AKA soups
"""
This performs a delta decode which @JStith pointed me to by sending me the below blog post.

Blog Post https://redsiege.com/delta
"""

# basically, this encodes shellcode by storing not the shellcode, but the difference between bytes
# then to decode, you add them back together. If we overflow, we wrap back around to stay within
# the one byte range. This is intended as an unorthadox (and therefore less likely to be signatured)
# way to encode shellcode that does not expand the size of the shellcode

def delta_encode(origStr):
	lastVal = 0
	encStr = b''
	for i in range(len(origStr)):
		current = origStr[i]
		encStr += ((current-lastVal) & 0xff).to_bytes(1, 'big')
		lastVal = current
	return encStr

def delta_decode(encStr):
	lastVal = 0
	decStr = b''
	for i in range(len(encStr)):
		delta = encStr[i]
		decVal = (delta+lastVal)&0xff
		decStr+= decVal.to_bytes(1, 'big')
		lastVal = decVal
	return decStr


# additional formatting function authored by soups. formats delta_encoded processes so they can be written
# for use in a c/c++ program
def format_bytes(bytes, name):
        c_key = "unsigned char "+name+"[] = {\n\t"
        count = 0
        for byte in bytes:
            
            if count % 12==0  and count != 0:
                c_key += '\n\t'
            c_key += f"{'0x{:02x}'.format(byte)},"
            count+=1

        c_key = c_key[:-1] # Removes the trialing , at the end.
        
        c_key += '\n};'

        return c_key