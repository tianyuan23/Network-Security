# Import AES symmetric encryption cipher
from Crypto.Cipher import AES

# Immport class for hexadecimal string process
import binascii

# support command-line arguments
import sys


# define block size of AES encryption
BLOCK_SIZE = 16

# The 128-bit AES key
key = binascii.unhexlify('00112233445566778899aabbccddeeff')

# The IV (initial value)
iv = binascii.unhexlify('11111111111111110000000000000000')

def ispadded(key, enc):
    cipher = AES.new(key, AES.MODE_ECB)
    blockNum = len(binascii.hexlify(enc))/ 2 / BLOCK_SIZE
    index = 0
    plaintext = ""
    plaintext_block = ""

    while index < blockNum:
        current_xor = cipher.decrypt(enc[0+16*index:16+16*index])
        if index == 0:
            # get rid of '0x' at the beginning and 'L' at the end when using hex()
            plaintext_block = hex(int(binascii.hexlify(iv), 16) ^ int(binascii.hexlify(current_xor), 16))[2:-1].zfill(32)
        else:
            # get rid of '0x' at the beginning and 'L' at the end when using hex()
            plaintext_block = hex(int(binascii.hexlify(current_xor), 16) ^ int(binascii.hexlify(enc[0+16*(index-1):16+16*(index-1)]), 16))[2:-1].zfill(32)
        plaintext += plaintext_block
        index += 1

    paddingcorrect = "no"
    padding = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10']
    for i in range(len(padding)):
        if plaintext[-2*(i+1):] == padding[i]*(i+1):
            paddingcorrect = "yes"

    return paddingcorrect

if __name__ == '__main__':
    print ispadded(key, binascii.unhexlify(sys.argv[1]))
