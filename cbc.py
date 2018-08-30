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

#The function to apply PKCS #5 padding to a block
def pad(s):
    pad_len = BLOCK_SIZE - len(s) % BLOCK_SIZE
    if (pad_len == 0):
        pad_len = BLOCK_SIZE
    return (s + pad_len * chr(pad_len).encode('ascii')) # eg. chr(97) -> 'a'

# The function to remove padding
def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

# encrypt with AES CBC mode
def encrypt(key, raw):
    raw = pad(raw)
    cipher = AES.new(key, AES.MODE_ECB)
    blockNum = len(binascii.hexlify(raw))/ 2 / BLOCK_SIZE
    index = 0
    ciphertext = ""
    ciphertext_block = ""

    while index < blockNum:
        if index == 0:
            current_xor = int(binascii.hexlify(iv), 16) ^ int(binascii.hexlify(raw[0:16]), 16)
        else:
            current_xor = int(binascii.hexlify(ciphertext_block), 16) ^ int(binascii.hexlify(raw[0+16*index:16+16*index]), 16)
        # get rid of '0x' at the beginning and 'L' at the end when using hex()
        ciphertext_block = cipher.encrypt(binascii.unhexlify(hex(current_xor)[2:-1].zfill(32)))
        ciphertext += ciphertext_block
        index += 1
    return ciphertext

# decrypt with AES CBC mode
def decrypt(key, enc):
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

    return unpad(binascii.unhexlify(plaintext))

# a function to parse command-line arguments
def getopts(argv):
    opts = {}
    while argv:
        if argv[0][0] == '-':
            opts[argv[0]] = argv[1]
        argv = argv[1:]
    return opts

if __name__ == '__main__':
    # parse command-line arguments
    myargs = getopts(sys.argv)
    #print(myargs)
    if '-e' in myargs: # encrption with hexadecimal string as plaintext
        plaintext = binascii.unhexlify(myargs['-e'])
        ciphertext = encrypt(key, plaintext)
        print('Ciphertext:' + binascii.hexlify(ciphertext))
    elif '-d' in myargs: # decryption with hexadecimal string as ciphertext
        ciphertext = binascii.unhexlify(myargs['-d'])
        plaintext = decrypt(key, ciphertext)
        print('Plaintext:' + binascii.hexlify(plaintext))
    elif '-s' in myargs:
        # encrption with ascii string as plaintext, output hexadecimal ciphertext
        plaintext = binascii.a2b_qp(myargs['-s'])
        ciphertext = encrypt(key, plaintext)
        print('Ciphertext:' + binascii.hexlify(ciphertext))
    elif '-u' in myargs:
        # decryption with hexadecimal string as ciphertext, output ascii string
        ciphertext = binascii.unhexlify(myargs['-u'])
        plaintext = decrypt(key, ciphertext)
        print('Plaintext:' + binascii.b2a_qp(plaintext))
    else:
        print("python cbc.py -e 010203040506")
        print("python cbc.py -s 'this is cool'")
        print("python cbc.py -d 285c4c14c5036e48cb6196ce69c10cb2")
        print("python cbc.py -u f6d04509405c223a383ac5170b3e163b")
