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

#The function to apply PKCS #5 padding to a block
def pad(s):
    pad_len = BLOCK_SIZE - len(s) % BLOCK_SIZE
    if (pad_len == 0):
        pad_len = BLOCK_SIZE
    return (s + pad_len * chr(pad_len).encode('ascii')) # eg. chr(97) -> 'a'

# The function to remove padding
def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

# encrypt with AES ECB mode
def encrypt(key, raw):
    raw = pad(raw)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(raw)

# decrypt with AES ECB mode
def decrypt(key, enc):
    cipher = AES.new(key, AES.MODE_ECB)
    dec = cipher.decrypt(enc)
    return unpad(dec)

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
        print("python ecb.py -e 010203040506")
        print("python ecb.py -s 'this is cool'")
        print("python ecb.py -d d25a16fe349cded7f6a2f2446f6da1c2")
        print("python ecb.py -u 9b43953eeb6c3b7b7971a8bec1a90819")
