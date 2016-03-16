from hashlib import md5
from struct import pack,unpack
import binascii
#from operator import xor
import hexdump

def xor2(a,b):
    return "".join(chr(ord(a[i]) ^ ord(b[i%len(b)])) for i in range(len(a)))

def xor3(a,b):
    mystr =[]
    for i in range(len(a)):
        b_index = i%len(b)
        a_Val = ord(a[i])
        b_Val = ord(b[b_index])
        a_char = chr(a_Val)
        b_char = chr(b_Val)

        xor_ab = a_Val ^ b_Val

        xor_char = chr(xor_ab)

        mystr.append(xor_char)

    return ''.join(mystr)

def crack_password(hash, challenge, dic):
    for line in open(dic):
        #if hash == md5(xor2(line.strip().ljust(32,'\x00'),challenge)).digest().encode('hex'):
        # if hash == binascii.hexlify(
        #         md5(
        #             (xor2(line.strip().ljust(32, '\x00'), challenge)).encode()
        #         ).digest()):

        padded_line = line.strip().ljust(32, '\x00')
        xor_result = xor3(padded_line, challenge)
        encoded_xor = (xor_result).encode('utf-8')
        md5hash = md5(encoded_xor).hexdigest()
        if hash == md5hash:
            print("\o/ Password: %r" % line.strip())

#crack_password("0cfa310f59cefcef9868f642ad365a92", "D\x03\xc5\xe9", "words.txt")

myPadPassline = 'swordfish'.ljust(32, '\x00')
print("Passline ", type(myPadPassline))
print("Passline ", myPadPassline)
print(bytearray(myPadPassline, 'utf-8'))
#chall = 'D\x03\xc5\xe9'
chall = 'D\x03\xc5\xe9'

xor_res = xor3(myPadPassline, chall)
print(":".join("{:02x}".format(ord(c)) for c in xor_res))
newStr = "".join("{:02x}".format(ord(c)) for c in xor_res)

#b_array = [ord(c) for c in xor_res]
b_array = bytearray(ord(c) for c in xor_res)
print('XOR RESULT', newStr)
print('XOR RESULT len', len(newStr))
print('XOR RESULT btye array len', len(b_array))
print('b_array', type(b_array))

#md5hash = md5(newStr.encode('utf-8')).hexdigest()
md5hash = md5(bytearray(newStr,'utf-8')).hexdigest()
print ('Md5 Hash', md5hash)

md5_hash = md5(b_array).hexdigest()
print ('THIS -->> Md5 Hash', md5_hash)  #<<<<<-------- This works. It's correct'

print("Hex dump: ", hexdump.dump(bytes(xor_res,'utf-8')).lower())

for character in xor_res:
    print(character, binascii.hexlify(character.encode('utf-8')))

print("xor_res", type(xor_res))
print('xor_res = ', xor_res)
print('HEXed', binascii.hexlify(bytes(xor_res,'utf-8')))
#7t\xaa\x9b e\xac\x9a,\x03\xc5\xe9D\x03\xc5\xe9D\x03\xc5\xe9D\x03\xc5\xe9D\x03\xc5\xe9D\x03\xc5\xe9
print('xor_res bytes = ', (xor_res).encode('utf-8'))
print('xor_res md5 = ', md5((xor_res).encode('utf-8')).hexdigest())
#print('xor_res md5 direct = ', md5(xor_res).hexdigest())
