from hashlib import md5
from struct import pack,unpack
import binascii
#from operator import xor

def xor2(a,b):
    return "".join(chr(ord(a[i]) ^ ord(b[i%len(b)])) for i in range(len(a)))

def xor3(a,b):
    mystr =[]
    for i in range(len(a)):
        mystr.append(
            chr(
                ord(a[i]) ^ ord(b[i%len(b)])
            )
        )
    return ''.join(mystr)

def xor4(a,b):
    return bytearray(int(ord(a[i]) ^ ord(b[i%len(b)])) for i in range(len(a)))

def crack_password(hash, challenge, dic):
    for line in open(dic):
        padded_line = line.strip().ljust(32, '\x00')
        xor_result = xor4(padded_line, challenge)
        md5hash = md5(xor_result).hexdigest()
        if hash == md5hash:
            print("\o/ Password: %r" % line.strip())

crack_password("0cfa310f59cefcef9868f642ad365a92", "D\x03\xc5\xe9", "john.txt")

# # print(xor2('aa','aa'))
# # print(xor2('aba','aaa').encode('utf-8'))
# # print(md5(xor2('aba','aaa').encode('utf-8')).hexdigest())
# myPadPassline = 'swordfish'.ljust(32, '\x00')
# print("Passline ", type(myPadPassline))
# print("Passline ", myPadPassline)
# print(bytearray(myPadPassline, 'utf-8'))
# #chall = 'D\x03\xc5\xe9'
# chall = 'D\x03\xc5\xe9'
# #hexvals = bytes.fromhex(chall).decode('utf-8')
# #challenc = chall.encode('utf-8')
# print("Chall", type(chall))
# print(chall)
# #print('challenc', challenc)
# xor_res = xor2(myPadPassline, chall)
#
# print("xor_res", type(xor_res))
# print('xor_res = ', xor_res)
#
# #print('xor_res md5 direct= ', binascii.hexlify(xor_res))
# print('xor_res utf= ', binascii.hexlify(xor_res.encode('utf-8')))
# print('xor_res utf hex= ', xor_res.encode('utf-8'))
# print('xor_res utf md 5digest= ', md5(xor_res.encode('utf-8')).hexdigest() )
# #print('xor_res utf md 5digest= ', md5(xor_res.encode('utf-8')).hexdigest() )
# hashed = md5(bytearray(xor_res, 'utf-8')).digest()
# print("hashed: ", hashed)

#7t\xaa\x9b e\xac\x9a,\x03\xc5\xe9D\x03\xc5\xe9D\x03\xc5\xe9D\x03\xc5\xe9D\x03\xc5\xe9D\x03\xc5\xe9
#corr_xor = bytearray("7t\xaa\x9b e\xac\x9a,\x03\xc5\xe9D\x03\xc5\xe9D\x03\xc5\xe9D\x03\xc5\xe9D\x03\xc5\xe9D\x03\xc5\xe9\", 'utf-8')
#hash_val = md5(corr_xor).digest()
#print('hash val',hash_val)