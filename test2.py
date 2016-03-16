
from subprocess import Popen,PIPE
from struct import *
import binascii
import codecs

def encoder(base, encode="", decode=""): # base=[32,64,128]
    p = Popen(["./encoder", str(base), "e" if len(encode)>0 else "d"], stdin=PIPE, stdout=PIPE)

    p.stdin.write(bytearray(encode,'utf-') if len(encode)>0 else bytearray(decode,'utf-8'))
    #p.stdin.write(encode if len(encode)>0 else decode)

    return p.communicate()[0]

print("0x%08x" % unpack(">I", encoder(32, decode="aaaakardli")[:4]))
#"0x%08x" % unpack(">I", encoder(32, decode=b"aaaakardli")[:4])

#encoder(32,decode="aegpumiplhhpz12ynd1efljwlkjcgwya")[1:17].encode("hex")
#print(str(encoder(32,decode="aegpumiplhhpz12ynd1efljwlkjcgwya")[1:17]))
#print(codecs.encode(encoder(32,decode="aegpumiplhhpz12ynd1efljwlkjcgwya")[1:17], 'hex_codec'))
print(binascii.hexlify(encoder(32, decode="aegpumiplhhpz12ynd1efljwlkjcgwya")[1:17]))
#print(binascii.hexlify(encoder(32, decode="aegpumiplhhpz12ynd1efljwlkjcgwya")))