from subprocess import Popen,PIPE
import binascii as b2a
import zlib as zl

def encoder(base, encode="", decode=""): # base=[32,64,128]
    p = Popen(["./encoder", str(base), "e" if len(encode)>0 else "d"], stdin=PIPE, stdout=PIPE)

    #p.stdin.write(str(encode).encode() if len(encode)>0 else str(decode).encode())
    #p.stdin.write(bytearray(encode,'utf-16') if len(encode)>0 else bytearray(decode,'utf-16'))
    #p.stdin.write(bytearray(encode,'utf-8') if len(encode)>0 else bytearray(decode,'utf-8'))
    p.stdin.write(encode if len(encode)>0 else decode)

    return p.communicate()[0]

compr_bytes = b'1eaba82\xca2hb\xbe\xeeY\xd6wgi\xcf\xe2\xde4yp1\xccC\xc8I\xe1\
xc1y\xc6\xe3\xdd\xcdW\xf4\xe0fx\xf3VAacc\xf1aH\xe2\xdb\xeezmgln\xbe\xefXy.CUdn\
xc0\xfbXcIMZr\xcc\xe4caBz\xde\xd0\xce.pirate.sea.'

my_bytes = b'\x00\x00\x08\x00E\x00\x00<\x01\x12@\x00@\x06\xe9~\n\x14\x1e\x03' \
           b'\n\x14\x1e\x01\xdb\x9c\x06\xb8\\s\xed+\x00\x00\x00\x00\xa0\x02\x11' \
           b'\x08\xd0\r\x00\x00\x02\x04\x04B\x04\x02\x08\n\x00\x05\xec9\x00\x00' \
           b'\x00\x00\x01\x03\x03\x05'
compressed = zl.compress(my_bytes)
#print("Compressed bytes: ", compressed)
encoded_bytes = encoder(128, encode=compressed)

print("Encoded bytes: ", encoded_bytes)

unc_bytes2 = b'\x00\x00\x08\x00E\x00\x00<\x00\x00@\x00@\x06\xea\x90\n\x14\x1e\x01' \
         b'\n\x14\x1e\x03\x06\xb8\xdb\x9c\xfd\x82\x8b\x08\\s\xed,\xa0\x12\x10' \
         b'\xd8\x86b\x00\x00\x02\x04\x04B\x04\x02\x08\n\x00\x10\xc1-\x00\x05' \
         b'\xec9\x01\x03\x03\x06'

compr_byt2 = b'\x90!x\xdac`\xe0`pe`\xb0a`p`p`{5\x81KD\x8e\x11\x88\x99\xd9v\xdc' \
             b'\x9e\xf3\xb7\xa9\x9b#\xa6\xf8\xad\xce\x02!\x81\x1bmI\x0c\x0cL,,N,L\x1c\\\x0c' \
             b'\x02\x07u\x19X\xdfX223\xb3\x01\x00\xc7\xfc\x0eP'

p46_to_decode = b'82\xca2hb\xbe\xeeY\xd6wgi\xcf\xe2\xde4yp1\xccC\xc8I\xe1\xc1y\xc6\xe3\xdd\xcdW\xf4' \
      b'\xe0fx\xf3VAacc\xf1aH\xe2\xdb\xeezmgln\xbe\xefXyCUdn\xc0\xfbXcIMZr\xcc\xe4caBz\xde\xd0\xce'

print("Bytes to decode & decompress p[46] LEN: ", len(p46_to_decode))

decoded_p46 = encoder(128, decode=p46_to_decode)

print("DECODED bytes [46]: ", decoded_p46)

decompressed_p46 = zl.decompress(decoded_p46)
print("DECODED and decompressed bytes [46]: ", decompressed_p46)