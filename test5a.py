from scapy.all import *
from subprocess import Popen,PIPE
import binascii as b2a
import zlib as zl
import codecs

def encoder(base, encode="", decode=""): # base=[32,64,128]
    p = Popen(["./encoder", str(base), "e" if len(encode)>0 else "d"], stdin=PIPE, stdout=PIPE)

    #p.stdin.write(str(encode).encode() if len(encode)>0 else str(decode).encode())
    #p.stdin.write(bytearray(encode,'utf-8') if len(encode)>0 else bytearray(decode,'utf-8'))
    #p.stdin.write(bytearray(encode,'unicode_escape') if len(encode)>0 else bytearray(decode,'unicode_escape'))
    p.stdin.write(encode if len(encode)>0 else decode)

    return p.communicate()[0]

def uncompress(s):
    print("In uncompress:", s)
    p = Popen(["./uncompress"], stdin=PIPE, stdout=PIPE)
    p.stdin.write(s)
    print("Written to stdin ...")
    print("Process ID: ", p.pid)
    #print("p.wait val: ", str(p.wait()))

    # try:
    #    return p.communicate()[0]

    # if p.wait() == 0:
    #     return p.communicate()[0]
    # else:
    #     return False

pktcap = rdpcap('bottle.cap')
#pkt_bytearray = pktcap[47][DNSQR].qname
pkt_bytearray = pktcap[46][DNSQR].qname
print("Type : ", type(pkt_bytearray))
print("Length : ", len(pkt_bytearray))
#pkt_cont = str(b2a.hexlify(pkt_bytearray).decode('utf-8'))
#pkt_cont = b2a.hexlify(pkt_bytearray).decode()
#pkt_cont = bytes(pkt_bytearray).decode()
pkt_cont = str(bytes(pkt_bytearray))

print("packet content: ", pkt_cont)
print("packet byte array: ", pkt_bytearray)
# skip header, remove top domain and undotify
#d = pkt_cont[5:-len(".pirate.sea.")].replace(".", "")
#d01 = str(bytes(pkt_bytearray[5:-len(".pirate.sea.")])).replace(".", "")
#d01 = str(pkt_bytearray[5:-len(".pirate.sea.")]).replace(".", "")
d01 = pkt_bytearray[5:-len(".pirate.sea.")]
#d01_undot = bytearray(str(d01).replace('.', ''), 'utf-8')
d01_undot = d01.replace(b'.', b'')
#d01_undot = d01 % format()

print("Encoded data len [d01 undot]: ", len(d01_undot))
#print("Only encoded data: ", d)
print("Encoded data len [d01]: ", len(d01))
#print("Encoded data len [d01] bytes: ", len(d01_bytes))
print("Only encoded data [d01] str: ", d01)

#decoded_output = encoder(128, decode=d)
decoded_output01 = encoder(128, decode=d01_undot)
print("Decoded output length: ", len(decoded_output01))
print("Decoded output: ", decoded_output01)
# hexed = b2a.hexlify(decoded_output01)
# print("Decoded output hex: ", b2a.hexlify(decoded_output01))
# print("Decoded output hex length: ", len(hexed))
#codecs.encode(d01, 'hex')


#u = uncompress(decoded_output)
#u = uncompress(decoded_output01)
#u = zl.decompress(decoded_output)
u = zl.decompress(decoded_output01)

print("Packet Bytes CORRECT: ", u)

ip_pkt = IP(u[4:])
ip_pkt.show() #from scapy API

######### Packet 47
pkt_bytes = pktcap[47][DNSRR].rdata
#pkt_cont47 = str(bytes(pkt_bytes))
print("packet BYTES [47]: ", pkt_bytes)
#print("packet content [47]: ", pkt_cont47)
print("d02 [47] Byte 1: ", chr(pkt_bytes[0]))
print("d02 [47] Byte 1: ", pkt_bytes[0])
print("d02 [47] Byte 1: ", hex(pkt_bytes[0]))
print("d02 [47] Byte 2: ", chr(pkt_bytes[1]))
print("d02 [47] Byte 2: ", pkt_bytes[1])
print("d02 [47] Byte 2: ", hex(pkt_bytes[1]))
print("d02 [47] Byte 3: ", chr(pkt_bytes[2]))
print("d02 [47] Byte 3: ", chr(pkt_bytes[2]))
print("d02 [47] Byte 3: ", pkt_bytes[2])
print("d02 [47] Byte 3: ", hex(pkt_bytes[2]))
d02 = pkt_bytes[2:]
#d2 = pkt_cont47[2:]
#print("d2 [47]: ", d2)
print("d02 [47]: ", d02)
print("d02 [47] Byte 1: ", chr(d02[0]))
print("d02 [47] Byte 1: ", d02[0])
print("d02 [47] Byte 1: ", hex(d02[0]))
print("d02 [47] Byte 2: ", chr(d02[1]))
print("d02 [47] Byte 2: ", d02[1])
print("d02 [47] Byte 2: ", hex(d02[1]))
print("d02 [47] Byte 3: ", chr(d02[2]))
print("d02 [47] Byte 3: ", d02[2])
print("d02 [47] Byte 3: ", hex(d02[2]))

print("packet bytes len", len(pkt_bytes))
print("d02 len", len(d02))

#d02_utf = bytearray(d02).decode('ascii')
# print("d02 utf:", d02_utf)

#decoded_output47 = encoder(128, decode=d02_utf)

decoded_output47 = encoder(128, decode=d02)
#
#u47 = uncompress(decoded_output47)
u47 = zl.decompress(decoded_output47)
#
#print("Uncompressed  p[47]: ", u47)



