from scapy.all import *
from subprocess import Popen,PIPE
import binascii as b2a
import zlib as zl

def encoder(base, encode="", decode=""): # base=[32,64,128]
    p = Popen(["./encoder", str(base), "e" if len(encode)>0 else "d"], stdin=PIPE, stdout=PIPE)

    p.stdin.write(bytearray(encode,'utf-') if len(encode)>0 else bytearray(decode,'utf-8'))
    #p.stdin.write(encode if len(encode)>0 else decode)

    return p.communicate()[0]

def uncompress(s):
    print("In uncompress:", s)
    p = Popen(["./uncompress"], stdin=PIPE, stdout=PIPE)
    p.stdin.write(s)
    print("Written to stdin ...")
    print("Process ID: ", p.pid)
    #print("p.wait val: ", str(p.wait()))

    # try:
    #     return p.communicate()[0]

    # if p.wait() == 0:
    #     return p.communicate()[0]
    # else:
    #     return False

pktcap = rdpcap('bottle.cap')
#pkt_bytearray = pktcap[47][DNSQR].qname
pkt_bytearray = pktcap[46][DNSQR].qname
print("Type : ", type(pkt_bytearray))
#pkt_cont = str(b2a.hexlify(pkt_bytearray).decode('utf-8'))
#pkt_cont = b2a.hexlify(pkt_bytearray).decode()
#pkt_cont = bytes(pkt_bytearray).decode()
pkt_cont = str(bytes(pkt_bytearray))

print("packet content: ", pkt_cont)
# skip header, remove top domain and undotify
d = pkt_cont[5:-len(".pirate.sea.")].replace(".","")
print("Only encoded data: ", d)
decoded_output = encoder(128, decode=d)
#print("Decoded output: ", decoded_output)

my_bytes = b'\x00\x00\x08\x00E\x00\x00<\x01\x12@\x00@\x06\xe9~\n\x14\x1e\x03' \
           b'\n\x14\x1e\x01\xdb\x9c\x06\xb8\\s\xed+\x00\x00\x00\x00\xa0\x02\x11' \
           b'\x08\xd0\r\x00\x00\x02\x04\x04B\x04\x02\x08\n\x00\x05\xec9\x00\x00' \
           b'\x00\x00\x01\x03\x03\x05'
compressed = zl.compress(my_bytes)
print("Compressed bytes: ", compressed)
#u = uncompress(decoded_output)
#u = zl.decompress(decoded_output)

#print("Bytes: ", u)