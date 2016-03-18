from scapy.all import *
import binascii as b2a

def b32_8to5(a):
    return "abcdefghijklmnopqrstuvwxyz012345".find(chr(a).lower())

def up_header(p):
    # print("Type p: ", type(p))
    # print("P UP hex vals: ", p)
    # print("P[0] int : ", hex(p[0]))
    # print("P[1] int : ", int(p[1]))
    return {
        "userid": int(chr(p[0]), 16),
        "up_seq": (b32_8to5(p[1]) >> 2) & 7,
        "up_frag": ((b32_8to5(p[1]) & 3) << 2) | ((b32_8to5(p[2]) >> 3) & 3),
        "dn_seq": (b32_8to5(p[2]) & 7),
        "dn_frag": b32_8to5(p[3]) >> 1,
        "lastfrag": b32_8to5(p[3]) & 1
    }

def dn_header(p):
    # print("P DOWN hex vals: ", p)
    # print("ord p[0]: ", ord(chr(p[0])))
    # print("ord p[1]: ", ord(chr(p[1])))
    return {
        "compress": ord(chr(p[0])) >> 7,
        "up_seq": (ord(chr(p[0])) >> 4) & 7,
        "up_frag": ord(chr(p[0])) & 15,
        "dn_seq": (ord(chr(p[1])) >> 1) & 15,
        "dn_frag": (ord(chr(p[1])) >> 5) & 7,
        "lastfrag": ord(chr(p[1])) & 1,
   }

#p = rdpcap('../scapy_tutorial/NewPcaps/TunnelCaps_2016/HTTP/amazon.com/amazon.com-2016-02-25-T190359-HTovDNS-incog.pcapng')
p = rdpcap('../scapy_tutorial/NewPcaps/TunnelCaps_2016/FTP/FTP-PlainTxT/FTovDNS-TextFile-dl-small.pcapng')
datasent = False
for i in range(0,20):
    if not p[i].haslayer(DNS):
        continue
    if DNSQR in p[i]:
        if DNSRR in p[i] and len(p[i][DNSRR].rdata)>0: # downstream/server
            d = p[i][DNSRR].rdata
            print("D[%i]: %r" % (i, str(d[:30])+(" [...]" if len(d)>30 else "")))
            hex_vals = str(b2a.hexlify(d[:30]))
            formatted_hex =':'.join(hex_vals[j:j+2] for j in range(0, len(hex_vals), 2))
            print("D[%i]: %r" % (i, formatted_hex))
            if datasent:
                print("       %r \n" % dn_header(d))
        else: # upstream/client
            d = p[i][DNSQR].qname
            print("U[%i]: %r" % (i, str(d[:30]) + (" [...]" if len(d)>30 else "")))
            hex_vals = str(b2a.hexlify(d[:30]))
            formatted_hex =':'.join(hex_vals[j:j+2] for j in range(0, len(hex_vals), 2))
            print("U[%i]: %r" % (i, formatted_hex))

            if str(chr(d[0])) in "0123456789abcdef":
                # print('IN <-------')
                print("       %r \n" % up_header(d))
                datasent = True
            else:
                datasent = False

