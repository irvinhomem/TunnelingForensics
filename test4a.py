from scapy.all import *
import binascii as b2a

def b32_8to5(a):
    return "abcdefghijklmnopqrstuvwxyz012345".find(chr(a).lower())

def up_header(p):
    print("Type p: ", type(p))
    print("P UP hex vals: ", p)
    print("P[0] int : ", hex(p[0]))
    print("P[1] int : ", int(p[1]))
    return {
        "userid": int(chr(p[0]), 16),
        "up_seq": (b32_8to5(p[1]) >> 2) & 7,
        "up_frag": ((b32_8to5(p[1]) & 3) << 2) | ((b32_8to5(p[2]) >> 3) & 3),
        "dn_seq": (b32_8to5(p[2]) & 7),
        "dn_frag": b32_8to5(p[3]) >> 1,
        "lastfrag": b32_8to5(p[3]) & 1
    }

def dn_header(p):
    print("P DOWN hex vals: ", p)
   #  print("ord p[0]: ", ord(p[0]))
   #  print("ord p[1]: ", ord(p[1]))
   #  return {
   #      "compress": ord(p[0]) >> 7,
   #      "up_seq": (ord(p[0]) >> 4) & 7,
   #      "up_frag": ord(p[0]) & 15,
   #      "dn_seq": (ord(p[1]) >> 1) & 15,
   #      "dn_frag": (ord(p[1]) >> 5) & 7,
   #      "lastfrag": ord(p[1]) & 1,
   # }

    print("ord p[0]: ", ord(chr(p[0])))
    print("ord p[1]: ", ord(chr(p[1])))
    return {
        "compress": ord(chr(p[0])) >> 7,
        "up_seq": (ord(chr(p[0])) >> 4) & 7,
        "up_frag": ord(chr(p[0])) & 15,
        "dn_seq": (ord(chr(p[1])) >> 1) & 15,
        "dn_frag": (ord(chr(p[1])) >> 5) & 7,
        "lastfrag": ord(chr(p[1])) & 1,
   }

p = rdpcap('bottle.cap')
datasent = False
for i in range(20,100):
    if not p[i].haslayer(DNS):
        continue
    if DNSQR in p[i]:
        if DNSRR in p[i] and len(p[i][DNSRR].rdata)>0: # downstream/server
            d = p[i][DNSRR].rdata
            #print("D[%i]: %r" % (i, str(d[:30])+(" [...]" if len(d)>30 else "")))
            hex_vals = str(b2a.hexlify(d[:30]))
            formatted_hex =':'.join(hex_vals[j:j+2] for j in range(0, len(hex_vals), 2))
            #print("D[%i]2: %r" % (i, b2a.hexlify(d[:30])))
            print("D[%i]3: %r" % (i, formatted_hex))
            if datasent:
                #print("       %r" % dn_header(str(b2a.hexlify(d))))
                print("       %r" % dn_header(d))
        else: # upstream/client
            d = p[i][DNSQR].qname
            #print("U[%i]: %r" % (i, str(d[:30]) + (" [...]" if len(d)>30 else "")))
            #print("U2[%i]: %r" % (i, b2a.hexlify(d[:30])))
            hex_vals = str(b2a.hexlify(d[:30]))
            formatted_hex =':'.join(hex_vals[j:j+2] for j in range(0, len(hex_vals), 2))
            print("U[%i]3: %r" % (i, formatted_hex))
            # print('d[0] ascii str', str(d[0]))
            # print('d[0] ascii chr', str(chr(d[0])))
            # print('Type: d[0]: ', type(d[0]))
            # #print('d[0] hex val str', b2a.hexlify(d[:1]))
            # #print('d[0] hex val str', bytes(d[:1]).decode('utf-8'))
            # print('d[0] hex val str', bytes(b2a.hexlify(d[:1])).decode('utf-8'))
            # decoded_str = bytes(b2a.hexlify(d[:1])).decode('utf-8')
            # print('decoded str', decoded_str)
            #if d[0].lower() in "0123456789abcdef":
            #if decoded_str.lower() in "0123456789abcdef":
            if str(chr(d[0])) in "0123456789abcdef":
                # print('IN <-------')
                print("       %r" % up_header(d))
                #print("       %r" % up_header(bytes(b2a.hexlify(d)).decode('utf-8')))
                #print("       %r" % up_header(chr(d)))
                #print("       %r" % up_header((bytearray((b2a.hexlify(d))).decode('utf-8'))))
                #print("       %r" % up_header(str(d)))
                datasent = True
            else:
                datasent = False

