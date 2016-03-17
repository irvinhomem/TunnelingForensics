#!/usr/bin/env python
# Hack.lu 2010 CTF - Challenge #9 "Bottle"
# Extract iodine DNS tunnel data
# -- StalkR
# Modified for Python3 --> irvinhomem
# Using inbuilt zlib library
from scapy.all import *
from subprocess import Popen,PIPE
import zlib as zl

input, output = "bottle.cap", "extracted.cap"
topdomain = b".pirate.sea."
upstream_encoding = 128
# and no downstream encoding (type NULL)

# see encoder.c
def encoder(base,encode="",decode=""): # base=[32,64,128]
  p = Popen(["./encoder", str(base), "e" if len(encode)>0 else "d"], stdin=PIPE, stdout=PIPE)
  p.stdin.write(encode if len(encode)>0 else decode)
  return p.communicate()[0]

# # see uncompress.c
# def uncompress(s):
#   p = Popen(["./uncompress"], stdin=PIPE, stdout=PIPE)
#   p.stdin.write(s)
#   if p.wait() == 0:
#     return p.communicate()[0]
#   else:
#     return False

def b32_8to5(a):
  return "abcdefghijklmnopqrstuvwxyz012345".find(chr(a).lower())

def up_header(p):
  return {
    "userid": int(chr(p[0]), 16),
    "up_seq": (b32_8to5(p[1]) >> 2) & 7,
    "up_frag": ((b32_8to5(p[1]) & 3) << 2) | ((b32_8to5(p[2]) >> 3) & 3),
    "dn_seq": (b32_8to5(p[2]) & 7),
    "dn_frag": b32_8to5(p[3]) >> 1,
    "lastfrag": b32_8to5(p[3]) & 1
  }

def dn_header(p):
  return {
    "compress": ord(chr(p[0])) >> 7,
    "up_seq": (ord(chr(p[0])) >> 4) & 7,
    "up_frag": ord(chr(p[0])) & 15,
    "dn_seq": (ord(chr(p[1])) >> 1) & 15,
    "dn_frag": (ord(chr(p[1])) >> 5) & 7,
    "lastfrag": ord(chr(p[1])) & 1,
  }

# Extract packets from DNS tunnel
# Note: handles fragmentation, but not packet reordering (sequence numbers)
p = rdpcap(input)
dn_pkt, up_pkt = b'', b''
datasent = False
E = []
for i in range(len(p)):
  if not p[i].haslayer(DNS):
    continue
  if DNSQR in p[i]:
    if DNSRR in p[i] and len(p[i][DNSRR].rdata)>0: # downstream/server
      d = p[i][DNSRR].rdata
      if datasent: # real data and no longer codec/fragment checks
        dn_pkt += d[2:]
        if dn_header(d)['lastfrag'] and len(dn_pkt)>0:
          u = zl.decompress(dn_pkt)
          if not u:
            raise Exception("Error dn_pkt %i: %r" % (i, dn_pkt))
          E += [IP(u[4:])]
          dn_pkt = b''
    else: # upstream/client
      d = p[i][DNSQR].qname
      if str(chr(d[0])).lower() in "0123456789abcdef":
        datasent = True
        # print("d type: ", type(d))
        # print("Up pkt type: ", type(up_pkt))
        # pkt_bt_str = d[5:-len(topdomain)].replace(b'.', b'')
        # print("Pkt_byte_str type: ", type(pkt_bt_str))
        up_pkt += d[5:-len(topdomain)].replace(b'.', b'')
        #up_pkt.join(d[5:-len(topdomain)].replace(b'.', b''))
        if up_header(d)['lastfrag'] and len(up_pkt)>0:
          u = zl.decompress(encoder(upstream_encoding, decode=up_pkt))
          if not u:
            raise Exception("Error up_pkt %i: %r" % (i, up_pkt))
          E += [IP(u[4:])]
          up_pkt = b''

wrpcap(output, E)
print("Successfully extracted %i packets into %s" % (len(E), output))