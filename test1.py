from scapy.all import *

p = rdpcap('bottle.cap')
for i in range(8):
    if not p[i].haslayer(DNS):
        continue
    if DNSQR in p[i]:
        if DNSRR in p[i] and len(p[i][DNSRR].rdata)>0: # downstream/server
            print("S[%i]: %r" % (i,p[i][DNSRR].rdata))
        else: # upstream/client
            print("C[%i]: %r" % (i,p[i][DNSQR].qname))