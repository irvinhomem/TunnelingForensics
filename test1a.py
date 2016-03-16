from scapy.all import *

p = rdpcap('bottle.cap')
print('Type p : ', type(p))
print('Length p : ', len(p))
pcapLen = len(p)

for i in range(pcapLen):
    if not p[i].haslayer(DNS):
        continue
    if DNSQR in p[i]:
        if DNSRR in p[i] and len(p[i][DNSRR].rdata)>0: # downstream/server
            print("S[%i]: %r" % (i,p[i][DNSRR].rdata))
        else: # upstream/client
            print("C[%i]: %r" % (i,p[i][DNSQR].qname))



# pktcap = rdpcap('bottle.cap')
# print('Type p : ', type(pktcap))
# for pkt in pktcap:
#     if not pkt[i].haslayer(DNS):
#         continue
#     if DNSQR in pkt[i]:
#         if DNSRR in pkt[i] and len(pkt[i][DNSRR].rdata)>0: # downstream/server
#             print("S[%i]: %r" % (i,pkt[i][DNSRR].rdata))
#         else: # upstream/client
#             print("C[%i]: %r" % (i,pkt[i][DNSQR].qname))