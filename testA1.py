from scapy.all import *
import binascii as b2a

topdomain = b".barns.crabdance.com."
upstream_encoding = 128

def encoder(base,encode="",decode=""): # base=[32,64,128]
  p = Popen(["./encoder", str(base), "e" if len(encode)>0 else "d"], stdin=PIPE, stdout=PIPE)
  p.stdin.write(encode if len(encode)>0 else decode)
  return p.communicate()[0]

pktcap = rdpcap('../scapy_tutorial/NewPcaps/TunnelCaps_2016/HTTP/amazon.com/amazon.com-2016-02-25-T190359-HTovDNS-incog.pcapng')


# Test 01 - Checking whether the packets with DNS query names starting with 'p' have content
#Numbering from 0
p25 = pktcap[25]
if not p25.haslayer(DNS):
    print("Not DNS packet")
    #continue
else:
    if DNSQR in p25:
         qry_name = p25[DNSQR].qname
         print("Query Name:", qry_name)
         pkt_content = p25[DNSRR].rdata
         print("pkt content type:", type(pkt_content))
         print("pkt content len:", len(pkt_content))
         print("pkt content:", pkt_content)
         pkt_hexvals = b2a.hexlify(pkt_content)
         print("hex vals pkt content:", pkt_hexvals)
         print("pkt hexvals len:", len(pkt_hexvals))

         #wrpcap('extract.cap', pkt_content)

        #Seems to be a bug -> See IP version reported as 14
         ip_pkt = IP(pkt_content)
         ip_pkt.show()

         #ip_pkt[TCP].show()


# Filter only DNS packets that have content in DNS Query name


my_pkt = 'e0:c1:78:da:63:60:e0:60:70:65:60:c9:32:59:c0:c0:60:ca:b6:90:f9:86:d5:c9:75:5c:0c:0c:4c:8c:bb:1f:54:c5:65:' \
         'b9:b7:b5:34:ef:93:6f:10:60:0c:0d:db:c4:c0:c0:c8:c8:c1:d5:ed:b2:64:22:83:ea:94:57:86:dc:06:9c:6c:cc:a1:2c:' \
         '6c:c2:4c:a1:c1:86:62:06:22:20:0e:97:30:af:7b:6a:7e:48:51:69:71:89:82:67:5e:b2:9e:a1:b4:81:24:48:9c:59:58:' \
         '08:2e:ee:9e:93:9f:94:98:a3:e0:ec:68:20:27:ce:6b:68:6c:60:62:60:6a:08:84:a6:66:51:40:ae:99:a1:91:31:10:99:' \
         '5a:9a:5a:46:19:78:a2:da:21:6c:20:08:b1:83:cb:3d:3f:3f:3d:27:15:64:83:a1:aa:81:32:c4:02:19:b8:60:49:6a:51:' \
         '5e:6a:89:82:63:69:49:46:7e:51:66:49:a5:82:bb:91:41:13:a3:92:01:2f:1b:a7:56:9b:47:db:77:5e:46:46:46:56:06:' \
         'e6:26:46:7e:06:a0:38:17:53:13:23:23:c3:1c:2d:96:f2:98:1b:01:13:ad:d8:16:37:3d:b8:11:e0:b1:a7:d3:fe:a3:64:' \
         '81:54:87:5b:dd:83:fe:a3:1f:3b:cf:29:be:8b:fa:97:c8:bb:dd:c8:a5:73:41:09:77:b0:7f:e8:92:73:4d:49:53:df:bd:' \
         '8e:8c:3f:f6:90:b5:41:e8:48:dc:14:fb:3d:d1:1e:16:5f:82:bf:ab:3c:fb:3d:f1:a5:e8:91:f3:5f:82:79:bf:78:fd:99:' \
         '1f:72:af:76:df:82:ec:fc:f6:03:17:02:e4:35:0c:98:1d:6e:71:14:07:e6:d4:ff:b7:b2:59:6e:ce:d6:b7:d7:5b:90:e5:' \
         '75:ad:ca:bd:67:3f:ff:18:16:fe:9e:72:35:e1:b3:9e:d7:7a:a7:4b:a7:5f:1d:c9:92:da:74:26:f8:ae:a8:77:b7:fc:09:' \
         'c9:44:f9:b3:73:57:d8:25:6b:b7:98:66:a6:b6:9c:90:3c:ea:a6:f4:23:78:ea:be:c7:0d:5e:02:c7:b4:de:ec:9a:ae:20:' \
         '78:dc:72:a6:00:cb:82:0f:89:55:53:55:7b:fc:82:4a:1f:6d:7b:cb:71:4a:e4:cf:39:a5:ac:cd:7e:e7:dd:98:a7:4f:67:' \
         'ae:3b:b0:f1:5e:f5:7a:57:e3:f3:bb:ec:0a:b7:df:fb:a2:aa:7a:88:d7:b4:73:ee:dc:df:7c:82:95:9d:72:e6:47:d7:f7:' \
         '15:65:32:31:33:32:30:2e:6e:7c:6e:d0:f8:c4:40:1e:18:a0:b2:ca:2c:12:06:62:0d:22:07:aa:66:64:f4:76:fe:5e:cd:' \
         '9a:c2:23:58:bb:aa:36:75:c7:a9:33:7e:06:b2:20:05:7c:2c:62:2c:22:5e:77:d9:c4:a4:f7:7c:cb:d8:5a:f6:b5:71:db:' \
         'ee:24:a9:5d:51:8d:fa:06:7c:20:69:7e:46:c6:ff:2c:2c:cc:4c:8c:6c:06:7a:6c:1c:da:6c:8c:ac:ac:ec:8c:8c:2c:4a:' \
         '06:0a:06:72:30:be:01:63:9b:50:46:49:49:81:95:be:7e:ba:5e:71:65:6e:72:8a:5e:72:7e:ae:81:10:48:bf:30:48:3f:' \
         '87:01:1b:90:62:62:64:30:30:05:89:c9:b3:e8:19:e8:18:68:2d:d0:58:a0:d6:a6:82:a2:31:09:a4:51:3f:b9:28:a7:58:' \
         '3f:bd:24:1d:9c:c0:f4:80:3c:03:71:90:36:05:16:01:03:3e:03:1e:36:2e:a0:ad:2c:8c:d7:2a:99:58:19:91:d3:02:37:' \
         '38:2d:30:32:ac:fa:b5:52:e1:6c:56:7a:f3:db:b8:2b:75:f7:64:8f:d4:3f:50:65:63:38:aa:f2:7b:e5:09:dd:dc:ba:7b:' \
         '73:9b:52:75:1a:93:4d:d2:ec:5e:06:1d:e2:d8:72:5a:ff:7b:fc:4c:ab:ac:39:01:55:ad:ac:3d:b5:17:b5:3c:5a:2e:73:' \
         'e6:d4:1c:3a:6b:3a:ff:73:d3:bb:a0:7b:19:f1:4f:18:ba:c4:15:a6:7d:d7:ec:9d:e5:7b:7a:c5:bd:b6:13:bc:f9:61:ed:' \
         'cc:b5:cc:f6:77:7e:55:d6:2a:4a:fe:3c:61:a5:1f:58:d6:73:dc:71:52:61:bf:ea:39:f3:1f:5e:3e:0c:ca:ef:8f:98:0a:' \
         'ac:7b:a0:dc:50:5c:e3:6b:a2:77:22:6f:c2:35:01:b9:99:2d:c5:52:05:9f:de:86:f2:bd:13:67:7b:95:fe:ce:e8:b5:ce:' \
         'dd:74:76:fb:6f:dd:87:0a:ee:45:33:3c:db:2d:7d:d9:4c:4a:29:27:67:83:a9:53:ce:04:4e:db:c9:2f:53:38:95:f8:5a:' \
         'd9:e6:1f:2a:56:bc:fc:2c:be:e1:49:6f:ab:92:55:31:f3:c6:84:be:75:19:8f:be:d8:4d:7f:9e:20:c4:99:61:76:cf:ea:' \
         'da:23:e7:a9:d1:e6:8d:93:1a:e5:77:f7:5e:5f:1b:94:22:16:3e:ed:66:9c:49:dd:09:d3:1b:0c:cc:8d:06:4d:cc:b5:06:' \
         '4d:4c:cf:16:00:e3:8d:89:89:59:68:f7:33:e4:80:62:65:65:30:f0:43:cd:92:02:e0:c8:06:66:49:76:d7:c2:d2:cc:b4:' \
         'c4:0a:43:5d:03:6d:90:08:b7:b0:0a:54:44:21:38:35:b9:b4:28:55:c1:39:b5:a8:24:33:0d:00:59:67:8d:91'