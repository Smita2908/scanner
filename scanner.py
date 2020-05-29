from scapy.all import *
from scapy_http import http


__version__ = "0.0.3"
interface = "en0"


def handle_arp_packet(packet):

    # Match ARP requests
    if packet[ARP].op == 1:  #ARP.who_has:
        print('New ARP Request')
        print(packet.summary())
        #print(ls(packet))
        print(packet[Ether].src, "has IP", packet[ARP].psrc)

    # Match ARP replies
    if packet[ARP].op == 2:  #ARP.is_at:
        print('New ARP Reply')
        print(packet.summary())
        #print(ls(packet))

    return


def handle_dns_packet(packet):
    #print(packet.summary())
    #print(ls(packet))
    try:
        if DNSQR in packet and packet.dport == 53:
            # queries
            print('[+] Detected DNS QR Message')
            print(packet.summary())
        elif DNSRR in packet and packet.sport == 53:
            # responses
            print('[+] Detected DNS RR Message ')
            for x in range(packet[DNS].ancount):
                print(packet[DNSRR][x].rdata)
    except:
        pass

    return


def get_url(packet):
    host = packet[http.HTTPRequest].Host or ""
    path = packet[http.HTTPRequest].Path or ""
    return host + path


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + str(url))
    #packet.show()
    #print(packet)
    #url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    #print(url)


def handle_packet(packet):
    ip = packet.getlayer(IP)
    tcp = packet.getlayer(TCP)

    print("%s:%d -> %s:%d" % (ip.src, tcp.sport, ip.dst, tcp.dport))
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + str(url))
    return


payload = "M-SEARCH * HTTP/1.1\r\n" \
"HOST:239.255.255.250:1900\r\n" \
"ST:upnp:rootdevice\r\n" \
"MAN: \"ssdp:discover\"\r\n" \
"MX:2\r\n\r\n"

ip = "192.168.1.1"
payload_service = "M-SEARCH * HTTP/1.1\r\nHost:%s:1900\r\nST: ssdp:all\r\nMan:\"ssdp:discover\"\r\n" % ip



def main(argv):
    print(argv)
    if (argv == 'arp'):
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"),timeout=2)
        ans.summary()
        #sniff(filter="arp", prn=handle_arp_packet, timeout =3)
    if (argv == 'dns'):
        sniff(filter="udp and port 53", prn=handle_dns_packet, timeout =100)
    if (argv == 'upnp'):
        send(IP(dst="239.255.255.250") / UDP(sport=65507, dport=1900) / payload)
        #sniff(filter="udp and port 1900", timeout=10,
        #    prn=lambda p: p["IP"].src + " " + str(p["UDP"].payload))
        #send(IP(dst=ip) / UDP(sport=65507, dport=1900) / payload_service)
        sniff(filter="udp and (port 1900 or 65507)", timeout=120, prn=lambda p: p["IP"].src + " " + str(p["UDP"].payload))
    if (argv == 'http'):
        #sniff(iface=interface, filter="tcp and port 80", prn=handle_packet)
        sniff(iface=interface,  store=False, prn=process_sniffed_packet)

    return

if __name__ == "__main__":
    main(sys.argv[1])
