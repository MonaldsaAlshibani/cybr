from scapy.all import TCP, sniff, IP, UDP, ICMP, DNS, DNSQR
import logging

logging.basicConfig(
    filename='tcp.log',  
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

IFACE = None
BPF = "tcp or udp or icmp or port 53"

def on_puket(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        msg = f"TCP {src}:{sport} -> {dst}:{dport}"
        print(msg)
        logging.info(msg)

    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if DNS in pkt and DNSQR in pkt and pkt[DNS].qd:
            qname = pkt[DNS].qd.qname.decode(errors="ignore")
            msg = f"DNS  {src}:{sport} -> {dst}:{dport}  q={qname}"
        else:
            msg = f"UDP  {src}:{sport} -> {dst}:{dport}"
        print(msg)
        logging.info(msg)

    elif ICMP in pkt:
        icmp_type = pkt[ICMP].type
        icmp_code = pkt[ICMP].code
        msg = f"ICMP {src} -> {dst} type={icmp_type} code={icmp_code}"
        print(msg)
        logging.info(msg)