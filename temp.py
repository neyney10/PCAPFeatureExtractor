from tls_reassemble import *
from scapy.all import rdpcap, TCP, load_layer
load_layer("tls")

tlsr = TLSReassemble()

packets = rdpcap('./pcaps/temp2.pcap')

tlsr.process(packets[1][TCP].load)
tlsr.process(packets[2][TCP].load)
tlsr.process(bytes(packets[3][TCP].payload))