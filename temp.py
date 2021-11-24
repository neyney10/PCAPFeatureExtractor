from nfstream import NFStreamer, NFPlugin
import pandas as pd
import numpy as np
from scapy.all import IP, DNS, IPv6, TCP, rdpcap, load_layer, raw
load_layer("tls")


class TLSPlugin(NFPlugin):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def on_init(self, packet, flow):
        flow.udps.ack = 0
        flow.udps.seq = 0
        flow.udps.record_len_up = 0
        flow.udps.record_len_down = 0
        flow.udps.record_lens = []
        
        
        self.on_update(packet, flow)
    
    def on_update(self, packet, flow):
        if flow.protocol == 6 and (flow.src_port == 443 or flow.dst_port == 443) and packet.payload_size > 0:
            if packet.direction == 0:
                record_lens, leftover = self.process(packet, flow.udps.record_len_up)
                flow.udps.record_len_up = leftover
                flow.udps.record_lens.extend(record_lens)
            else:
                record_lens, leftover = self.process(packet, flow.udps.record_len_down)
                flow.udps.record_len_down = leftover
                flow.udps.record_lens.extend(record_lens)
    
    def on_expire(self, flow):
        pass

    def process(self, packet, record_len, tls_header_len=5):
        raw_tcp_payload_data = raw(IP(packet.ip_packet)[TCP].payload)
        record_lens = []
        pos = 0
        while pos < len(raw_tcp_payload_data):
            if record_len == 0: # empty/new
                record_len = int.from_bytes(raw_tcp_payload_data[pos+3:pos+5], byteorder='big')
                record_lens.append(record_len)
                pos += tls_header_len
                
            received_data_len = len(raw_tcp_payload_data[pos:])
            if record_len <= received_data_len:
                pos += record_len
                received_data_len = 0
                record_len = 0
            else: 
                record_len -= received_data_len
                pos += received_data_len
        
        return (record_lens, record_len)



source = "/mnt/d/temp/University/masters/thesis/research/temp/NFStream/pcaps/DoH-Chrome81-Cloudflare.pcap"  #temp/skype_video2b.pcap' #'temp/DoH-Firefox84-NextDNS-1-pcap-format.pcap' # 'temp/skype_video2b.pcap' # sys.argv[1]


def entry():
    streamer = NFStreamer(source=source,
                                    decode_tunnels=True,
                                    bpf_filter=None,
                                    promiscuous_mode=True,
                                    snapshot_length=1536,
                                    idle_timeout=99999999,
                                    active_timeout=99999999,
                                    accounting_mode=3,
                                    udps=[
                                        #FlowPic2019('./temp', 0,  flow_active_time=60)
                                        #FlowPic2('./temp', time_per_subflow=60)
                                        #GrayPic1('./temp')
                                        TLSPlugin()
                                    ],
                                    n_dissections=20,
                                    statistical_analysis=True,)
    streamer.to_pandas()

if __name__ == '__main__':
    entry()