'''
Note: 
    Requires python 3
    Requires linux (can use WSL)
    Doesn't work with pcapng suffix files, only pcap suffixes 
        work around is just rename the suffix from pcapng to pcap.

Using Scapy library as a complement for NFStream such as parsing DNS packets
'''

from plugins.asn_info import ASNInfo
from sessions_processor import SessionsProcessor
from plugins.n_pkts_byte_freq import NPacketsByteFrequency
from plugins.first_packet_payload import FirstPacketPayloadLen
from plugins.most_freq_payload_len_ratio import MostFreqPayloadLenRatio
from plugins.dns_counter import DNSCounter
from plugins.small_pkt_payload_ratio import SmallPacketPayloadRatio
from plugins.pkt_rel_time import PacketRelativeTime
from plugins.res_req_diff_time import ResReqDiffTime
from plugins.byte_freq import ByteFrequency
from plugins.graypic import GrayPic1
from flows_processor import FlowsProcessor
from nfstream import NFStreamer  # https://www.nfstream.org/docs/api

# possible files:
# './pcaps/tls.pcap' 
# "./pcaps/DoH-Firefox84-NextDNS-1.pcap"
# "./pcaps/merged.pcap"
# "./tests/pcaps/dns_1.pcap"
# "./pcaps/DoH-Firefox84-first-100-sec.pcap"
pcap_filepath = "./pcaps/DoH-Firefox84-NextDNS-1.pcap"
bpf_filter_string = None
plugins = [ASNInfo(),
           DNSCounter(),
           FirstPacketPayloadLen(),
           MostFreqPayloadLenRatio(),
           NPacketsByteFrequency(n_first_packets=6),
           PacketRelativeTime(),
           SmallPacketPayloadRatio(),
           ResReqDiffTime()]
           
my_streamer = NFStreamer(source=pcap_filepath,
                         decode_tunnels=True,
                         bpf_filter=bpf_filter_string,
                         promiscuous_mode=True,
                         snapshot_length=1536,
                         idle_timeout=1,
                         active_timeout=1,
                         accounting_mode=3,
                         udps=plugins,
                         n_dissections=20,
                         statistical_analysis=True,
                         splt_analysis=0,
                         n_meters=0,
                         performance_report=0)

my_streamer.to_csv('out-timed-flows.csv', columns_to_anonymize=[])

session_streamer = NFStreamer(source=pcap_filepath,
                         decode_tunnels=True,
                         bpf_filter=bpf_filter_string,
                         promiscuous_mode=True,
                         snapshot_length=1536,
                         idle_timeout=99999999,
                         active_timeout=99999999,
                         accounting_mode=3,
                         udps=plugins,
                         n_dissections=20,
                         statistical_analysis=True,
                         splt_analysis=0,
                         n_meters=0,
                         performance_report=0)

session_streamer.to_csv('out-sessions.csv', columns_to_anonymize=[])

'''
df = my_streamer.to_pandas(columns_to_anonymize=[])
sp = SessionsProcessor()
sp.process(df)


fp = FlowsProcessor(my_streamer)
fp.process()
'''
