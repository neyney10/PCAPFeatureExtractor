
from hosts_processor import HostsProcessor
from plugins.asn_info import ASNInfo
from plugins.n_pkts_byte_freq import NPacketsByteFrequency
from plugins.first_packet_payload import FirstPacketPayloadLen
from plugins.most_freq_payload_len_ratio import MostFreqPayloadLenRatio
from plugins.dns_counter import DNSCounter
from plugins.small_pkt_payload_ratio import SmallPacketPayloadRatio
from plugins.pkt_rel_time import PacketRelativeTime
from plugins.res_req_diff_time import ResReqDiffTime
from nfstream import NFStreamer  # https://www.nfstream.org/docs/api
from os import path

class Extractor:
    def __init__(self, input_pcap_filepath, output_dirpath) -> None:
        self.input_pcap_filepath = input_pcap_filepath
        self.output_dirpath = output_dirpath
        
    def extract(self):
        bpf_filter_string = None  
        plugins = self._plugins()
        # Time-windowed flows
        my_streamer = NFStreamer(source=self.input_pcap_filepath,
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

        my_streamer.to_csv(path.join(self.output_dirpath,'out-timed-flows.csv'), columns_to_anonymize=[])
        # Sessions
        session_streamer = NFStreamer(source=self.input_pcap_filepath,
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
        sessions_df = session_streamer.to_pandas(columns_to_anonymize=[])
        sessions_df.to_csv(path.join(self.output_dirpath,'out-sessions.csv'))
        # Hosts
        HostsProcessor(sessions_df, self.output_dirpath).process()

    def _plugins(self):
        return [ASNInfo(),
                DNSCounter(),
                FirstPacketPayloadLen(),
                MostFreqPayloadLenRatio(),
                NPacketsByteFrequency(n_first_packets=6),
                PacketRelativeTime(),
                SmallPacketPayloadRatio(),
                ResReqDiffTime()]