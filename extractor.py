

# from tls_record_joy import TLSRecordJoy

from nfstream import NFStreamer  # https://www.nfstream.org/docs/api
from os import path
from .tls_tshark_entry import extract_tls_features_and_merge
#from .hosts_processor import HostsProcessor
from .plugins.clump_flows import Clump_Flow
from .plugins.packets_size_interarrival_time import Packets_size_and_interarrival_time
from .plugins.asn_info import ASNInfo
from .plugins.n_pkts_byte_freq import NPacketsByteFrequency
from .plugins.first_packet_payload import FirstPacketPayloadLen
from .plugins.most_freq_payload_len_ratio import MostFreqPayloadLenRatio
from .plugins.dns_counter import DNSCounter
from .plugins.small_pkt_payload_ratio import SmallPacketPayloadRatio
from .plugins.pkt_rel_time import PacketRelativeTime
from .plugins.res_req_diff_time import ResReqDiffTime
#from .plugins.graypic import GrayPic1
from .plugins.protocol_header_fields import ProtocolHeaderFields
from .plugins.n_bytes import NBytes
from .plugins.stnn import STNN
#from guppy import hpy; h=hpy()


class Extractor:
    def __init__(self, input_pcap_filepath, output_dirpath, bpf_filter_string=None, custom_plugin_package=None, TLS=True) -> None:
        self.input_pcap_filepath = input_pcap_filepath
        self.output_dirpath = output_dirpath
        self.bpf_filter_string = bpf_filter_string
        self.custom_plugin_package = custom_plugin_package
        self.TLS = TLS
        
    def extract(self):
        plugins = self._plugins() if self.custom_plugin_package is None else self.custom_plugin_package

        # Time-windowed flows
        '''
        my_streamer = NFStreamer(source=self.input_pcap_filepath,
                                decode_tunnels=True,
                                bpf_filter=self.bpf_filter_string,
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
        del my_streamer
        '''
        
        # Sessions
        session_streamer = NFStreamer(source=self.input_pcap_filepath,
                                decode_tunnels=True,
                                bpf_filter=self.bpf_filter_string,
                                promiscuous_mode=True,
                                snapshot_length=1536,
                                idle_timeout=999999999,
                                active_timeout=999999999,
                                accounting_mode=0,
                                udps=plugins,
                                n_dissections=20,
                                statistical_analysis=True,
                                splt_analysis=0,
                                n_meters=0,
                                performance_report=0)

        if self.TLS:
            sessions_df = session_streamer.to_pandas(columns_to_anonymize=[])
            config_filepath = path.join(path.dirname(__file__), 'tools/config.json')
            sessions_df = extract_tls_features_and_merge(sessions_df, self.input_pcap_filepath, config_filepath)
            sessions_df.to_csv(path.join(self.output_dirpath,'out-sessions.csv'), index=False)
        else:
            session_streamer.to_csv(path.join(self.output_dirpath,'out-sessions.csv'))

        # Hosts
        # HostsProcessor(sessions_df, self.output_dirpath).process()
        #print(6,h.heap())
        return path.join(self.output_dirpath,'out-sessions.csv')

    def _plugins(self):
        return [
            ASNInfo(),
            DNSCounter(),
            FirstPacketPayloadLen(),
            MostFreqPayloadLenRatio(),
            NPacketsByteFrequency(n_first_packets=6),
            PacketRelativeTime(),
            SmallPacketPayloadRatio(),
            ResReqDiffTime(),
            Clump_Flow(),
            Packets_size_and_interarrival_time(),
            ProtocolHeaderFields(20),
            NBytes(),
            STNN(20)
        ]