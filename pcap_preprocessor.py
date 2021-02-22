import os

from nfstream.streamer import NFStreamer

from plugins.flow_time_slicer import FlowTimeSlicer
from plugins.most_freq_payload_len_ratio import MostFreqPayloadLenRatio
from plugins.is_dns import IsDNS
from plugins.small_pkt_payload_ratio import SmallPacketPayloadRatio
from plugins.pkt_rel_time import PacketRelativeTime
from plugins.res_req_diff_time import ResReqDiffTime
from plugins.byte_freq import ByteFrequency
from flows_processor import FlowsProcessor

class PCAPPreprocessor:
    '''
        Windows, for dev-testing.
    '''
    def __init__(self, pcap_filepath) -> None:
        self.pcap_filepath = pcap_filepath
    
    def preprocess(self): 
        self._split_to_sessions(self.pcap_filepath)
        dir_list = os.listdir('./pcaps/splitted_pcap/')
        self._create_editcap_directory()
        for filepath in dir_list:
            self._split_to_time_windows(filepath)
    
    
    def _split_to_sessions(self, pcap_filepath):
        cd_command = 'cd ./pcaps'
        command = '"SplitCap.exe" -r ' + pcap_filepath + ' -o splitted_pcap -s sessions -d'
        op_result = os.system(cd_command + ' && ' + command)
        
        if op_result != 0:
            raise 'Failed to split PCAP file to sessions. command: ' + command
        
    def _split_to_time_windows(self, pcap_filepath, seconds = 10):
        filepath = './pcaps/splitted_pcap/' + pcap_filepath
        timesplit_command = '"D:/Program Files/Wireshark/editcap.exe" -i ' + str(seconds) + ' ' + filepath + ' ./pcaps/editcap_output/file.pcap'
        print(timesplit_command)
        op_result = os.system(timesplit_command)
        
        if op_result != 0:
            raise 'Failed to split PCAP file to time windows. command: ' + timesplit_command
    
    def _create_editcap_directory(self):
        path = './pcaps/editcap_output'
        try:
            os.mkdir(path)
        except OSError:
            print ("Creation of the directory %s failed" % path)
        else:
            print ("Successfully created the directory %s " % path)
            
            
            
## for debug
'''
pcappp = PCAPPreprocessor('DoH-Firefox84-NextDNS-1-pcap-format.pcap')
pcappp.preprocess()
'''


dir_list = os.listdir('./pcaps/editcap_output/')
for pcap_filepath_windowed in dir_list:
    pcap_filepath_windowed = './pcaps/editcap_output/' + pcap_filepath_windowed
    bpf_filter_string = None
    plugins = [FlowTimeSlicer(time=15),
            ResReqDiffTime(),
            ByteFrequency(),
            PacketRelativeTime(),
            SmallPacketPayloadRatio(),
            IsDNS(),
            MostFreqPayloadLenRatio()]
    streamer = NFStreamer(source=pcap_filepath_windowed,
                                decode_tunnels=True,
                                bpf_filter=bpf_filter_string,
                                promiscuous_mode=True,
                                snapshot_length=1536,
                                idle_timeout=1200,
                                active_timeout=1800,
                                accounting_mode=3,
                                udps=plugins,
                                n_dissections=20,
                                statistical_analysis=True,
                                splt_analysis=0,
                                n_meters=0,
                                performance_report=0)
    
    flows = list(streamer)
    print('Flow count:', len(flows))
print('Exiting...')
