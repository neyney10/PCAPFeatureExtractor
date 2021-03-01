from hosts_processor import HostsProcessor
from stats.stats import IterableStats, StatsCollection
from nfstream import NFStreamer
import pandas as pd
import numpy as np


class FlowsProcessor:
    def __init__(self, streamer: NFStreamer) -> None:
        self.streamer = streamer

    def process(self):
        byte_count = 0
        flows = 0

        byte_frequency = np.zeros(256)
        prt_stats_list = list()

        tcp = 0
        udp = 0
        dns = 0
        
        for flow in self.streamer:
            flows += 1
            byte_count += np.sum(flow.udps.bidirectional_n_packets_byte_frequency)
            byte_frequency += flow.udps.bidirectional_n_packets_byte_frequency
            prts    = IterableStats(flow.udps.packet_relative_times)
            prrdts  = IterableStats(flow.udps.req_res_time_diff)
            prt_stats_list.append(prts)
            if flow.protocol == 6:
                tcp += flow.bidirectional_packets
            elif flow.protocol == 17:
                udp += flow.bidirectional_packets
                if flow.udps.bidirectional_dns_packets:
                    dns += flow.udps.bidirectional_dns_packets
            
        print(StatsCollection(prt_stats_list).average())

        print(flows)
        print('TCP: ', tcp, 'UDP:', udp, 'DNS:', dns)
        print(byte_frequency / byte_count) # frequency to distribution
        req_res =  list(map( 
                    lambda flows:
                        IterableStats(
                            sum(
                                map(
                                lambda flow: flow.udps.req_res_time_diff,
                                flows
                                ),
                                []
                            )
                        ),
                    nfc.sessions.values()
                    ))
        
        
        
        df = self.streamer.to_pandas(columns_to_anonymize=[])
        df.to_csv('out-flows.csv')
        # self._host_features(df)
        #print(df.head())
        #df.to_csv('out.csv')

    def _host_features(self, df):
        HostsProcessor().process(df)


    
