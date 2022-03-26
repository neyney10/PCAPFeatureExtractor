import ast
import pandas as pd
import os
from enum import IntEnum
import numpy as np
from pandas.core.groupby.generic import DataFrameGroupBy

class Protocol(IntEnum):
    TCP=6
    UDP=17


class HostsProcessor:
    '''
        Works on pre-computed pandas dataframe of bidirectional
        network flows of 5 tuple.
    '''
    def __init__(self, df, output_dirpath) -> None:
        self.df = df
        self.output_dirpath = output_dirpath
        self.unidir_grouped_by_source = df.groupby(by='src_ip')
        self.unidir_grouped_by_dest = df.groupby(by='dst_ip')

    def process(self):
        '''
        Note: code here can be optimized both in terms of performance and memory consumption.
        But at the moment, readability is preferable.
        '''
        # output dataframe
        out_df = pd.DataFrame()
        # pre proccessing to df
        self.df['udps.src2dst_payload_freq'] = self.df['udps.src2dst_payload_freq'].apply(ast.literal_eval)
        self.df['udps.dst2src_payload_freq'] = self.df['udps.dst2src_payload_freq'].apply(ast.literal_eval)
        # Features
        # first seen (ms)
        first_seen_ms = self._host(self.df, 'bidirectional_first_seen_ms', 'bidirectional_first_seen_ms').min(numeric_only=True).squeeze()
        out_df['first_seen_ms'] = first_seen_ms
        # last seen (ms)
        last_seen_ms = self._host(self.df, 'bidirectional_last_seen_ms', 'bidirectional_last_seen_ms').min(numeric_only=True).squeeze()
        out_df['last_seen_ms'] = last_seen_ms
        # seen duration (ms)
        seen_duration_ms = last_seen_ms - first_seen_ms
        out_df['seen_duration_ms'] = seen_duration_ms
        # packets sent by host
        sent_packets_df = self._host(self.df, 'src2dst_packets', 'dst2src_packets')
        sent_packets = sent_packets_df.sum().squeeze()
        out_df['sent_packets'] = sent_packets
        # packets received by host
        received_packets = self._host(self.df, 'dst2src_packets', 'src2dst_packets').sum().squeeze()
        out_df['received_packets'] = received_packets
        # received/sent packets ratio by host
        recv_sent_packets_ratio = received_packets / sent_packets
        out_df['recv_sent_packets_ratio'] = recv_sent_packets_ratio
        # average of packets sent in sessions by host
        sent_mean_packets_per_sessions = sent_packets_df.mean().squeeze()
        out_df['sent_mean_packets_per_sessions'] = sent_mean_packets_per_sessions
        # median of packets sent in sessions by host
        sent_median_packets_per_sessions = sent_packets_df.median().squeeze()
        out_df['sent_median_packets_per_sessions'] = sent_median_packets_per_sessions
        # std deviation of packets sent in sessions by host
        sent_stdev_packets_per_sessions = sent_packets_df.std().squeeze()
        out_df['sent_stdev_packets_per_sessions'] = sent_stdev_packets_per_sessions
        # std deviation of packets sent in sessions by host
        sent_var_packets_per_sessions = sent_packets_df.var().squeeze()
        out_df['sent_variance_packets_per_sessions'] = sent_var_packets_per_sessions
        # bytes sent
        sent_bytes = self._host(self.df, 'src2dst_bytes', 'dst2src_bytes').sum().squeeze()
        out_df['sent_bytes'] = sent_bytes
        # bytes received
        recv_bytes = self._host(self.df, 'dst2src_bytes', 'src2dst_bytes').sum().squeeze()
        out_df['recv_bytes'] = recv_bytes
        # bytes received
        recv_sent_bytes_ratio = recv_bytes / sent_bytes
        out_df['recv_sent_bytes_ratio'] = recv_sent_bytes_ratio
        # sent payload frequency by host
        sent_payload_freq = self._host(self.df, 'udps.src2dst_payload_freq', 'udps.dst2src_payload_freq').apply(
            lambda row: self._merge_dicts(row['udps.src2dst_payload_freq'])
            )
        out_df['sent_payload_freq'] = sent_payload_freq
        # most frequent payload length sent by host
        def dict_max(dict1):
            return max(dict1.values())
        sent_most_freq_payload_len = sent_payload_freq.apply(dict_max)
        out_df['sent_most_freq_payload_len'] = sent_most_freq_payload_len
        # most freq payload sent to number of packets sent ratio by host
        sent_most_freq_payload_ratio = sent_most_freq_payload_len / sent_packets
        out_df['sent_most_freq_payload_ratio'] = sent_most_freq_payload_ratio
        # number of distinct different destination addresses
        unique_dst_addresses = self._host(self.df, 'dst_ip', 'src_ip').nunique().squeeze()
        out_df['num_distinct_dst_addresses'] = unique_dst_addresses
        # number of distinct different destination ports
        unique_dst_ports = self._host(self.df, 'dst_port', 'src_port').nunique().squeeze()
        out_df['num_distinct_dst_ports'] = unique_dst_ports
        # number of small packets sent
        sent_small_pkt_payload_packets = self._host(self.df, 'udps.src2dst_small_packet_payload_packets', 
            'udps.dst2src_small_packet_payload_packets').sum().squeeze()
        out_df['sent_small_packet_payload_packets'] = sent_small_pkt_payload_packets
        # number of small packets to the number of sent packets ratio
        sent_small_pkt_payload_ratio = sent_small_pkt_payload_packets / sent_packets
        out_df['sent_small_packet_payload_ratio'] = sent_small_pkt_payload_ratio
        # number of total sessions
        sessions = self._host(self.df, 'protocol', 'protocol').count().squeeze()
        out_df['sessions'] = sessions
        # number of UDP sessions
        udp_sessions = self._host(self.df[self.df['protocol']==Protocol.UDP], 'protocol', 'protocol').count().squeeze()
        out_df['udp_sessions'] = udp_sessions
        # number of TCP sessions
        tcp_sessions = self._host(self.df[self.df['protocol']==Protocol.TCP], 'protocol', 'protocol').count().squeeze()
        out_df['tcp_sessions'] = tcp_sessions
        # number of UDP packets sent
        sent_udp_packets = self._host(self.df[self.df['protocol']==Protocol.UDP], 'src2dst_packets', 'dst2src_packets').sum().squeeze()
        out_df['sent_udp_packets'] = sent_udp_packets
        # number of TCP packets sent
        sent_tcp_packets = self._host(self.df[self.df['protocol']==Protocol.TCP], 'src2dst_packets', 'dst2src_packets').sum().squeeze()
        out_df['sent_tcp_packets'] = sent_tcp_packets
        # number of DNS packets sent
        sent_dns_packets = self._host(self.df[self.df['protocol']==Protocol.UDP], 
                                      'udps.src2dst_dns_packets', 
                                      'udps.dst2src_dns_packets').sum().squeeze()
        out_df['sent_dns_packets'] = sent_dns_packets
        # ratio of number UDP packets to number of packets sent
        sent_udp_packets_ratio = sent_udp_packets / sent_packets
        out_df['sent_udp_packets_ratio'] = sent_udp_packets_ratio
        # ratio of number TCP packets to number of packets sent
        sent_tcp_packets_ratio = sent_tcp_packets / sent_packets
        out_df['sent_tcp_packets_ratio'] = sent_tcp_packets_ratio
        # ratio of number DNS packets to number of packets sent
        sent_dns_packets_ratio = sent_dns_packets / sent_packets
        out_df['sent_dns_packets_ratio'] = sent_dns_packets_ratio

        

        #save to file
        out_df.to_csv(os.path.join(self.output_dirpath, 'out-hosts.csv'))
        
    def _host(self, df, k1, k2):
        '''
        Description:
            Retrieves all relavent columns from both direction that represent the same thing.
            In case we want all packets sent by some source IP address (host), the function
            combines the packets sent in session when the host is the initiator of the session,
            with the number of packets received in the session where the host is not the initator.
            This function do this for all hosts in the df in seperate.
            
        Params:
            df: the sessions dataframe created by NFStream.
            k1: the key/column for the df to extract its values from.
            k2: the equivalent key/column for k1 just for the reverse direction.
            
        Example:
            If the df have columns 'src2dst_packets' and 'dst2src_packets' that represents
            the number of packets from source to destination and from destination to source respectfuly,
            then `k1='src2dst_packets'` and `k2='dst2src_packets'`
            so the function call would be:
            `self._host(df, 'src2dst_packets', 'dst2src_packets')`
        '''
        unidir_grouped_by_source = self.unidir_grouped_by_source[['src_ip', k1]]
        unidir_grouped_by_dest   = self.unidir_grouped_by_dest[['dst_ip', k2]]
        dataframes = list()
        for group_name, group in unidir_grouped_by_source:
            if group_name in unidir_grouped_by_dest.groups:
                dest_group = unidir_grouped_by_dest.get_group(group_name)
                dest_group = dest_group.rename(columns={'dst_ip':'src_ip',k2:k1})
                merged_group = pd.concat([group[['src_ip', k1]], dest_group])
                dataframes.append(merged_group)
            else:
                dataframes.append(group[['src_ip', k1]])

        return pd.concat(dataframes).groupby(by='src_ip', as_index=True)
    
    def _stats(self, grouped_df: DataFrameGroupBy):
        '''
        Description:
            Computes a pre-defined list of statistical functions
            for a grouped dataframe (DataFrameGroupBy) object.
            The statistical functions are:
            - mean
            - median
            - std
            - var
            in that order.
            
        Example:
            out_df[['mean', 'median', 'std', 'var']] = self._stats(grouped_df)
        '''
        return grouped_df.agg([
            np.mean,
            np.median,
            np.std,
            np.var
        ])
    
    def _merge_dicts(self, dicts):
        ''' Merge dictionaries and keep values of common keys in list'''
        merged_dict = dict()
        for i in range(len(dicts)):
            merged_dict = self._merge_dict(merged_dict, dicts.iloc[i])
        
        return merged_dict

    def _merge_dict(self, dict1, dict2):
        ''' Merge dictionaries and keep values of common keys in list'''
        dict3 = {**dict1, **dict2}
        for key, value in dict3.items():
            if key in dict1 and key in dict2:
                    dict3[key] = value + dict1[key]
        return dict3




if __name__ == '__main__':
    print('starting')
    df = pd.read_csv('./temp/out-sessions.csv')
    HostsProcessor(df ,'temp').process()