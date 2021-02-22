import ast
import pandas as pd
from scapy import main
class HostsProcessor:
    '''
        Works on pre-computed pandas dataframe of bidirectional
        network flows of 5 tuple.
    '''
    def __init__(self) -> None:
        pass

    def process(self, df):
        # output dataframe
        out_df = pd.DataFrame()
        # pre proccessing to df
        df['udps.src2dst_payload_freq'] = df['udps.src2dst_payload_freq'].apply(ast.literal_eval)
        df['udps.dst2src_payload_freq'] = df['udps.dst2src_payload_freq'].apply(ast.literal_eval)

        sent_packets = self._host(df, 'src2dst_packets', 'dst2src_packets').sum()
        out_df['sent_packets'] = sent_packets['src2dst_packets']

        received_packets = self._host(df, 'dst2src_packets', 'src2dst_packets').sum()
        out_df['received_packets'] = received_packets['dst2src_packets']

        recv_sent_ratio = received_packets['dst2src_packets'] / sent_packets['src2dst_packets']
        out_df['recv_sent_ratio'] = recv_sent_ratio

        sent_payload_freq = self._host(df, 'udps.src2dst_payload_freq', 'udps.dst2src_payload_freq').apply(
            lambda row: self._merge_dicts(row['udps.src2dst_payload_freq'])
            )
        def dict_max(dict1):
            return max(dict1.values())
        sent_most_freq_payload = sent_payload_freq.apply(dict_max)
        sent_most_freq_payload_ratio = sent_most_freq_payload / sent_packets['src2dst_packets']
        out_df['sent_freq_payload_ratio'] = sent_most_freq_payload_ratio.values

        #save to file
        out_df.to_csv('./hosts_out.csv')

    def _host(self, df, k1, k2):
        unidir_grouped_by_source = df[['src_ip', k1]].groupby(by='src_ip')
        unidir_grouped_by_dest   = df[['dst_ip', k2]].groupby(by='dst_ip')
        dataframes = list()
        for group_name, group in unidir_grouped_by_source:
            if group_name in unidir_grouped_by_dest.groups:
                dest_group = unidir_grouped_by_dest.get_group(group_name)
                dest_group = dest_group.rename(columns={'dst_ip':'src_ip',k2:k1})
                merged_group = pd.concat([group[['src_ip', k1]], dest_group])
                dataframes.append(merged_group)
            else:
                dataframes.append(group)
        return pd.concat(dataframes).groupby(by='src_ip')
    
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





print('starting')
df = pd.read_csv('out.csv')
HostsProcessor().process(df)