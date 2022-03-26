from stats.stats import IterableStats
import numpy as np
import pandas as pd
import hashlib 
import os
import json


class TLSRecordJoy():
    '''

    '''
    # Note that in Joy, the output path is always relative, i.e, it appends './' before the given filepath.
    def __init__(self, pcap_filepath, config_filepath=os.path.join(os.path.dirname(__file__), 'tools/config.json'), 
                 output_filepath='tls-cisco-joy.json', **kwargs):
        super().__init__(**kwargs)
        self.pcap_filepath = pcap_filepath
        self.config_filepath = config_filepath
        self.output_filepath = output_filepath

    def execute_joy(self, nfstream_sessions_df=None):
        joy_config = self._read_joy_config_file()
        joy_command = ' '.join([joy_config['CiscoJoyPath'], 
                                'preemptive_timeout=0', 
                                'bidir=1', 
                                'tls=1', 
                                'output='+self.output_filepath, 
                                self.pcap_filepath])
        print(joy_command)
        res = os.system(joy_command)
        if res != 0 :
            raise Exception('[3rd-party tool] Cisco Joy didnt execute succesfully')
        
        joy_df = self._read_joy_output()
        os.remove(self.output_filepath)
        if joy_df is None:
            return nfstream_sessions_df
        
        if nfstream_sessions_df is None:
            return joy_df
        
        nfstream_sessions_df['hashed_session_id'] = nfstream_sessions_df.apply(self._five_tuple, axis=1)
        nfstream_sessions_df.reset_index()
        
        merged_df = nfstream_sessions_df.merge(joy_df, 
                                               on='hashed_session_id',
                                               how='left',
                                               validate='one_to_one',
                                               left_index=True).drop('hashed_session_id', axis=1)
        
        return merged_df
        
    def _read_joy_config_file(self):
        with open(self.config_filepath) as text_config:
            json_config = json.loads(text_config.read())
            return json_config
    
    def _read_joy_output(self):
        exctracted_features = [] 
        with open(self.output_filepath, "r") as joy_output:
            for i,row in enumerate(joy_output):
                if i == 0: # first line is metadata
                    continue # skip
                flow = json.loads(row)
                if 'tls' in flow:
                    exctracted_features.append(self._extract_features(flow))
                
        if len(exctracted_features) == 0:
            return None
        
        joy_df = pd.DataFrame(exctracted_features)
        joy_df['protocol'] = 6 # TCP
        joy_df['hashed_session_id'] = joy_df.apply(self._five_tuple, axis=1)
        joy_df = joy_df.drop(['src_ip', 'src_port','dst_ip','dst_port','protocol'], axis=1) 
        
        return joy_df.reset_index()
    
    def _extract_features(self, flow, n_records=20):
        # general flow features
        extracted_flow_features = {
            'src_ip':   flow['sa'], 
            'src_port': flow['sp'], 
            'dst_ip':   flow['da'], 
            'dst_port': flow['dp'],
        }
        
        # TLS:
        tls = flow['tls']
        exctracted_general_tls_features = self._exctract_general_tls_features(tls)
        exctracted_tls_features = self._exctract_tls_record_features(tls['srlt'])
        extracted_early_tls_features = self._exctract_tls_record_features(tls['srlt'][:min(n_records, len(tls['srlt']))])
        # rename dictionary keys
        extracted_early_tls_features = { key+'_n' : value for key, value in extracted_early_tls_features.items() }
        
        return {**exctracted_general_tls_features,
                **extracted_flow_features,
                **exctracted_tls_features,
                'tls_early_records_n': n_records,
                **extracted_early_tls_features} 
    
    def _exctract_general_tls_features(self, tls):
        # general TLS features
        extracted_tls_general_features = {
            'tls_cipher_suites': list(tls['cs']),
        }
        
        return extracted_tls_general_features
    
    def _extract_tls_clump_features(self, clumps):
        # clumped TLS features
        '''
        Clump is an aggregation of multiple records in the same direction.
        A clump is closed when the following record is sent in the reversed direction, which then
        opens a new clump for records in the reversed direction.
        
        The first clump is from source to destination.
        '''
        # bidirectional
        clump_bytes = list(map(lambda clump: sum(map(lambda record: record['b'], clump)), clumps))
        clump_bytes_stats = IterableStats(clump_bytes)
        clump_sizes = list(map(lambda clump: len(clump), clumps))
        clump_sizes_stats = IterableStats(clump_sizes)
        extracted_tls_clumped_features = {
            'bidirectional_tls_clumps': len(clumps),
            'bidirectional_tls_clump_bytes': clump_bytes,
            'bidirectional_tls_clump_sizes': clump_sizes,
            'bidirectional_mean_tls_clump_bytes':             clump_bytes_stats.average(),
            'bidirectional_median_tls_clump_bytes':           clump_bytes_stats.median(),
            'bidirectional_stddev_tls_clump_bytes':           clump_bytes_stats.std_deviation(),
            'bidirectional_variance_tls_clump_bytes':         clump_bytes_stats.variance(),
            'bidirectional_skew_from_median_tls_clump_bytes': clump_bytes_stats.skew_from_median(),
            'bidirectional_coeff_of_var_tls_clump_bytes':     clump_bytes_stats.coeff_of_variation(),
            'bidirectional_min_tls_clump_bytes':              clump_bytes_stats.min(),
            'bidirectional_max_tls_clump_bytes':              clump_bytes_stats.max(),
            'bidirectional_mean_tls_clump_sizes':             clump_sizes_stats.average(),
            'bidirectional_median_tls_clump_sizes':           clump_sizes_stats.median(),
            'bidirectional_stddev_tls_clump_sizes':           clump_sizes_stats.std_deviation(),
            'bidirectional_variance_tls_clump_sizes':         clump_sizes_stats.variance(),
            'bidirectional_skew_from_median_tls_clump_sizes': clump_sizes_stats.skew_from_median(),
            'bidirectional_coeff_of_var_tls_clump_sizes':     clump_sizes_stats.coeff_of_variation(),
            'bidirectional_min_tls_clump_sizes':              clump_sizes_stats.min(),
            'bidirectional_max_tls_clump_sizes':              clump_sizes_stats.max(),
        }
        # src -> dst
        src2dst_clumps = clumps[::2]
        src2dst_clump_bytes = list(map(lambda clump: sum(map(lambda record: record['b'], clump)), src2dst_clumps))
        src2dst_clump_bytes_stats = IterableStats(src2dst_clump_bytes)
        src2dst_clump_sizes = list(map(lambda clump: len(clump), src2dst_clumps))
        src2dst_clump_sizes_stats = IterableStats(src2dst_clump_sizes)
        src2dst_extracted_tls_clumped_features = {
            'src2dst_tls_clumps': len(src2dst_clumps),
            'src2dst_tls_clump_bytes': src2dst_clump_bytes,
            'src2dst_tls_clump_sizes': src2dst_clump_sizes,
            'src2dst_mean_tls_clump_bytes':             src2dst_clump_bytes_stats.average(),
            'src2dst_median_tls_clump_bytes':           src2dst_clump_bytes_stats.median(),
            'src2dst_stddev_tls_clump_bytes':            src2dst_clump_bytes_stats.std_deviation(),
            'src2dst_variance_tls_clump_bytes':         src2dst_clump_bytes_stats.variance(),
            'src2dst_skew_from_median_tls_clump_bytes': src2dst_clump_bytes_stats.skew_from_median(),
            'src2dst_coeff_of_var_tls_clump_bytes':     src2dst_clump_bytes_stats.coeff_of_variation(),
            'src2dst_min_tls_clump_bytes':              src2dst_clump_bytes_stats.min(),
            'src2dst_max_tls_clump_bytes':              src2dst_clump_bytes_stats.max(),
            'src2dst_mean_tls_clump_sizes':             src2dst_clump_sizes_stats.average(),
            'src2dst_median_tls_clump_sizes':           src2dst_clump_sizes_stats.median(),
            'src2dst_stddev_tls_clump_sizes':            src2dst_clump_sizes_stats.std_deviation(),
            'src2dst_variance_tls_clump_sizes':         src2dst_clump_sizes_stats.variance(),
            'src2dst_skew_from_median_tls_clump_sizes': src2dst_clump_sizes_stats.skew_from_median(),
            'src2dst_coeff_of_var_tls_clump_sizes':     src2dst_clump_sizes_stats.coeff_of_variation(),
            'src2dst_min_tls_clump_sizes':              src2dst_clump_sizes_stats.min(),
            'src2dst_max_tls_clump_sizes':              src2dst_clump_sizes_stats.max(),
        }
        # dst -> src
        dst2src_clumps = clumps[1::2]
        dst2src_clump_bytes = list(map(lambda clump: sum(map(lambda record: record['b'], clump)), dst2src_clumps))
        dst2src_clump_bytes_stats = IterableStats(dst2src_clump_bytes)
        dst2src_clump_sizes = list(map(lambda clump: len(clump), dst2src_clumps))
        dst2src_clump_sizes_stats = IterableStats(dst2src_clump_sizes)
        dst2src_extracted_tls_clumped_features = {
            'dst2src_tls_clumps': len(dst2src_clumps),
            'dst2src_tls_clump_bytes': dst2src_clump_bytes,
            'dst2src_tls_clump_sizes': dst2src_clump_sizes,
            'dst2src_mean_tls_clump_bytes':             dst2src_clump_bytes_stats.average(),
            'dst2src_median_tls_clump_bytes':           dst2src_clump_bytes_stats.median(),
            'dst2src_stddev_tls_clump_bytes':            dst2src_clump_bytes_stats.std_deviation(),
            'dst2src_variance_tls_clump_bytes':         dst2src_clump_bytes_stats.variance(),
            'dst2src_skew_from_median_tls_clump_bytes': dst2src_clump_bytes_stats.skew_from_median(),
            'dst2src_coeff_of_var_tls_clump_bytes':     dst2src_clump_bytes_stats.coeff_of_variation(),
            'dst2src_min_tls_clump_bytes':              dst2src_clump_bytes_stats.min(),
            'dst2src_max_tls_clump_bytes':              dst2src_clump_bytes_stats.max(),
            'dst2src_mean_tls_clump_sizes':             dst2src_clump_sizes_stats.average(),
            'dst2src_median_tls_clump_sizes':           dst2src_clump_sizes_stats.median(),
            'dst2src_stddev_tls_clump_sizes':            dst2src_clump_sizes_stats.std_deviation(),
            'dst2src_variance_tls_clump_sizes':         dst2src_clump_sizes_stats.variance(),
            'dst2src_skew_from_median_tls_clump_sizes': dst2src_clump_sizes_stats.skew_from_median(),
            'dst2src_coeff_of_var_tls_clump_sizes':     dst2src_clump_sizes_stats.coeff_of_variation(),
            'dst2src_min_tls_clump_sizes':              dst2src_clump_sizes_stats.min(),
            'dst2src_max_tls_clump_sizes':              dst2src_clump_sizes_stats.max(),
        }
        
        return {**src2dst_extracted_tls_clumped_features,
                **dst2src_extracted_tls_clumped_features,
                **extracted_tls_clumped_features}
        
    
    def _exctract_tls_record_features(self, records):
        # src -> dst
        src2dst_tls_records = list(filter(lambda tls_record: tls_record['dir'] == '>', records))
        src2dst_tls_record_sizes = list(map(lambda tls_record: tls_record['b'], src2dst_tls_records))
        src2dst_stats = IterableStats(src2dst_tls_record_sizes)
        src2dst_extracted_features = {
            'src2dst_tls_records': len(src2dst_tls_records),
            'src2dst_tls_record_types': list(map(lambda tls_record: tls_record['tp'], src2dst_tls_records)) ,
            'src2dst_tls_record_sizes': src2dst_tls_record_sizes,
            'src2dst_tls_record_frequencies': {key : value for key,value in np.asarray(np.unique(src2dst_tls_record_sizes, return_counts=True) ).T},
            'src2dst_tls_payload_bytes': sum(src2dst_tls_record_sizes),
            'src2dst_tls_record_distinct_sizes': len(np.unique(src2dst_tls_record_sizes)),
            'src2dst_mean_tls_record_size':             src2dst_stats.average(),
            'src2dst_median_tls_record_size':           src2dst_stats.median(),
            'src2dst_stddev_tls_record_size':           src2dst_stats.std_deviation(),
            'src2dst_variance_tls_record_size':         src2dst_stats.variance(),
            'src2dst_skew_from_median_tls_record_size': src2dst_stats.skew_from_median(),
            'src2dst_coeff_of_var_tls_record_size':     src2dst_stats.coeff_of_variation(),
            'src2dst_min_tls_record_size':              src2dst_stats.min(),
            'src2dst_max_tls_record_size':              src2dst_stats.max(),
        }
        
        # dst -> src
        dst2src_tls_records = list(filter(lambda tls_record: tls_record['dir'] == '<', records))                                                  
        dst2src_tls_record_sizes = list(map(lambda tls_record: tls_record['b'], dst2src_tls_records))
        dst2src_stats = IterableStats(dst2src_tls_record_sizes)
        dst2src_extracted_features = {
            'dst2src_tls_records': len(dst2src_tls_records),
            'dst2src_tls_record_types': list(map(lambda tls_record: tls_record['tp'], dst2src_tls_records)) ,
            'dst2src_tls_record_sizes': dst2src_tls_record_sizes,
            'dst2src_tls_record_frequencies': {key : value for key,value in np.asarray(np.unique(dst2src_tls_record_sizes, return_counts=True) ).T},
            'dst2src_tls_payload_bytes': sum(dst2src_tls_record_sizes),
            'dst2src_tls_record_distinct_sizes': len(np.unique(dst2src_tls_record_sizes)),
            'dst2src_mean_tls_record_size':             dst2src_stats.average(),
            'dst2src_median_tls_record_size':           dst2src_stats.median(),
            'dst2src_stddev_tls_record_size':            dst2src_stats.std_deviation(),
            'dst2src_variance_tls_record_size':         dst2src_stats.variance(),
            'dst2src_skew_from_median_tls_record_size': dst2src_stats.skew_from_median(),
            'dst2src_coeff_of_var_tls_record_size':     dst2src_stats.coeff_of_variation(),
            'dst2src_min_tls_record_size':              dst2src_stats.min(),
            'dst2src_max_tls_record_size':              dst2src_stats.max(),
            
        }
        # bidirectional                                    
        tls_record_sizes = list(map(lambda tls_record: tls_record['b'],  records))
        bi_stats = IterableStats(tls_record_sizes)
        bidirectional_extracted_features = {
            'bidirectional_tls_records': len(records),
            'bidirectional_tls_record_types': list(map(lambda tls_record: tls_record['tp'], records)) ,
            'bidirectional_tls_record_sizes': tls_record_sizes,
            'bidirectional_tls_record_frequencies': {key : value for key,value in np.asarray(np.unique(tls_record_sizes, return_counts=True) ).T},
            'bidirectional_tls_payload_bytes': sum(tls_record_sizes),
            'bidirectional_tls_record_distinct_sizes': len(np.unique(tls_record_sizes)),
            'bidirectional_mean_tls_record_size':             bi_stats.average(),
            'bidirectional_median_tls_record_size':           bi_stats.median(),
            'bidirectional_stddev_tls_record_size':           bi_stats.std_deviation(),
            'bidirectional_variance_tls_record_size':         bi_stats.variance(),
            'bidirectional_skew_from_median_tls_record_size': bi_stats.skew_from_median(),
            'bidirectional_coeff_of_var_tls_record_size':     bi_stats.coeff_of_variation(),
            'bidirectional_min_tls_record_size':              bi_stats.min(),
            'bidirectional_max_tls_record_size':              bi_stats.max(),
        }
        
        return {**src2dst_extracted_features, 
                **dst2src_extracted_features,
                **bidirectional_extracted_features,
                **self._extract_tls_clump_features(self._clumps(records))}
        
    def _clumps(self, tls_records):
        clumps = []
        dir = '>'
        begin = 0
        end = 0
        for i, record in enumerate(tls_records):
            if dir != record['dir']:
                end = i
                clump = tls_records[begin:end]
                clumps.append(clump)
                begin = end
                dir = record['dir']
        
        if end < begin:
            clump = tls_records[begin:len(tls_records)]
            clumps.append(clump)
            
        return clumps

    def _five_tuple(self, row):
        return hashlib.md5(
            '-'.join(sorted([
                row['src_ip'],
                str(row['src_port']),
                row['dst_ip'],
                str(row['dst_port']),
                str(row['protocol'])
            ])).encode()
        ).digest()
        
        
        
        
if __name__ == '__main__':
    print('starting')
    #df = pd.read_csv('./temp/out-sessions.csv')
    merged_df = TLSRecordJoy(r'./pcaps/DoH-Firefox84-NextDNS-1-pcap-format.pcap').execute_joy()
    
    merged_df.to_csv('./temp/out-sessions-merged-with-tls.csv')