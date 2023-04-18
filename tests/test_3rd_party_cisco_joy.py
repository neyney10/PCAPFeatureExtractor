from nfstream.streamer import NFStreamer
import unittest
from os import path
import os
import sys
sys.path.append(os.getcwd())
from tls_record_joy import TLSRecordJoy

'''
    TESTING 3RD PARTY TOOLS
    1. Cisco-Joy.
                            '''
'''
    WORK IN PROGRESS
                    '''

class TestTLSRecordFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.pcap_filepath = 'tests/pcaps/tls_small_pkt_payload_ratio_single.pcap'
        tls_joy = TLSRecordJoy(self.pcap_filepath, config_filepath=path.join('tools','config.json'))
        self.joy_df = tls_joy.execute_joy(nfstream_sessions_df=None)
        
    @classmethod  
    def tearDownClass(self):
        del self.joy_df
        
    def test_tls_record_count_1(self):
        # Given
            # self.joy_df
        # When
        src2dst_number_of_tls_records_per_session = list(self.joy_df['src2dst_tls_records'])
        dst2src_number_of_tls_records_per_session = list(self.joy_df['dst2src_tls_records'])
        bidir_number_of_tls_records_per_session   = list(self.joy_df['bidirectional_tls_records'])
        # Then
        self.assertSequenceEqual(src2dst_number_of_tls_records_per_session, [8])
        self.assertSequenceEqual(dst2src_number_of_tls_records_per_session, [4])
        self.assertSequenceEqual(bidir_number_of_tls_records_per_session,   [12])
        
    def test_tls_record_types_1(self):
        # Given
            # self.joy_df
        # When
        src2dst_types_of_tls_records_per_session = list(self.joy_df['src2dst_tls_record_types'])
        dst2src_types_of_tls_records_per_session = list(self.joy_df['dst2src_tls_record_types'])
        bidir_types_of_tls_records_per_session   = list(self.joy_df['bidirectional_tls_record_types'])
        # Then
        self.assertSequenceEqual(src2dst_types_of_tls_records_per_session, [[22, 20, 22, 23, 23, 23 ,23, 23]])
        self.assertSequenceEqual(dst2src_types_of_tls_records_per_session, [[22, 20, 22, 23]])
        self.assertSequenceEqual(bidir_types_of_tls_records_per_session,   [[22, 22, 20, 22, 20, 22, 23, 23, 23, 23, 23, 23]])
        
    def test_tls_record_sizes_1(self):
        # Given
            # self.joy_df
        # When
        src2dst_sizes_of_tls_records_per_session = list(self.joy_df['src2dst_tls_record_sizes'])
        dst2src_sizes_of_tls_records_per_session = list(self.joy_df['dst2src_tls_record_sizes'])
        bidir_sizes_of_tls_records_per_session   = list(self.joy_df['bidirectional_tls_record_sizes'])
        # Then
        self.assertSequenceEqual(src2dst_sizes_of_tls_records_per_session, [[512, 1, 40, 664, 114, 49, 51, 45]])
        self.assertSequenceEqual(dst2src_sizes_of_tls_records_per_session, [[85, 1, 40, 207]])
        self.assertSequenceEqual(bidir_sizes_of_tls_records_per_session,   [[512, 85, 1, 40, 1, 40, 664, 207, 114, 49, 51, 45]])
        
    def test_tls_record_size_frequencies_1(self):
        # Given
            # self.joy_df
        # When
        src2dst_size_freq_of_tls_records_per_session = list(self.joy_df['src2dst_tls_record_frequencies'])
        dst2src_size_freq_of_tls_records_per_session = list(self.joy_df['dst2src_tls_record_frequencies'])
        bidir_size_freq_of_tls_records_per_session   = list(self.joy_df['bidirectional_tls_record_frequencies'])
        # Then
        self.assertSequenceEqual(src2dst_size_freq_of_tls_records_per_session, [{512: 1, 1: 1, 40: 1, 664:1, 114: 1, 49:1, 51:1, 45: 1}])
        self.assertSequenceEqual(dst2src_size_freq_of_tls_records_per_session, [{85: 1, 1: 1, 40: 1, 207: 1}])
        self.assertSequenceEqual(bidir_size_freq_of_tls_records_per_session,   [{512: 1, 85: 1, 1: 2, 40: 2, 664: 1, 207: 1, 114: 1, 49: 1, 51: 1, 45: 1}])
        
    def test_tls_record_total_payload_bytes_1(self):
        # Given
            # self.joy_df
        # When
        src2dst_total_bytes_of_tls_records_per_session = list(self.joy_df['src2dst_tls_payload_bytes'])
        dst2src_total_bytes_of_tls_records_per_session = list(self.joy_df['dst2src_tls_payload_bytes'])
        bidir_total_bytes_of_tls_records_per_session   = list(self.joy_df['bidirectional_tls_payload_bytes'])
        # Then
        self.assertSequenceEqual(src2dst_total_bytes_of_tls_records_per_session, [1476])
        self.assertSequenceEqual(dst2src_total_bytes_of_tls_records_per_session, [333])
        self.assertSequenceEqual(bidir_total_bytes_of_tls_records_per_session,   [1476 + 333])
        
    def test_tls_record_number_of_distinct_sizes_1(self):
        # Given
            # self.joy_df
        # When
        src2dst_distinct_sizes_of_tls_records_per_session = list(self.joy_df['src2dst_tls_record_distinct_sizes'])
        dst2src_distinct_sizes_of_tls_records_per_session = list(self.joy_df['dst2src_tls_record_distinct_sizes'])
        bidir_distinct_sizes_of_tls_records_per_session   = list(self.joy_df['bidirectional_tls_record_distinct_sizes'])
        # Then
        self.assertSequenceEqual(src2dst_distinct_sizes_of_tls_records_per_session, [8])
        self.assertSequenceEqual(dst2src_distinct_sizes_of_tls_records_per_session, [4])
        self.assertSequenceEqual(bidir_distinct_sizes_of_tls_records_per_session,   [10])
        
    def test_tls_record_sizes_mean_1(self):
        # Given
            # self.joy_df
        # When
        src2dst_mean_distinct_sizes_of_tls_records_per_session = list(self.joy_df['src2dst_mean_tls_record_size'])
        dst2src_mean_distinct_sizes_of_tls_records_per_session = list(self.joy_df['dst2src_mean_tls_record_size'])
        bidir_mean_distinct_sizes_of_tls_records_per_session   = list(self.joy_df['bidirectional_mean_tls_record_size'])
        # Then
        self.assertSequenceEqual(src2dst_mean_distinct_sizes_of_tls_records_per_session, [184.5])
        self.assertSequenceEqual(dst2src_mean_distinct_sizes_of_tls_records_per_session, [83.25])
        self.assertSequenceEqual(bidir_mean_distinct_sizes_of_tls_records_per_session,   [150.75])
        
    
    
if __name__ == '__main__':
    unittest.main()
