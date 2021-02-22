
import unittest
import sys
sys.path.append('../')
from nfstream import NFStreamer
from plugins.dns_counter import DNSCounter
from plugins.most_freq_payload_len_ratio import MostFreqPayloadLenRatio
from plugins.small_pkt_payload_ratio import SmallPacketPayloadRatio
from plugins.res_req_diff_time import ResReqDiffTime
from plugins.byte_freq import ByteFrequency
from plugins.pkt_rel_time import PacketRelativeTime
import numpy as np

'''
    Testing NFStream Plugins
                            '''


class TestDNSCounter(unittest.TestCase):
    '''
    dns_packets   
    dns_queries   
    dns_responses 
    dns_qd_count  
    dns_an_count
    dns_ns_count
    dns_ar_count
    dns_response_digit_count
    dns_response_alpha_count
    dns_response_hypens_coun 
    dns_response_dots_count
    dns_response_ip_count
    '''
        
    def test_dns_counting_1(self):
        # Given
        plugins = [DNSCounter()]
        pcap_filepath = './pcaps/dns_1.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=plugins)
        # When
        flows = list(streamer) # read streams/flows streamer
        # Then
        flow_at_test = flows[0]
        # bidirectional
        self.assertEqual(flow_at_test.udps.bidirectional_dns_packets,   flow_at_test.bidirectional_packets)
        self.assertEqual(flow_at_test.udps.bidirectional_dns_queries,   1)
        self.assertEqual(flow_at_test.udps.bidirectional_dns_responses, 1)
        self.assertEqual(flow_at_test.udps.bidirectional_dns_qd_count,  2)
        self.assertEqual(flow_at_test.udps.bidirectional_dns_an_count,  3)
        self.assertEqual(flow_at_test.udps.bidirectional_dns_ns_count,  0)
        self.assertEqual(flow_at_test.udps.bidirectional_dns_ar_count,  0)
        self.assertEqual(flow_at_test.udps.bidirectional_dns_response_digit_count,  1)
        self.assertEqual(flow_at_test.udps.bidirectional_dns_response_alpha_count,  93)
        self.assertEqual(flow_at_test.udps.bidirectional_dns_response_hypens_count, 8)
        self.assertEqual(flow_at_test.udps.bidirectional_dns_response_dots_count,   9)
        self.assertEqual(flow_at_test.udps.bidirectional_dns_response_ip_count,     1)
        # src -> dst
        self.assertEqual(flow_at_test.udps.src2dst_dns_queries,   1)
        self.assertEqual(flow_at_test.udps.src2dst_dns_responses, 0)
        self.assertEqual(flow_at_test.udps.src2dst_dns_qd_count,  1)
        self.assertEqual(flow_at_test.udps.src2dst_dns_an_count,  0)
        self.assertEqual(flow_at_test.udps.src2dst_dns_ns_count,  0)
        self.assertEqual(flow_at_test.udps.src2dst_dns_ar_count,  0)
        self.assertEqual(flow_at_test.udps.src2dst_dns_response_digit_count,  0)
        self.assertEqual(flow_at_test.udps.src2dst_dns_response_alpha_count,  0)
        self.assertEqual(flow_at_test.udps.src2dst_dns_response_hypens_count, 0)
        self.assertEqual(flow_at_test.udps.src2dst_dns_response_dots_count,   0)
        self.assertEqual(flow_at_test.udps.src2dst_dns_response_ip_count,     0)
        # dst -> src
        self.assertEqual(flow_at_test.udps.dst2src_dns_queries,   0)
        self.assertEqual(flow_at_test.udps.dst2src_dns_responses, 1)
        self.assertEqual(flow_at_test.udps.dst2src_dns_qd_count,  1)
        self.assertEqual(flow_at_test.udps.dst2src_dns_an_count,  3)
        self.assertEqual(flow_at_test.udps.dst2src_dns_ns_count,  0)
        self.assertEqual(flow_at_test.udps.dst2src_dns_ar_count,  0)
        self.assertEqual(flow_at_test.udps.dst2src_dns_response_digit_count,  1)
        self.assertEqual(flow_at_test.udps.dst2src_dns_response_alpha_count,  93)
        self.assertEqual(flow_at_test.udps.dst2src_dns_response_hypens_count, 8)
        self.assertEqual(flow_at_test.udps.dst2src_dns_response_dots_count,   9)
        self.assertEqual(flow_at_test.udps.dst2src_dns_response_ip_count,     1)

class TestMostFreqPayloadRatio(unittest.TestCase):

    def test_most_freq_payload_ratio_1(self):
        # Given
        plugins = [MostFreqPayloadLenRatio()]
        pcap_filepath = './pcaps/http_most_freq_payload_ratio_simgle.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=plugins)
        # When
        flows = list(streamer) # read streams/flows streamer
        # Then
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')
        self.assertEqual(flow_at_test.udps.src2dst_most_freq_payload_ratio, 
                        3/5)
        self.assertEqual(flow_at_test.udps.dst2src_most_freq_payload_ratio, 
                        3/4)


class TestSmallPacketPayloadRatio(unittest.TestCase):

    def test_small_pkt_payload_ratio_1(self):
        # Given
        plugins = [SmallPacketPayloadRatio()]
        pcap_filepath = './pcaps/tls_small_pkt_payload_ratio_single.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=plugins)
        # When
        flows = list(streamer) # read streams/flows streamer
        # Then
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')
        self.assertEqual(flow_at_test.udps.src2dst_small_packet_payload_ratio, 
                        2/9)


class TestPacketRelativeTime(unittest.TestCase):

    def test_pkt_rel_time_1(self):
        # Given
        plugins = [PacketRelativeTime()]
        pcap_filepath = './pcaps/tls_pkt_rel_time_single.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=plugins)
        # When
        flows = list(streamer) # read streams/flows streamer
        # Then
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')
        self.assertEqual(flow_at_test.udps.packet_relative_times, 
                        [0, 132, 44999, 45065, 90006, 90075, 135027, 135090])


class TestByteFrequencyPlugin(unittest.TestCase):

    def test_byte_frequency_1(self):
        # Given
        plugins = [ByteFrequency()]
        pcap_filepath = './pcaps/tls_req_res_diff_time_single.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=plugins)
        # When
        flows = list(streamer) # read streams/flows streamer
        # Then
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')
        
        ''' 
            TODO
                '''
            


class TestReqResDiffTimePlugin(unittest.TestCase):
    def setUp(self):
        self.plugins = [ResReqDiffTime()]

    def test_stream_req_res_diff_time_1(self):
        # Given
        pcap_filepath = './pcaps/tls_req_res_diff_time_single.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=self.plugins)
        # When
        flows = list(streamer) # read streams/flows streamer
        # Then
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')
        self.assertEqual(len(flow_at_test.udps.req_res_time_diff), 44)
        avg = np.average(flow_at_test.udps.req_res_time_diff)
        self.assertAlmostEqual(avg, 21482, delta=1)
            
            
    def test_stream_req_res_diff_time_2(self):
        # Given / Arrange
        pcap_filepath = './pcaps/tls_req_res_diff_time_single_2.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=self.plugins)
        # When / Act
        flows = list(streamer) # read streams/flows streamer
        # Then / Assert
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')
        self.assertEqual(len(flow_at_test.udps.req_res_time_diff), 8)
        avg = np.average(flow_at_test.udps.req_res_time_diff)
        self.assertAlmostEqual(avg, 469, delta=0.5)




if __name__ == '__main__':
    unittest.main()
