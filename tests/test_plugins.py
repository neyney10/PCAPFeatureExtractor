

import unittest
import sys
sys.path.append('../')
from plugins.n_pkts_byte_freq import NPacketsByteFrequency
from nfstream import NFStreamer
from plugins.dns_counter import DNSCounter
from plugins.most_freq_payload_len_ratio import MostFreqPayloadLenRatio
from plugins.small_pkt_payload_ratio import SmallPacketPayloadRatio
from plugins.res_req_diff_time import ResReqDiffTime
from plugins.pkt_rel_time import PacketRelativeTime
from plugins.clump_flows import Clump_Flow
from plugins.packets_size_interarrival_time import Packets_size_and_interarrival_time
import numpy as np

'''
    Testing NFStream Plugins
                            '''

class TestClumpsPlugin(unittest.TestCase):
    def setUp(self):
        self.plugins = [Clump_Flow()]

    def test_clump_flow_1(self):
            # Given
        pcap_filepath = './pcaps/tls_pkt_rel_time_single.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=self.plugins)
        # When
        flows = list(streamer) # read streams/flows streamer
        # Then
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')
        
        #src2dst
        self.assertEqual(flow_at_test.udps.src2dst_max_clumps_len, 98)
        self.assertEqual(flow_at_test.udps.src2dst_min_clumps_len, 98)
        self.assertEqual(flow_at_test.udps.src2dst_mean_clumps_len, 98)
        self.assertEqual(flow_at_test.udps.src2dst_stddev_clumps_len, 0)
        self.assertEqual(flow_at_test.udps.src2dst_skewness_clumps_len, 0)
        self.assertEqual(flow_at_test.udps.src2dst_variance_clumps_len, 0)
        self.assertEqual(flow_at_test.udps.src2dst_kurtosis_clumps_len, 0)
        
        self.assertEqual(flow_at_test.udps.src2dst_max_clumps_size, 1)
        self.assertEqual(flow_at_test.udps.src2dst_min_clumps_size, 1)
        self.assertEqual(flow_at_test.udps.src2dst_mean_clumps_size, 1)
        self.assertEqual(flow_at_test.udps.src2dst_stddev_clumps_size, 0)
        self.assertEqual(flow_at_test.udps.src2dst_skewness_clumps_size, 0)
        self.assertEqual(flow_at_test.udps.src2dst_variance_clumps_size, 0)
        self.assertEqual(flow_at_test.udps.src2dst_kurtosis_clumps_size, 0)

        self.assertEqual(flow_at_test.udps.src2dst_max_clumps_bytes_per_packet, 98)
        self.assertEqual(flow_at_test.udps.src2dst_min_clumps_bytes_per_packet, 98)
        self.assertEqual(flow_at_test.udps.src2dst_mean_clumps_bytes_per_packet, 98)
        self.assertEqual(flow_at_test.udps.src2dst_stddev_clumps_bytes_per_packet, 0)
        self.assertEqual(flow_at_test.udps.src2dst_skewness_clumps_bytes_per_packet, 0)
        self.assertEqual(flow_at_test.udps.src2dst_variance_clumps_bytes_per_packet, 0)
        self.assertEqual(flow_at_test.udps.src2dst_kurtosis_clumps_bytes_per_packet, 0)

        self.assertEqual(flow_at_test.udps.src2dst_max_clumps_interarrival_time, 44952.0)
        self.assertEqual(flow_at_test.udps.src2dst_min_clumps_interarrival_time, 0.0)
        self.assertEqual(flow_at_test.udps.src2dst_mean_clumps_interarrival_time, 33690.0)
        self.assertEqual(flow_at_test.udps.src2dst_stddev_clumps_interarrival_time, 22460.031715620233)
        self.assertEqual(flow_at_test.udps.src2dst_skewness_clumps_interarrival_time, -1.1546907587693247)
        self.assertEqual(flow_at_test.udps.src2dst_variance_clumps_interarrival_time, 504453024.6666667)
        self.assertEqual(flow_at_test.udps.src2dst_kurtosis_clumps_interarrival_time, -0.666674206180156)

        self.assertEqual(flow_at_test.udps.src2dst_max_clump_len, [98.0,98.0,98.0,98.0])
        self.assertEqual(flow_at_test.udps.src2dst_min_clump_len, [98.0,98.0,98.0,98.0])
        self.assertEqual(flow_at_test.udps.src2dst_mean_clump_len, [98.0,98.0,98.0,98.0])
        self.assertEqual(flow_at_test.udps.src2dst_stddev_clump_len, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.src2dst_skewness_clump_len, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.src2dst_variance_clump_len, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.src2dst_kurtosis_clump_len, [0.0,0.0,0.0,0.0])

        self.assertEqual(flow_at_test.udps.src2dst_max_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.src2dst_min_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.src2dst_mean_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.src2dst_stddev_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.src2dst_skewness_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.src2dst_variance_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.src2dst_kurtosis_clump_interarrival_time, [0.0,0.0,0.0,0.0])

        #dst2src
        self.assertEqual(flow_at_test.udps.dst2src_max_clumps_len, 229)
        self.assertEqual(flow_at_test.udps.dst2src_min_clumps_len, 229)
        self.assertEqual(flow_at_test.udps.dst2src_mean_clumps_len, 229)
        self.assertEqual(flow_at_test.udps.dst2src_stddev_clumps_len, 0)
        self.assertEqual(flow_at_test.udps.dst2src_skewness_clumps_len, 0)
        self.assertEqual(flow_at_test.udps.dst2src_variance_clumps_len, 0)
        self.assertEqual(flow_at_test.udps.dst2src_kurtosis_clumps_len, 0)

        self.assertEqual(flow_at_test.udps.dst2src_max_clumps_size, 1)
        self.assertEqual(flow_at_test.udps.dst2src_min_clumps_size, 1)
        self.assertEqual(flow_at_test.udps.dst2src_mean_clumps_size, 1)
        self.assertEqual(flow_at_test.udps.dst2src_stddev_clumps_size, 0)
        self.assertEqual(flow_at_test.udps.dst2src_skewness_clumps_size, 0)
        self.assertEqual(flow_at_test.udps.dst2src_variance_clumps_size, 0)
        self.assertEqual(flow_at_test.udps.dst2src_kurtosis_clumps_size, 0)

        self.assertEqual(flow_at_test.udps.dst2src_max_clumps_bytes_per_packet, 229)
        self.assertEqual(flow_at_test.udps.dst2src_min_clumps_bytes_per_packet, 229)
        self.assertEqual(flow_at_test.udps.dst2src_mean_clumps_bytes_per_packet, 229)
        self.assertEqual(flow_at_test.udps.dst2src_stddev_clumps_bytes_per_packet, 0)
        self.assertEqual(flow_at_test.udps.dst2src_skewness_clumps_bytes_per_packet, 0)
        self.assertEqual(flow_at_test.udps.dst2src_variance_clumps_bytes_per_packet, 0)
        self.assertEqual(flow_at_test.udps.dst2src_kurtosis_clumps_bytes_per_packet, 0)

        self.assertEqual(flow_at_test.udps.dst2src_max_clumps_interarrival_time, 132.0)
        self.assertEqual(flow_at_test.udps.dst2src_min_clumps_interarrival_time, 63.0)
        self.assertEqual(flow_at_test.udps.dst2src_mean_clumps_interarrival_time, 82.5)
        self.assertEqual(flow_at_test.udps.dst2src_stddev_clumps_interarrival_time, 33.090784215548595)
        self.assertEqual(flow_at_test.udps.dst2src_skewness_clumps_interarrival_time, 1.1357582101135595)
        self.assertEqual(flow_at_test.udps.dst2src_variance_clumps_interarrival_time, 1095.0)
        self.assertEqual(flow_at_test.udps.dst2src_kurtosis_clumps_interarrival_time, -0.6812084818915367)

        self.assertEqual(flow_at_test.udps.dst2src_max_clump_len, [229.0,229.0,229.0,229.0])
        self.assertEqual(flow_at_test.udps.dst2src_min_clump_len, [229.0,229.0,229.0,229.0])
        self.assertEqual(flow_at_test.udps.dst2src_mean_clump_len, [229.0,229.0,229.0,229.0])
        self.assertEqual(flow_at_test.udps.dst2src_stddev_clump_len, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_skewness_clump_len, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_variance_clump_len, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_kurtosis_clump_len, [0.0,0.0,0.0,0.0])

        self.assertEqual(flow_at_test.udps.dst2src_max_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_min_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_mean_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_stddev_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_skewness_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_variance_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_kurtosis_clump_interarrival_time, [0.0,0.0,0.0,0.0])

        #bidirectional
        self.assertEqual(flow_at_test.udps.max_clumps_len, 229)
        self.assertEqual(flow_at_test.udps.min_clumps_len,98)
        self.assertEqual(flow_at_test.udps.mean_clumps_len, 163.5)
        self.assertEqual(flow_at_test.udps.stddev_clumps_len,70.02244538105519)
        self.assertEqual(flow_at_test.udps.skewness_clumps_len,0)
        self.assertEqual(flow_at_test.udps.variance_clumps_len,4903.142857142857)
        self.assertEqual(flow_at_test.udps.kurtosis_clumps_len,-2.0)

        self.assertEqual(flow_at_test.udps.max_clumps_size,1)
        self.assertEqual(flow_at_test.udps.min_clumps_size,1)
        self.assertEqual(flow_at_test.udps.mean_clumps_size,1)
        self.assertEqual(flow_at_test.udps.stddev_clumps_size,0)
        self.assertEqual(flow_at_test.udps.skewness_clumps_size,0)
        self.assertEqual(flow_at_test.udps.variance_clumps_size,0)
        self.assertEqual(flow_at_test.udps.kurtosis_clumps_size,0)

        self.assertEqual(flow_at_test.udps.max_clumps_bytes_per_packet,229)
        self.assertEqual(flow_at_test.udps.min_clumps_bytes_per_packet,98)
        self.assertEqual(flow_at_test.udps.mean_clumps_bytes_per_packet,163.5)
        self.assertEqual(flow_at_test.udps.stddev_clumps_bytes_per_packet,70.02244538105519)
        self.assertEqual(flow_at_test.udps.skewness_clumps_bytes_per_packet,0)
        self.assertEqual(flow_at_test.udps.variance_clumps_bytes_per_packet,4903.142857142857)
        self.assertEqual(flow_at_test.udps.kurtosis_clumps_bytes_per_packet,-2.0)

        self.assertEqual(flow_at_test.udps.max_clumps_interarrival_time, 44952.0)
        self.assertEqual(flow_at_test.udps.min_clumps_interarrival_time, 0.0)
        self.assertEqual(flow_at_test.udps.mean_clumps_interarrival_time, 16886.25)
        self.assertEqual(flow_at_test.udps.stddev_clumps_interarrival_time, 23214.190461562823)
        self.assertEqual(flow_at_test.udps.skewness_clumps_interarrival_time, 0.516394118239571)
        self.assertEqual(flow_at_test.udps.variance_clumps_interarrival_time, 538898638.7857143)
        self.assertEqual(flow_at_test.udps.kurtosis_clumps_interarrival_time, -1.733322411845363)

        self.assertEqual(flow_at_test.udps.max_clump_len, [98.0,229.0,98.0,229.0,98.0,229.0,98.0,229.0])
        self.assertEqual(flow_at_test.udps.min_clump_len, [98.0,229.0,98.0,229.0,98.0,229.0,98.0,229.0])
        self.assertEqual(flow_at_test.udps.mean_clump_len, [98.0,229.0,98.0,229.0,98.0,229.0,98.0,229.0])
        self.assertEqual(flow_at_test.udps.stddev_clump_len, [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.skewness_clump_len, [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.variance_clump_len, [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.kurtosis_clump_len, [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0])

        self.assertEqual(flow_at_test.udps.max_clump_interarrival_time, [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.min_clump_interarrival_time, [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.mean_clump_interarrival_time, [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.stddev_clump_interarrival_time, [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.skewness_clump_interarrival_time, [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.variance_clump_interarrival_time, [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.kurtosis_clump_interarrival_time, [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0])

    def test_clump_flow_2(self):
        # Given
        pcap_filepath = './pcaps/tls_small_pkt_payload_ratio_single.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=self.plugins)
        # When
        flows = list(streamer) # read streams/flows streamer
        # Then
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')
        
        #src2dst
        self.assertEqual(flow_at_test.udps.src2dst_max_clumps_len, 828.0)
        self.assertEqual(flow_at_test.udps.src2dst_min_clumps_len, 66.0)
        self.assertEqual(flow_at_test.udps.src2dst_mean_clumps_len, 503.5)
        self.assertEqual(flow_at_test.udps.src2dst_stddev_clumps_len, 322.2530061923395)
        self.assertEqual(flow_at_test.udps.src2dst_skewness_clumps_len, -0.5495140751181137)
        self.assertEqual(flow_at_test.udps.src2dst_variance_clumps_len, 103847.0)
        self.assertEqual(flow_at_test.udps.src2dst_kurtosis_clumps_len, -1.0241700487087126)

        self.assertEqual(flow_at_test.udps.src2dst_max_clumps_size, 4.0)
        self.assertEqual(flow_at_test.udps.src2dst_min_clumps_size, 1)
        self.assertEqual(flow_at_test.udps.src2dst_mean_clumps_size, 2.25)
        self.assertEqual(flow_at_test.udps.src2dst_stddev_clumps_size, 1.2583057392117916)
        self.assertEqual(flow_at_test.udps.src2dst_skewness_clumps_size, 0.6520236646847543)
        self.assertEqual(flow_at_test.udps.src2dst_variance_clumps_size, 1.583333333333333)
        self.assertEqual(flow_at_test.udps.src2dst_kurtosis_clumps_size, -0.9030470914127426)

        self.assertEqual(flow_at_test.udps.src2dst_max_clumps_bytes_per_packet, 414.0)
        self.assertEqual(flow_at_test.udps.src2dst_min_clumps_bytes_per_packet, 66.0)
        self.assertEqual(flow_at_test.udps.src2dst_mean_clumps_bytes_per_packet, 229.0625)
        self.assertEqual(flow_at_test.udps.src2dst_stddev_clumps_bytes_per_packet, 162.1149765598478)
        self.assertEqual(flow_at_test.udps.src2dst_skewness_clumps_bytes_per_packet, 0.12668917827875245)
        self.assertEqual(flow_at_test.udps.src2dst_variance_clumps_bytes_per_packet, 26281.265625000004)
        self.assertEqual(flow_at_test.udps.src2dst_kurtosis_clumps_bytes_per_packet, -1.6820327141898344)

        self.assertEqual(flow_at_test.udps.src2dst_max_clumps_interarrival_time, 9.0)
        self.assertEqual(flow_at_test.udps.src2dst_min_clumps_interarrival_time, 0.0)
        self.assertEqual(flow_at_test.udps.src2dst_mean_clumps_interarrival_time, 2.25)
        self.assertEqual(flow_at_test.udps.src2dst_stddev_clumps_interarrival_time, 4.5)
        self.assertEqual(flow_at_test.udps.src2dst_skewness_clumps_interarrival_time, 1.1547005383792515)
        self.assertEqual(flow_at_test.udps.src2dst_variance_clumps_interarrival_time, 20.25)
        self.assertEqual(flow_at_test.udps.src2dst_kurtosis_clumps_interarrival_time, -0.6666666666666665)

        self.assertEqual(flow_at_test.udps.src2dst_max_clump_len, [66.0,571.0,723.0,173.0])
        self.assertEqual(flow_at_test.udps.src2dst_min_clump_len, [66.0,54.0,105.0,104.0])
        self.assertEqual(flow_at_test.udps.src2dst_mean_clump_len, [66.0,312.5,414.0,123.75])
        self.assertEqual(flow_at_test.udps.src2dst_stddev_clump_len, [0.0,365.57420587344507,436.9919907732864,32.92795165205391])
        self.assertEqual(flow_at_test.udps.src2dst_skewness_clump_len, [0.0,0.0,0.0,1.1346721570685077])
        self.assertEqual(flow_at_test.udps.src2dst_variance_clump_len, [0.0,133644.5,190962.0,1084.25])
        self.assertEqual(flow_at_test.udps.src2dst_kurtosis_clump_len, [0.0,-2.0,-2.0,-0.6814517653222136])

        self.assertEqual(flow_at_test.udps.src2dst_max_clump_interarrival_time, [0.0,4.0,2.0,1.0])
        self.assertEqual(flow_at_test.udps.src2dst_min_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.src2dst_mean_clump_interarrival_time, [0.0,2.0,1.0,0.25])
        self.assertEqual(flow_at_test.udps.src2dst_stddev_clump_interarrival_time, [0.0,2.8284271247461903,1.4142135623730951,0.5])
        self.assertEqual(flow_at_test.udps.src2dst_skewness_clump_interarrival_time, [0.0,0.0,0.0,1.1547005383792515])
        self.assertEqual(flow_at_test.udps.src2dst_variance_clump_interarrival_time, [0.0,8.0,2.0,0.25])
        self.assertEqual(flow_at_test.udps.src2dst_kurtosis_clump_interarrival_time, [0.0,-2.0,-2.0,-0.6666666666666665])

        
        #dst2src
        self.assertEqual(flow_at_test.udps.dst2src_max_clumps_len, 320.0)
        self.assertEqual(flow_at_test.udps.dst2src_min_clumps_len, 66.0)
        self.assertEqual(flow_at_test.udps.dst2src_mean_clumps_len, 172.25)
        self.assertEqual(flow_at_test.udps.dst2src_stddev_clumps_len, 112.19737073568169)
        self.assertEqual(flow_at_test.udps.dst2src_skewness_clumps_len, 0.48303687368319326)
        self.assertEqual(flow_at_test.udps.dst2src_variance_clumps_len, 12588.25)
        self.assertEqual(flow_at_test.udps.dst2src_kurtosis_clumps_len, -1.2574291459307467)

        self.assertEqual(flow_at_test.udps.dst2src_max_clumps_size, 2.0)
        self.assertEqual(flow_at_test.udps.dst2src_min_clumps_size, 1)
        self.assertEqual(flow_at_test.udps.dst2src_mean_clumps_size, 1.5)
        self.assertEqual(flow_at_test.udps.dst2src_stddev_clumps_size, 0.5773502691896257)
        self.assertEqual(flow_at_test.udps.dst2src_skewness_clumps_size,  5.551115123125783e-17)
        self.assertEqual(flow_at_test.udps.dst2src_variance_clumps_size, 0.3333333333333333)
        self.assertEqual(flow_at_test.udps.dst2src_kurtosis_clumps_size, -2.0)

        self.assertEqual(flow_at_test.udps.dst2src_max_clumps_bytes_per_packet, 195.0)
        self.assertEqual(flow_at_test.udps.dst2src_min_clumps_bytes_per_packet, 54.0)
        self.assertEqual(flow_at_test.udps.dst2src_mean_clumps_bytes_per_packet, 118.75)
        self.assertEqual(flow_at_test.udps.dst2src_stddev_clumps_bytes_per_packet, 69.5)
        self.assertEqual(flow_at_test.udps.dst2src_skewness_clumps_bytes_per_packet, 0.10922411230601688)
        self.assertEqual(flow_at_test.udps.dst2src_variance_clumps_bytes_per_packet, 4830.25)
        self.assertEqual(flow_at_test.udps.dst2src_kurtosis_clumps_bytes_per_packet, -1.8185859617430495)

        self.assertEqual(flow_at_test.udps.dst2src_max_clumps_interarrival_time, 150.0)
        self.assertEqual(flow_at_test.udps.dst2src_min_clumps_interarrival_time, 145.0)
        self.assertEqual(flow_at_test.udps.dst2src_mean_clumps_interarrival_time, 147.25)
        self.assertEqual(flow_at_test.udps.dst2src_stddev_clumps_interarrival_time, 2.217355782608343)
        self.assertEqual(flow_at_test.udps.dst2src_skewness_clumps_interarrival_time, 0.2780305556539614)
        self.assertEqual(flow_at_test.udps.dst2src_variance_clumps_interarrival_time, 4.916666666666658)
        self.assertEqual(flow_at_test.udps.dst2src_kurtosis_clumps_interarrival_time, -1.4266015512783659)

        self.assertEqual(flow_at_test.udps.dst2src_max_clump_len, [66.0,195.0,266.0,54.0])
        self.assertEqual(flow_at_test.udps.dst2src_min_clump_len, [66.0,195.0,54.0,54.0])
        self.assertEqual(flow_at_test.udps.dst2src_mean_clump_len, [66.0,195.0,160.0,54.0])
        self.assertEqual(flow_at_test.udps.dst2src_stddev_clump_len, [0.0,0.0,149.90663761154806,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_skewness_clump_len, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_variance_clump_len, [0.0,0.0,22472.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_kurtosis_clump_len, [0.0,0.0,-2.0,0.0])

        self.assertEqual(flow_at_test.udps.dst2src_max_clump_interarrival_time, [0.0,0.0,1.0,4.0])
        self.assertEqual(flow_at_test.udps.dst2src_min_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_mean_clump_interarrival_time, [0.0,0.0,0.5,2.0])
        self.assertEqual(flow_at_test.udps.dst2src_stddev_clump_interarrival_time, [0.0,0.0,0.7071067811865476,2.8284271247461903])
        self.assertEqual(flow_at_test.udps.dst2src_skewness_clump_interarrival_time, [0.0,0.0,0.0,0.0])
        self.assertEqual(flow_at_test.udps.dst2src_variance_clump_interarrival_time, [0.0,0.0,0.5,8.0])
        self.assertEqual(flow_at_test.udps.dst2src_kurtosis_clump_interarrival_time, [0.0,0.0,-2.0,-2.0])

        #bidirectional
        self.assertEqual(flow_at_test.udps.max_clumps_len, 828.0)
        self.assertEqual(flow_at_test.udps.min_clumps_len, 66.0)
        self.assertEqual(flow_at_test.udps.mean_clumps_len, 337.875)
        self.assertEqual(flow_at_test.udps.stddev_clumps_len, 285.0460802346576)
        self.assertEqual(flow_at_test.udps.skewness_clumps_len, 0.5936481089832953)
        self.assertEqual(flow_at_test.udps.variance_clumps_len, 81251.26785714286)
        self.assertEqual(flow_at_test.udps.kurtosis_clumps_len, -1.0401259818440216)

        self.assertEqual(flow_at_test.udps.max_clumps_size, 4.0)
        self.assertEqual(flow_at_test.udps.min_clumps_size, 1)
        self.assertEqual(flow_at_test.udps.mean_clumps_size, 1.875)
        self.assertEqual(flow_at_test.udps.stddev_clumps_size, 0.991031208965115)
        self.assertEqual(flow_at_test.udps.skewness_clumps_size, 1.1914950296623115)
        self.assertEqual(flow_at_test.udps.variance_clumps_size, 0.9821428571428573)
        self.assertEqual(flow_at_test.udps.kurtosis_clumps_size, 0.7490909090909086)

        self.assertEqual(flow_at_test.udps.max_clumps_bytes_per_packet, 414.0)
        self.assertEqual(flow_at_test.udps.min_clumps_bytes_per_packet, 54.0)
        self.assertEqual(flow_at_test.udps.mean_clumps_bytes_per_packet, 173.90625)
        self.assertEqual(flow_at_test.udps.stddev_clumps_bytes_per_packet, 129.65461932573015)
        self.assertEqual(flow_at_test.udps.skewness_clumps_bytes_per_packet, 0.8510770040087812)
        self.assertEqual(flow_at_test.udps.variance_clumps_bytes_per_packet, 16810.3203125)
        self.assertEqual(flow_at_test.udps.kurtosis_clumps_bytes_per_packet, -0.5871121114366313)

        self.assertEqual(flow_at_test.udps.max_clumps_interarrival_time, 150.0)
        self.assertEqual(flow_at_test.udps.min_clumps_interarrival_time, 0.0)
        self.assertEqual(flow_at_test.udps.mean_clumps_interarrival_time, 74.75000000000001)
        self.assertEqual(flow_at_test.udps.stddev_clumps_interarrival_time, 77.57530903211776)
        self.assertEqual(flow_at_test.udps.skewness_clumps_interarrival_time, -0.003180981731713864)
        self.assertEqual(flow_at_test.udps.variance_clumps_interarrival_time, 6017.928571428572)
        self.assertEqual(flow_at_test.udps.kurtosis_clumps_interarrival_time, -1.9931840217663834)

        self.assertEqual(flow_at_test.udps.max_clump_len, [66.0, 66.0, 571.0, 195.0, 723.0, 266.0, 173.0, 54.0])
        self.assertEqual(flow_at_test.udps.min_clump_len, [66.0, 66.0, 54.0, 195.0, 105.0, 54.0, 104.0, 54.0])
        self.assertEqual(flow_at_test.udps.mean_clump_len, [66.0, 66.0, 312.5, 195.0, 414.0, 160.0, 123.75, 54.0])
        self.assertEqual(flow_at_test.udps.stddev_clump_len, [0.0, 0.0, 365.57420587344507, 0.0, 436.9919907732864, 149.90663761154806, 32.92795165205391, 0.0])
        self.assertEqual(flow_at_test.udps.skewness_clump_len, [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.1346721570685077, 0.0])
        self.assertEqual(flow_at_test.udps.variance_clump_len, [0.0, 0.0, 133644.5, 0.0, 190962.0, 22472.0, 1084.25, 0.0])
        self.assertEqual(flow_at_test.udps.kurtosis_clump_len, [0.0, 0.0, -2.0, 0.0, -2.0, -2.0, -0.6814517653222136, 0.0])

        self.assertEqual(flow_at_test.udps.max_clump_interarrival_time, [0.0, 0.0, 4.0, 0.0, 2.0, 1.0, 1.0, 4.0])
        self.assertEqual(flow_at_test.udps.min_clump_interarrival_time, [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
        self.assertEqual(flow_at_test.udps.mean_clump_interarrival_time, [0.0, 0.0, 2.0, 0.0, 1.0, 0.5, 0.25, 2.0])
        self.assertEqual(flow_at_test.udps.stddev_clump_interarrival_time, [0.0, 0.0, 2.8284271247461903, 0.0, 1.4142135623730951, 0.7071067811865476, 0.5, 2.8284271247461903])
        self.assertEqual(flow_at_test.udps.skewness_clump_interarrival_time, [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.1547005383792515, 0.0])
        self.assertEqual(flow_at_test.udps.variance_clump_interarrival_time, [0.0, 0.0, 8.0, 0.0, 2.0, 0.5, 0.25, 8.0])
        self.assertEqual(flow_at_test.udps.kurtosis_clump_interarrival_time, [0.0, 0.0, -2.0, 0.0, -2.0, -2.0, -0.6666666666666665, -2.0])



class TestPacketsSizeInterarrivalTimePlugin(unittest.TestCase):

    def setUp(self):
        self.plugins = [Packets_size_and_interarrival_time()]
    
    def test_packets_size_and_interarrival_time_1(self):
        # Given
        pcap_filepath = './pcaps/tls_pkt_rel_time_single.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=self.plugins)
        # When
        flows = list(streamer) # read streams/flows streamer
        # Then
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')

        #Packets Size
        self.assertEqual(flow_at_test.udps.packets_size_min, 98.0)
        self.assertEqual(flow_at_test.udps.packets_size_max, 229.0)
        self.assertEqual(flow_at_test.udps.packets_size_stddev, 70.02244538105519)
        self.assertEqual(flow_at_test.udps.packets_size_first_quartile, 98.0)
        self.assertEqual(flow_at_test.udps.packets_size_second_quartile, 163.5)
        self.assertEqual(flow_at_test.udps.packets_size_third_quartile, 229.0)
        self.assertEqual(flow_at_test.udps.packets_size_mean, 163.5)
        self.assertEqual(flow_at_test.udps.packets_size_median_absoulte_deviation, 65.5)
        self.assertEqual(flow_at_test.udps.packets_size_variance, 4903.142857142857)
        self.assertEqual(flow_at_test.udps.packets_size_skewness, 0.0)
        self.assertEqual(flow_at_test.udps.packets_size_kurtosis, -2.0)
        self.assertEqual(flow_at_test.udps.packets_size_sum, 1308.0)
        
        #Packets Interarrival Time 
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_min, 0.0)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_max, 44952.0)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_stddev, 23214.190461562823)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_first_quartile, 64.5)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_second_quartile, 100.5)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_third_quartile, 44904.0)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_mean, 16886.25)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_median_absoulte_deviation, 69.0)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_variance, 538898638.7857143)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_skewness, 0.516394118239571)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_kurtosis, -1.733322411845363)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_sum, 135090.0)

    def test_packets_size_and_interarrival_time_2(self):
        # Given
        pcap_filepath = './pcaps/tls_small_pkt_payload_ratio_single.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=self.plugins)
        # When
        flows = list(streamer) # read streams/flows streamer
        # Then
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')

        #Packets Size
        self.assertEqual(flow_at_test.udps.packets_size_min, 54.0)
        self.assertEqual(flow_at_test.udps.packets_size_max, 723.0)
        self.assertEqual(flow_at_test.udps.packets_size_stddev, 201.13613016348617)
        self.assertEqual(flow_at_test.udps.packets_size_first_quartile, 60.0)
        self.assertEqual(flow_at_test.udps.packets_size_second_quartile, 105.0)
        self.assertEqual(flow_at_test.udps.packets_size_third_quartile, 184.0)
        self.assertEqual(flow_at_test.udps.packets_size_mean, 180.20000000000002)
        self.assertEqual(flow_at_test.udps.packets_size_median_absoulte_deviation, 51.0)
        self.assertEqual(flow_at_test.udps.packets_size_variance, 40455.74285714285)
        self.assertEqual(flow_at_test.udps.packets_size_skewness, 1.8866361368697218)
        self.assertEqual(flow_at_test.udps.packets_size_kurtosis, 2.2211745099976588)
        self.assertEqual(flow_at_test.udps.packets_size_sum, 2703)
        
        #Packets Interarrival Time 
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_min, 0.0)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_max, 150.0)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_stddev, 66.57827473483124)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_first_quartile, 0.0)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_second_quartile, 2.0)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_third_quartile, 77.0)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_mean, 40.666666666666664)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_median_absoulte_deviation, 2.0)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_variance, 4432.666666666667)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_skewness, 1.051871352384891)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_kurtosis, -0.8862335514542248)
        self.assertEqual(flow_at_test.udps.packets_interarrival_time_sum, 610.0)



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
        # TODO: read a file with a single flow, as multiprocessing by n_meters can reorder the flows
        # Given
        plugins = [DNSCounter()]
        pcap_filepath = './pcaps/dns_1.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=plugins, n_meters=1)
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
        self.assertEqual(flow_at_test.udps.bidirectional_dns_response_ttls_s, [3158, 23, 3]) # in seconds
        self.assertEqual(flow_at_test.udps.bidirectional_median_dns_response_ttls_s, 23)
        self.assertEqual(flow_at_test.udps.bidirectional_mean_dns_response_digit_count, 1)
        self.assertEqual(flow_at_test.udps.bidirectional_mean_dns_response_alpha_count, 93)
        self.assertEqual(flow_at_test.udps.bidirectional_mean_dns_response_hypens_count, 8)
        self.assertEqual(flow_at_test.udps.bidirectional_mean_dns_response_dots_count, 9)
        self.assertEqual(flow_at_test.udps.bidirectional_mean_dns_response_ip_count, 1)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_mean_dns_response_ttls_s, 1061.333, 3)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_stdev_dns_response_ttls_s, 1482.5897, 3)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_variance_dns_response_ttls_s, 2198072.2222, 3)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_coeff_of_var_dns_response_ttls_s, 1.3969, 3)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_skew_from_median_dns_response_ttls_s, 2.101, 3)
        self.assertEqual(flow_at_test.udps.bidirectional_min_dns_response_ttls_s, 3)
        self.assertEqual(flow_at_test.udps.bidirectional_max_dns_response_ttls_s, 3158)
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
        self.assertEqual(flow_at_test.udps.src2dst_dns_response_ttls_s, None) # in seconds
        self.assertEqual(flow_at_test.udps.src2dst_mean_dns_response_ttls_s, None)
        self.assertEqual(flow_at_test.udps.src2dst_stdev_dns_response_ttls_s, None)
        self.assertEqual(flow_at_test.udps.src2dst_variance_dns_response_ttls_s, None)
        self.assertEqual(flow_at_test.udps.src2dst_coeff_of_var_dns_response_ttls_s, None)
        self.assertEqual(flow_at_test.udps.src2dst_skew_from_median_dns_response_ttls_s, None)
        self.assertEqual(flow_at_test.udps.src2dst_min_dns_response_ttls_s, None)
        self.assertEqual(flow_at_test.udps.src2dst_max_dns_response_ttls_s, None)
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
        self.assertEqual(flow_at_test.udps.dst2src_dns_response_ttls_s, [3158, 23, 3]) # in seconds
        self.assertAlmostEqual(flow_at_test.udps.dst2src_mean_dns_response_ttls_s, 1061.333, 3)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_stdev_dns_response_ttls_s, 1482.5897, 3)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_variance_dns_response_ttls_s, 2198072.2222, 3)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_coeff_of_var_dns_response_ttls_s, 1.3969, 3)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_skew_from_median_dns_response_ttls_s, 2.101, 3)
        self.assertEqual(flow_at_test.udps.dst2src_min_dns_response_ttls_s, 3)
        self.assertEqual(flow_at_test.udps.dst2src_max_dns_response_ttls_s, 3158)

class TestMostFreqPayloadRatio(unittest.TestCase):

    def test_most_freq_payload_ratio_1(self):
        # Given
        plugins = [MostFreqPayloadLenRatio()]
        pcap_filepath = './pcaps/http_most_freq_payload_ratio_single.pcap'
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
        self.assertEqual(flow_at_test.udps.dst2src_most_freq_payload_len, 
                        0)
        self.assertEqual(flow_at_test.udps.src2dst_most_freq_payload_len, 
                        0)


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
        self.assertEqual(flow_at_test.udps.src2dst_small_packet_payload_packets, 
                        2)
        self.assertEqual(flow_at_test.udps.dst2src_small_packet_payload_ratio, 
                        4/6)
        self.assertEqual(flow_at_test.udps.dst2src_small_packet_payload_packets, 
                        4)


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
        # bidirectional
        self.assertEqual(flow_at_test.udps.bidirectional_packet_relative_times, 
                        [0, 132, 44999, 45065, 90006, 90075, 135027, 135090])
        self.assertEqual(flow_at_test.udps.bidirectional_min_packet_relative_times,  0)
        self.assertEqual(flow_at_test.udps.bidirectional_max_packet_relative_times, 135090)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_mean_packet_relative_times, 67549.25)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_stddev_packet_relative_times , 50309.985012296514)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_variance_packet_relative_times, 2531094591.9375)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_coeff_of_var_packet_relative_times, 0.7447896906671)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_skew_from_median_packet_relative_times, 0.0008199167)
        # src -> dst
        self.assertEqual(flow_at_test.udps.src2dst_packet_relative_times, 
                        [0, 44999, 90006, 135027])
        self.assertEqual(flow_at_test.udps.src2dst_min_packet_relative_times,  0)
        self.assertEqual(flow_at_test.udps.src2dst_max_packet_relative_times, 135027)
        self.assertAlmostEqual(flow_at_test.udps.src2dst_mean_packet_relative_times, 67508)
        self.assertAlmostEqual(flow_at_test.udps.src2dst_stddev_packet_relative_times , 50321.36849788)
        self.assertAlmostEqual(flow_at_test.udps.src2dst_variance_packet_relative_times, 2532240127.5)
        self.assertAlmostEqual(flow_at_test.udps.src2dst_coeff_of_var_packet_relative_times, 0.745413410231)
        self.assertAlmostEqual(flow_at_test.udps.src2dst_skew_from_median_packet_relative_times, 0.0003278925135)
        # dst -> src
        self.assertEqual(flow_at_test.udps.dst2src_packet_relative_times, 
                        [132, 45065, 90075, 135090])
        self.assertEqual(flow_at_test.udps.dst2src_min_packet_relative_times,  132)
        self.assertEqual(flow_at_test.udps.dst2src_max_packet_relative_times, 135090)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_mean_packet_relative_times, 67590.5)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_stddev_packet_relative_times , 50298.565121184)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_variance_packet_relative_times, 2529945653.25)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_coeff_of_var_packet_relative_times, 0.7441661937)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_skew_from_median_packet_relative_times, 0.0012226988)
        


class TestByteFrequencyPlugin(unittest.TestCase):

    def test_byte_frequency_1(self):
        # Given
        plugins = [NPacketsByteFrequency(n_first_packets=1)]
        pcap_filepath = './pcaps/tls_pkt_rel_time_single.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=plugins)
        # When
        flows = list(streamer) # read streams/flows streamer
        # Then
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')
        
        self.assertEqual(flow_at_test.udps.n_packets_byte_frequency_value, 1)
        self.assertEqual(list(flow_at_test.udps.bidirectional_n_packets_byte_frequency), 
            [
                1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1,
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1,
                1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
                0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0,
                0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0,
                1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0
            ]
        )
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_mean_n_packets_byte_distribution, 106.52380952) 
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_stdev_n_packets_byte_distribution, 76.95594640) 
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_median_n_packets_byte_distribution, 97)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_variance_n_packets_byte_distribution, 5922.217687074)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_coeff_of_var_n_packets_byte_distribution, 0.7224295371)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_skew_from_median_n_packets_byte_distribution, 0.3712699265)
        self.assertEqual(list(flow_at_test.udps.src2dst_n_packets_byte_frequency), 
            [
                1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1,
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1,
                1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
                0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0,
                0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0,
                1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0
            ]
        )
        self.assertAlmostEqual(flow_at_test.udps.src2dst_mean_n_packets_byte_distribution, 106.52380952) 
        self.assertAlmostEqual(flow_at_test.udps.src2dst_stdev_n_packets_byte_distribution, 76.95594640) 
        self.assertAlmostEqual(flow_at_test.udps.src2dst_median_n_packets_byte_distribution, 97)
        self.assertAlmostEqual(flow_at_test.udps.src2dst_variance_n_packets_byte_distribution, 5922.217687074)
        self.assertAlmostEqual(flow_at_test.udps.src2dst_coeff_of_var_n_packets_byte_distribution, 0.7224295371)
        self.assertAlmostEqual(flow_at_test.udps.src2dst_skew_from_median_n_packets_byte_distribution, 0.3712699265)
        self.assertEqual(list(flow_at_test.udps.dst2src_n_packets_byte_frequency), 
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        )
        self.assertAlmostEqual(flow_at_test.udps.dst2src_mean_n_packets_byte_distribution, 0) 
        self.assertAlmostEqual(flow_at_test.udps.dst2src_stdev_n_packets_byte_distribution, 0) 
        self.assertAlmostEqual(flow_at_test.udps.dst2src_median_n_packets_byte_distribution, 0)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_variance_n_packets_byte_distribution, 0)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_coeff_of_var_n_packets_byte_distribution, 0)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_skew_from_median_n_packets_byte_distribution, 0)
        
    def test_byte_frequency_2(self):
        # Given
        plugins = [NPacketsByteFrequency(n_first_packets=2)]
        pcap_filepath = './pcaps/tls_pkt_rel_time_single.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=plugins)
        # When
        flows = list(streamer) # read streams/flows streamer
        # Then
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')
        
        self.assertEqual(flow_at_test.udps.n_packets_byte_frequency_value, 2)
        self.assertEqual(list(flow_at_test.udps.bidirectional_n_packets_byte_frequency), 
            [
                2, 2, 2, 2, 1, 2, 2, 1, 2, 1, 2, 1, 1, 1, 2, 2, 1, 0, 1, 1, 1, 2,
                0, 2, 2, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 2, 0, 2, 1, 0, 1, 1, 1,
                1, 0, 0, 2, 2, 1, 0, 2, 0, 0, 0, 0, 1, 0, 2, 1, 0, 1, 1, 0, 1, 1,
                0, 1, 0, 2, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 1, 1, 2, 2, 0, 2,
                1, 1, 1, 0, 0, 0, 1, 2, 1, 2, 0, 1, 2, 1, 0, 2, 0, 2, 2, 0, 1, 0,
                1, 2, 1, 1, 0, 2, 1, 0, 0, 1, 1, 1, 1, 0, 2, 2, 1, 0, 2, 1, 1, 0,
                2, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 2, 1, 2, 0, 1,
                1, 0, 1, 0, 0, 2, 0, 1, 0, 0, 1, 0, 1, 0, 2, 0, 1, 0, 1, 0, 1, 0,
                0, 1, 0, 1, 1, 2, 1, 0, 0, 0, 2, 2, 0, 2, 1, 0, 2, 1, 0, 0, 0, 0,
                1, 0, 0, 1, 1, 1, 1, 1, 2, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0,
                0, 1, 1, 1, 0, 2, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 2, 1, 0, 0, 0,
                1, 0, 0, 1, 1, 2, 1, 1, 2, 1, 1, 0, 0, 1
            ]
        )
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_mean_n_packets_byte_distribution, 116.31707317) 
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_stdev_n_packets_byte_distribution, 77.0165769) 
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_median_n_packets_byte_distribution, 111)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_variance_n_packets_byte_distribution, 5931.55312314)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_coeff_of_var_n_packets_byte_distribution, 0.66212615)
        self.assertAlmostEqual(flow_at_test.udps.bidirectional_skew_from_median_n_packets_byte_distribution, 0.207114106)
        self.assertEqual(list(flow_at_test.udps.src2dst_n_packets_byte_frequency), 
            [
                1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1,
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1,
                1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
                0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0,
                0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0,
                1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0
            ]
        )
        self.assertAlmostEqual(flow_at_test.udps.src2dst_mean_n_packets_byte_distribution, 106.52380952) 
        self.assertAlmostEqual(flow_at_test.udps.src2dst_stdev_n_packets_byte_distribution, 76.95594640) 
        self.assertAlmostEqual(flow_at_test.udps.src2dst_median_n_packets_byte_distribution, 97)
        self.assertAlmostEqual(flow_at_test.udps.src2dst_variance_n_packets_byte_distribution, 5922.217687074)
        self.assertAlmostEqual(flow_at_test.udps.src2dst_coeff_of_var_n_packets_byte_distribution, 0.7224295371)
        self.assertAlmostEqual(flow_at_test.udps.src2dst_skew_from_median_n_packets_byte_distribution, 0.3712699265)
        self.assertEqual(list(flow_at_test.udps.dst2src_n_packets_byte_frequency), 
            [
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1,
                1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1,
                1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0,
                0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1,
                1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1,
                1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0,
                1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0,
                1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0,
                1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1,
                1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0,
                0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1
            ]
        )
        self.assertAlmostEqual(flow_at_test.udps.dst2src_mean_n_packets_byte_distribution, 120.66197183) 
        self.assertAlmostEqual(flow_at_test.udps.dst2src_stdev_n_packets_byte_distribution, 76.64376046) 
        self.assertAlmostEqual(flow_at_test.udps.dst2src_median_n_packets_byte_distribution, 119)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_variance_n_packets_byte_distribution, 5874.2660186)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_coeff_of_var_n_packets_byte_distribution, 0.63519399944)
        self.assertAlmostEqual(flow_at_test.udps.dst2src_skew_from_median_n_packets_byte_distribution, 0.06505311668)
        
            


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
        self.assertEqual(len(flow_at_test.udps.req_res_time_diff), 43)
        self.assertSequenceEqual(flow_at_test.udps.req_res_time_diff, 
            [
                132, 44867, 66, 44941, 69, 44952, 63, 
                44949, 70, 44941, 65, 44934, 63, 44949, 
                69, 44937, 67, 44947, 68, 44924, 61, 44947, 
                63, 44949, 61, 44943, 64, 44935, 63, 44947, 
                83, 44930, 64, 44938, 65, 44938, 66, 44945, 
                66, 44940, 77, 44931, 61
            ]
        )
        avg = np.average(flow_at_test.udps.req_res_time_diff)
        self.assertAlmostEqual(avg, 21981, delta=1)
        self.assertAlmostEqual(flow_at_test.udps.min_req_res_time_diff, 61)
        self.assertAlmostEqual(flow_at_test.udps.max_req_res_time_diff, 44952)
        self.assertAlmostEqual(flow_at_test.udps.mean_req_res_time_diff, 21981.627906976744)
        self.assertAlmostEqual(flow_at_test.udps.median_req_res_time_diff, 132)
        self.assertAlmostEqual(flow_at_test.udps.stddev_req_res_time_diff, 22427.9231825)
        self.assertAlmostEqual(flow_at_test.udps.variance_req_res_time_diff, 503011738.28015137)
        self.assertAlmostEqual(flow_at_test.udps.coeff_of_var_req_res_time_diff, 1.02030310391)
        self.assertAlmostEqual(flow_at_test.udps.skew_from_median_req_res_time_diff, 2.92264616690)
            
    def test_stream_req_res_diff_time_2(self):
        # Given / Arrange
        pcap_filepath = './pcaps/tls_req_res_diff_time_single_2.pcap'
        streamer = NFStreamer(source=pcap_filepath, udps=self.plugins)
        # When / Act
        flows = list(streamer) # read streams/flows streamer
        # Then / Assert
        flow_at_test = flows[0]
        self.assertLessEqual(len(flows), 1, 'The PCAP test file should contain only a single stream, but contains more.')
        self.assertEqual(len(flow_at_test.udps.req_res_time_diff), 7)
        self.assertSequenceEqual(flow_at_test.udps.req_res_time_diff, [87, 5, 81, 3132, 89, 267, 94])
        avg = np.average(flow_at_test.udps.req_res_time_diff)
        self.assertAlmostEqual(avg, 536, delta=0.5)
        self.assertAlmostEqual(flow_at_test.udps.min_req_res_time_diff, 5)
        self.assertAlmostEqual(flow_at_test.udps.max_req_res_time_diff, 3132)
        self.assertAlmostEqual(flow_at_test.udps.mean_req_res_time_diff, 536.4285714)
        self.assertAlmostEqual(flow_at_test.udps.median_req_res_time_diff, 89)
        self.assertAlmostEqual(flow_at_test.udps.stddev_req_res_time_diff, 1062.163271972)
        self.assertAlmostEqual(flow_at_test.udps.variance_req_res_time_diff, 1128190.8163265)
        self.assertAlmostEqual(flow_at_test.udps.coeff_of_var_req_res_time_diff, 1.98006468809)
        self.assertAlmostEqual(flow_at_test.udps.skew_from_median_req_res_time_diff, 1.2637282324)




if __name__ == '__main__':
    unittest.main()
