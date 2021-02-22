from nfstream import NFPlugin
from scapy.all import * # for high layer packet parsing
import numpy as np # for bytes distribution

class UniDirBytes(NFPlugin):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.flows = dict()

    def on_init(self, packet, flow):
        '''
        on_init(self, packet, flow): Method called at flow creation.
        '''
        #flow_id_string = flow.src_ip + flow.dst_ip + str(flow.src_port) + str(flow.dst_port)

        flow.udps.bytes_frequency   = np.zeros(256) # of ip payload onwards
        flow.udps.req_res_time_diff = list() 
        self.current_flow_direction = 0 # 0 for forward, 1 for backward
        self.current_flow_direction_timestamp = packet.time
        
        self.on_update(packet, flow)


    def on_update(self, packet, flow):
       # flow_id_string = flow.src_ip + flow.dst_ip + str(flow.src_port) + str(flow.dst_port)
        
        payload = IP(packet.ip_packet)
        #print('Parsed Packet:', packet[IP].src, packet[IP].dst)

        self._add_payload_bytes_frequency(packet.ip_packet, flow.udps.bytes_frequency)
        if packet.direction != self.current_flow_direction:
            self.current_flow_direction = packet.direction
            flow.udps.req_res_time_diff.append(packet.time - self.current_flow_direction_timestamp)
            self.current_flow_direction_timestamp = packet.time

        if DNSQR in payload:
            payload[DNSQR].qname
        if DNSRR in payload:
            payload[DNSRR].rrname

    def on_expire(self, flow):
        pass
        #flow_id_string = flow.src_ip + flow.dst_ip + str(flow.src_port) + str(flow.dst_port)
        #print(flow_id_string, flow.id, self.flows[flow_id_string], flow.bidirectional_bytes, flow.bidirectional_packets)

    def cleanup(self):
        print("cleanup", self.flows)


    def _add_payload_bytes_frequency(self, payload, container):
        payload_bytes_array = np.frombuffer(payload, dtype='B') # 'B' unsigned byte
        container[payload_bytes_array] += 1