from nfstream import NFStreamer, NFPlugin
import numpy as np
from scapy.all import IP, IPv6, raw

class NBytes(NFPlugin):
    '''
        Extracts the first n_bytes from the flow, the bytes are taken
        from the transport layer payload (L4). if the flow have less than n_bytes bytes,
        then the rest of the bytes are zero-valued.
    '''
    def __init__(self, n=784):
        self.n = n
    
    def on_init(self, packet, flow):
        flow.udps.n_bytes_value = self.n
        flow.udps.n_bytes = np.zeros(self.n)
        flow.udps.n_bytes_counted = 0
        
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if flow.udps.n_bytes is None:
            return
        remaining_bytes = self.n - flow.udps.n_bytes_counted
        if remaining_bytes >= 0 and packet.protocol in [6, 17]:
            amount_to_copy = min(remaining_bytes, packet.payload_size)
            if amount_to_copy == 0:
                return
            max_index_to_copy = -packet.payload_size+amount_to_copy if -packet.payload_size+amount_to_copy != 0 else None
            
            #print(type(remaining_bytes), type(amount_to_copy), type(flow.udps.n_bytes_counted))
            #print(remaining_bytes, amount_to_copy, flow.udps.n_bytes_counted) #packet.ip_packet, np.frombuffer(packet.ip_packet, dtype=np.uint8))
            #print(-packet.payload_size, max_index_to_copy, len(self.get_payload_as_binary(packet, flow.ip_version)))
            #print(flow.udps.n_bytes[flow.udps.n_bytes_counted:flow.udps.n_bytes_counted+amount_to_copy])
            #print(packet.ip_packet[-packet.payload_size:max_index_to_copy])
            #print(np.frombuffer(packet.ip_packet[-packet.payload_size:max_index_to_copy], dtype=np.uint8))
            rawb = self.get_payload_as_binary(packet, flow.ip_version)
            if len(rawb) != packet.payload_size:
                flow.udps.n_bytes = None
                return
            flow.udps.n_bytes[flow.udps.n_bytes_counted:flow.udps.n_bytes_counted+amount_to_copy] = np.frombuffer(rawb[-packet.payload_size:max_index_to_copy], dtype=np.uint8)
            flow.udps.n_bytes_counted += amount_to_copy

    def on_expire(self, flow):
        if flow.udps.n_bytes is not None:
            flow.udps.n_bytes /= 255
            flow.udps.n_bytes = list(flow.udps.n_bytes)
        # optional: del flow.udps.n_bytes_counted

    def get_payload_as_binary(self, packet, ip_version):
        if ip_version == 4:
            scapy_packet = IP(packet.ip_packet)
        elif ip_version == 6:
            scapy_packet = IPv6(packet.ip_packet)
        
        return raw(scapy_packet.payload.payload)