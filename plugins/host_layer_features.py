from nfstream import NFPlugin


class HostLayerFeatures(NFPlugin):
    '''
        EXPERIMENTAL
    
    '''
    def __init__(self, time: float, **kwargs):  # time in seconds
        super().__init__(**kwargs)
        self.time = time
        self.hosts = dict()

    def on_init(self, packet, flow):
        pass

    def on_update(self, packet, flow):
        pass

    def _five_tuple_string_of(self, flow):
        return str.join('',
            sorted([
                flow.src_ip,
                str(flow.src_port),
                flow.dst_ip,
                str(flow.dst_port)]))
        
        
        
class Host:
    def __init__(self, ip: str) -> None:
        self.ip = ip
        # default values
        self.recv_packets = 0
        self.recv_bytes   = 0
        self.sent_packets = 0
        self.sent_bytes
    
    
    def __hash__(self) -> int:
        pass

    def __str__(self) -> str:
        '''
        for debug purposes.
        '''
        
        pass