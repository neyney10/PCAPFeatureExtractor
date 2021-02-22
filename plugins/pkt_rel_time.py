# used for byte frequency analysis

from nfstream import NFPlugin

class PacketRelativeTime(NFPlugin):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def on_init(self, packet, flow):
        '''
        on_init(self, packet, flow): Method called at flow creation.
        '''
        flow.udps.first_packet_timestamp = packet.time
        flow.udps.packet_relative_times = list()

        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        flow.udps.packet_relative_times.append(packet.time
                                                - flow.udps.first_packet_timestamp)

        
    def on_expire(self, flow):
        # Cleanup
        del flow.udps.first_packet_timestamp

