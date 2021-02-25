from nfstream import NFPlugin
import numpy as np # for bytes distribution

class ResReqDiffTime(NFPlugin):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def on_init(self, packet, flow):
        '''
        on_init(self, packet, flow): Method called at flow creation.
        '''
        flow.udps.req_res_time_diff = list() 
        flow.udps.current_flow_direction = 0 # 0 for forward, 1 for backward
        flow.udps.current_flow_direction_timestamp = packet.time

    def on_update(self, packet, flow):
        if packet.direction != flow.udps.current_flow_direction:
            flow.udps.req_res_time_diff.append(packet.time - flow.udps.current_flow_direction_timestamp)
            flow.udps.current_flow_direction = packet.direction
            flow.udps.current_flow_direction_timestamp = packet.time

    def on_expire(self, flow): 
        # Cleanup
        del flow.udps.current_flow_direction_timestamp
        del flow.udps.current_flow_direction



