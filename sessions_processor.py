class SessionsProcessor:
    def __init__(self) -> None:
        pass
    
    def process(self, df):
        grouped_by_session = df.groupby(lambda f: self._five_tuple(df.iloc[f]))
        
        
        print('Finished processing sessions')


    def _five_tuple(self, flow):
        return '-'.join(
            sorted([
                flow.src_ip,
                str(flow.src_port),
                flow.dst_ip,
                str(flow.dst_port),
                str(flow.protocol)
            ])
        )
        
    def _fill_empty_timed_windows(self, time_windowed_flows):
        '''
        W.I.P
        '''
        previous_window = time_windowed_flows[0]
        for i in range(1, len(time_windowed_flows)):
            current_window = time_windowed_flows[1]
            time_diff = current_window.bidirectional_first_seen_ms - previous_window.bidirectional_last_seen_ms + (1 - previous_window.bidirectional_duration_ms)
    