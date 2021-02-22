from scapy.all import load_layer
load_layer("tls")

class TLSReassemble:
    ''' 
        Assumes that packets are received in order.
        For out of order packets, need to reorder TCP stream by
        seq/ack.

    '''
    def __init__(self) -> None:
        self.accumulated = 0
        self.last_record_size = 0
        self.last_record_received = None
    
    def process(self, tcp_payload):
        records = list()
        if self.accumulated == 0:
            tls = TLS(tcp_payload)
            payload_size = len(tcp_payload)
            accumulated_payload_size = 0
            i = 0
            while accumulated_payload_size < payload_size:
                record = tls[i]
                record_size = record.len
                received_data_size = record.deciphered_len
                accumulated_payload_size += received_data_size + 5 # 5 is TLS record header len 

                if record_size > received_data_size:
                    self.accumulated += received_data_size
                    self.last_record_size = record_size
                    self.last_record_received = record
                else:
                    records.append(tls[i])
                
                i += 2
        else:
            completing_size = self.last_record_size - self.accumulated
            completing_payload = tcp_payload[:completing_size]
            self.last_record_received.msg[0].data += completing_payload
            records.append(self.last_record_received)
            self.accumulated = 0
            self.last_record_size = 0
            self.last_record_received_data = None

            return records + self.process(tcp_payload[completing_size:])

        return records

            
            

            

            