# Capture data over the TCP frame
import struct

class TCP:
    def __init__(self, raw_data):

        # unpacks the source and destination ports, sequence ID, acknowledgment and the flags
        (self.port_src, self.port_dest, self.seq, self.ack, offset_flag) = struct.unpack(
            '! H H L L H', raw_data[:14])

        # Calculates values of all flags
        offset = (offset_flag >> 12) * 4                # sets the pointer
        self.urg_flag = (offset_flag & 32) >> 5
        self.ack_flag = (offset_flag & 16) >> 4
        self.psh_flag = (offset_flag & 8) >> 3
        self.rst_flag = (offset_flag & 4) >> 2
        self.syn_flag = (offset_flag & 2) >> 1
        self.fin_flag = offset_flag & 1

        # unpacks the TCP data
        self.data = raw_data[offset:]