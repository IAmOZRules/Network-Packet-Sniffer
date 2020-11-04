# captires packet information over ICMP
import struct

class ICMP:
    def __init__(self, raw_data):

        # decodes the ICMP type, code, and checksum
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])

        self.data = raw_data[4:]            # unpacks the ICMP message data