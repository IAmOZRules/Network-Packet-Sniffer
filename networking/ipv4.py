# Takes in raw_data, decodes the IP address and returns in formatted manner
import struct

class IPv4:
    def __init__(self, raw_data):

        # sets the pointer at initial position
        version_header_length = raw_data[0]

        # Performs right shift by 4 units to get the IP header length
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4

        # unpacks the TTL, IPv4 protocol, source and target IP addresses
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.ipv4(src)
        self.target = self.ipv4(target)
        self.data = raw_data[self.header_length:]

    def ipv4(self, addr):
        # joins the passed fields and outputs the properly formatted IP address
        return '.'.join(map(str, addr))