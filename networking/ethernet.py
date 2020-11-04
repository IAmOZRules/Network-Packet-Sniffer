# Takes in input raw_data
# and outputs the data into understandable chunks

import socket
import struct
from mac import *

class Ethernet:
    def __init__(self, raw_data):

        # unpacks the passed raw_data into destination, source and the prptocol
        dest, src, proto = struct.unpack('! 6s 6s H', raw_data[:14])

        # passes the unpacked data and converts to readable format
        self.dest_mac = return_mac_address(dest)
        self.src_mac = return_mac_address(src)

        # Converts the prototype from host byte order to network byte order
        self.proto = socket.htons(proto)

        # data in the ethernet frame after the 14th bit
        self.data = raw_data[14:]