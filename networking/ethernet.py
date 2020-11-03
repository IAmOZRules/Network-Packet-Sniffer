# Takes in input raw_data
# and outputs the data into understandable chunks

import socket
import struct
from mac import *

class Ethernet:
    def __init__(self, raw_data):

        # unpacks the passed raw_data into destination, source and the prptocol
        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

        # passes the unpacked data and converts to readable format
        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)

        # Converts the prototype from host byte order to network byte order
        self.proto = socket.htons(prototype)

        # data in the ethernet frame after the 14th bit
        self.data = raw_data[14:]