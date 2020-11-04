# Writes the collected packages into 'capture.pcap' file
import struct
import time

class Pcap:
    def __init__(self, filename, link_type=1):
        self.file = open(filename, 'wb')
        self.file.write(struct.pack(
            '@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    # performs the write operations on the 'capture.pcap' file
    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.file.write(struct.pack(
            '@ I I I I', ts_sec, ts_usec, length, length))
        self.file.write(data)

    # closes the 'capture.pcap' file to prevent more write operations
    def close(self):
        self.file.close()