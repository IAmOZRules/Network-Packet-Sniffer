# importing all required files/packages
import socket
from mac import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

# defining the tabs
PADDING_1 = '\t - '
PADDING_2 = '\t\t - '
PADDING_3 = '\t\t\t - '
PADDING_4 = '\t\t\t\t - '

OUTPUT_PADDING_1 = '\t   '
OUTPUT_PADDING_2 = '\t\t   '
OUTPUT_PADDING_3 = '\t\t\t   '
OUTPUT_PADDING_4 = '\t\t\t\t   '


def main():

    # creates the 'capture.pcap' file
    pcap = Pcap('capture.pcap')

    # captures the network packets
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # while any data is being captured
    while True:

        # receives from port 65535
        data, addr = connection.recvfrom(65535)
        
        # writes the data into the capture.pcap file
        pcap.write(data)

        # Passes the data to ethernet function
        ethernet = Ethernet(data)

        # Prints the ethernet packet information
        print('\nEthernet Frame:')
        print(PADDING_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(
            ethernet.dest_mac, ethernet.src_mac, ethernet.proto))

        # If ethernet protocol is 8, print IPv4 information
        if ethernet.proto == 8:

            # Passes data to IPv4 module
            ip = IPv4(ethernet.data)

            # prints the IPv4 packet information
            print(PADDING_1 + 'IPv4 Packet:')

            print(PADDING_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(
                ip.version, ip.header_length, ip.ttl))

            print(PADDING_2 + 'Protocol: {}, Source: {}, Target: {}'.format(
                ip.proto, ip.src, ip.target))

            # If IP protocol is 1, print ICMP information
            if ip.proto == 1:

                # passes the data to ICMP module
                icmp = ICMP(ip.data)

                # prints the ICMP information
                print(PADDING_1 + 'ICMP Packet:')
                print(PADDING_2 + 'Type: {}, Code: {}, Checksum: {},'.format(
                    icmp.type, icmp.code, icmp.checksum))

                # prints the captured ICMP data
                print(PADDING_2 + 'ICMP Data:')
                print(format_output(OUTPUT_PADDING_3, icmp.data))

            # If IP protocol is 6, print TCP information
            elif ip.proto == 6:

                # passes the data to TCP module
                tcp = TCP(ip.data)

                # prints the TCP information
                print(PADDING_1 + 'TCP Segment:')
                print(PADDING_2 + 'Source Port: {}, Destination Port: {}'.format(
                    tcp.src_port, tcp.dest_port))

                print(PADDING_2 + 'Sequence: {}, Acknowledgment: {}'.format(
                    tcp.seq, tcp.ack))
                
                print(PADDING_2 + 'Flags:')
                
                print(PADDING_3 + 'URG: {}, ACK: {}, PSH: {}'.format(
                    tcp.urg_flag, tcp.ack_flag, tcp.psh_flag))
                
                print(PADDING_3 + 'RST: {}, SYN: {}, FIN:{}'.format(
                    tcp.rst_flag, tcp.syn_flag, tcp.fin_flag))

                # If any data captured over TCP, do
                if len(tcp.data) > 0:

                    # prints information from HTTP if any of source or destination ports is 80
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print(PADDING_2 + 'HTTP Data:')
                        try:

                            # passes data to HTTP module
                            http = HTTP(tcp.data)

                            info_http = str(http.data).split('\n')
                            for line in info_http:
                                print(OUTPUT_PADDING_3 + str(line))
                        except:
                            print(format_output(OUTPUT_PADDING_3, tcp.data))
                    
                    # Print TCP data
                    else:
                        print(PADDING_2 + 'TCP Data:')
                        print(format_output(OUTPUT_PADDING_3, tcp.data))

            # If IP protocol is 17, print UDP information
            elif ip.proto == 17:

                # passes data to UDP module
                udp = UDP(ip.data)

                # prints out UDP information
                print(PADDING_1 + 'UDP Segment:')
                print(PADDING_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(
                    udp.src_port, udp.dest_port, udp.size))

            # prints out information about other IPv4 protocols
            else:
                print(PADDING_1 + 'Other IPv4 Data:')
                print(format_output(OUTPUT_PADDING_2, ip.data))

        else:
            print('Ethernet Data:')
            print(format_output(OUTPUT_PADDING_1, ethernet.data))

    # closes the pcap file to prevent further writes
    pcap.close()

# calls the main function
main()
