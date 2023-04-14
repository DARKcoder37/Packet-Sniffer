import socket
import struct
import textwrap


# Spacing for proper output
Tab1 = '\t - '
Tab2 = '\t\t - '
Tab3 = '\t\t\t - '
Tab4 = '\t\t\t\t - '

Data_tab1 = '\t '
Data_tab2 = '\t\t '
Data_tab3 = '\t\t\t '
Data_tab4 = '\t\t\t\t '



def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW , socket.ntohs(3))
        
    while True : 
        raw_data , addr = conn.recvfrom(65536)
        dest_mac , src_mac , ether_proto , data = ethernet_frame(raw_data)
        print("\nEthernet Frame : ")
        print(Tab1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac , src_mac , ether_proto))
    
         # ipv4
        if ether_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(Tab1 + 'IPv4 Packet: ')
            print(Tab2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(Tab2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(Tab1 + 'ICMP Packet:')
                print(Tab2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(Tab2 + 'Data:')
                print(format_multi_line(Data_tab3, data))

            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, offset_reserved_flags) = tcp_segments(data)
                print(Tab1 + 'TCP Segment:')
                print(Tab2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(Tab2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print(Tab2 + 'Flags:')
                print(Tab3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack,
                                                                                            flag_psh, flag_rst,
                                                                                            flag_syn, flag_fin))
                print(Tab2 + 'Data:')
                print(format_multi_line(Data_tab3, data))

            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(Tab1 + 'UDP Segment:')
                print(Tab2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

            else:
                print(Tab1 + 'Data:')
                print(format_multi_line(Data_tab2, data))

        else:
            print('Data:')
            print(format_multi_line(Data_tab1, data))


# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac , src_mac , proto = struct.unpack('! 6s 6s H', data[:14])
    # dest_mac -->6s(six characters) 
    # src_mac --> 6s
    # protocol(type) --> H
    return get_mac_addr(dest_mac) , get_mac_addr(src_mac) , socket.htons(proto) , data[14:]
    # ethernet frame retnrs destination, source, ethernet type(protocol) and payload(data) 

# Return properly formatted MAC address (i.e. AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format,bytes_addr)
    #return ':'.join(bytes_str).upper()
    mac_addr = ':'.join(bytes_str).upper()
    return(mac_addr)

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4 # Using bitwise operator to extract version
    header_length = (version_header_length & 15) * 4
    # starting to unpack
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version, header_length, ttl, protocol, ipv4(src), ipv4(target), data[header_length:]

# Return properly formatted IPv4 address (xxx.xxx.xxx.xxx)
def ipv4(addr):
    return '.'.join(map(str,addr))

# ---------------------------------------------------------------
# Once we gets protocol (what type of data) from IPv4 header 
# Only focusing on ICMP TCP and UDP as these are used 99% of the time

# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H',data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segments
def tcp_segments(data):
    src_port, dest_port, sequence, ack_no, offset_reserved_flags = struct.unpack('! H H L L H')
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32 ) >> 5
    flag_ack = (offset_reserved_flags & 16 ) >> 4
    flag_psh = (offset_reserved_flags & 8 ) >> 3
    flag_rst = (offset_reserved_flags & 4 ) >> 2
    flag_syn = (offset_reserved_flags & 2 ) >> 1
    flag_fin = (offset_reserved_flags & 1 )
    return src_port, dest_port, sequence, ack_no, offset_reserved_flags, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H',data [:8])
    return src_port, dest_port, size, data[8:]

# Formats muti-line data
def format_multi_line(prefix, string, size = 80):
    size -= len(prefix)
    if (isinstance(string,bytes)):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if (size % 2):
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])


if __name__ == '__main__':
    main()
