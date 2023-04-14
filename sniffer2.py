import socket
import struct
import textwrap


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW , socket.ntohs(3))
        
    while True : 
        raw_data , addr = conn.recvfrom(65536)
        dest_mac , src_mac , ether_proto , data = ethernet_frame(raw_data)
        print("\nEthernet Frame : ")
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac , src_mac
                                                                 , ether_proto))


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

main()
