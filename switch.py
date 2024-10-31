#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name
mac_table = {}
vlan_config = {}
port_type = {}


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)
def remove_vlan_tag(frame):
    return frame[0:12] + frame[16:]

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)
    
def is_broadcast(dest_mac):
    return dest_mac == 'ff:ff:ff:ff:ff:ff'

def create_tagged_frame(vlan,data,target_port,length):
    tagged_frame = data[0:12] + create_vlan_tag(vlan) + data[12:]
    send_to_link(target_port,length + 4,tagged_frame)

def create_untagged_frame(data,length,target_port):
    untagged_frame = data[0:12] + data[16:]
    send_to_link(target_port, length - 4, untagged_frame)

def forward_frame(target_port,interface,length,data,vlan_id):
    if vlan_id == -1: 
        if port_type[get_interface_name(target_port)] == 'trunk':
            create_tagged_frame(vlan_config[get_interface_name(interface)],data,target_port,length)
        
        else:
            vlan_interface_to_send = vlan_config[get_interface_name(target_port)]
            vlan_source = vlan_config[get_interface_name(interface)]
            if vlan_interface_to_send == vlan_source:
                send_to_link(target_port,length,data)

    else: 
        if port_type[get_interface_name(target_port)] == 'trunk':
            send_to_link(target_port, length, data)
        else:
            vlan_interface_to_send = vlan_config[get_interface_name(target_port)]
            if vlan_interface_to_send == vlan_id:
                create_untagged_frame(data,length,target_port)


def load_vlan_config(switch_id):
    global vlan_config, port_type
    try:
        file_path = 'configs/switch' + switch_id + '.cfg'
        with open(file_path,'r') as f:
            lines = f.readlines()
            priority = int(lines[0].strip())

            for line in lines[1:]:
                parts = line.strip().split()
                interface = parts[0]

                if parts[1]=='T':
                    port_type[interface] = 'trunk'
                    vlan_config[interface] = -2
                else:
                    vlan_id = int(parts[1])
                    port_type[interface] = 'access'
                    vlan_config[interface] = vlan_id
        
    except IOError:
        print(f"Can't read the file {file_path}")
    except ValueError:
        print(f"Invalid format: {file_path}")

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    global mac_table
    load_vlan_config(switch_id)

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)
        mac_table[src_mac] = (interface,vlan_id)



        # unicast
        if dest_mac in mac_table:
            target_port,target_vlan = mac_table[dest_mac]
            forward_frame(target_port,interface,length,data,vlan_id)
        else:
            for i in interfaces:
                if i != interface:
                    forward_frame(i,interface,length,data,vlan_id)
                    


if __name__ == "__main__":
    main()
