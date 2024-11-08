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
port_states = {}
own_bridge_id=0
root_bridge_id=0
root_path_cost=0
root_port=0
priority=0
BPDU_MULTICAST_MAC = b'\x01\x80\xc2\x00\x00\x00'
LLC_LENGTH = struct.pack('!H', 52) # H means packed as unsigned short (2 bytes)
LLC_HEADER = b'\x42\x42\x03' # DSAP | SSAP | Control
BPDU_HEADER = b'\x00\x00\x00\x00' # Protocol Identifier | Protocol Version Identifier | BPDU Type 

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

def create_bpdu(root_bridge_id,sender_path_cost,sender_bridge_id,port):
    dest_mac = BPDU_MULTICAST_MAC
    src_mac = get_switch_mac()
    bpdu = (
        dest_mac + src_mac + LLC_LENGTH + LLC_HEADER + BPDU_HEADER +
        b'\x00' +  # flags
        struct.pack('!Q', root_bridge_id) +  # root_bridge_id, 8 bytes
        struct.pack('!L', sender_path_cost) +  # root_path_cost, 4 bytes
        struct.pack('!Q', sender_bridge_id) +  # bridge_id, 8 bytes
        struct.pack('!H', port)  # port_id, 2 bytes
    )
    send_to_link(port, len(bpdu),bpdu)

def send_bdpu_every_sec():
    while True:

        global own_bridge_id, root_bridge_id

        if root_bridge_id == own_bridge_id:
            for port in port_states:

                if port_type[get_interface_name(port)] == 'trunk':
                    root_bridge_id = own_bridge_id
                    sender_bridge_id = own_bridge_id
                    sender_path_cost=0

                    create_bpdu(root_bridge_id,sender_path_cost,sender_bridge_id,port)
                
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
            vlan_dest = vlan_config[get_interface_name(target_port)]
            vlan_source = vlan_config[get_interface_name(interface)]
            if vlan_dest == vlan_source:
                send_to_link(target_port,length,data)

    else: 
        if port_type[get_interface_name(target_port)] == 'access':
            vlan_dest = vlan_config[get_interface_name(target_port)]
            if vlan_dest == vlan_id:
                create_untagged_frame(data,length,target_port)
        else:
            send_to_link(target_port, length, data)
    


def load_vlan_config(switch_id):
    global vlan_config, port_type,priority
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

def initialize_stp(interfaces):
    global port_states,root_path_cost,own_bridge_id,root_bridge_id,priority
    
    for i in interfaces:
        if port_type[get_interface_name(i)] =='trunk':
            port_states[i] = 'BLOCKING'
        else:
            port_states[i] = 'DESIGNATED_PORT'

    own_bridge_id=priority
    root_bridge_id=own_bridge_id
    root_path_cost=0

    if own_bridge_id == root_bridge_id:
        for port in port_states:
            port_states[port] = 'DESIGNATED_PORT'

def receive_bpdu(interface, data,interfaces):
    global root_bridge_id, root_path_cost, root_port, own_bridge_id, port_states
   
    root_bridge_id_bpdu = int.from_bytes(data[22:30],byteorder='big')
    root_path_cost_bpdu = int.from_bytes(data[30:34],byteorder='big')
    bridge_id_bpdu = int.from_bytes(data[34:42],byteorder='big')
    port_id_bpdu = int.from_bytes(data[42:44],byteorder='big')
    

    if root_bridge_id_bpdu < root_bridge_id:
        prev_root_bridge_id = root_bridge_id  # save the previous root bridge id
        root_bridge_id = root_bridge_id_bpdu
        root_path_cost = root_path_cost_bpdu + 10
        root_port = port_id_bpdu

        if own_bridge_id == prev_root_bridge_id:
            for port in port_states:
                if port_type[get_interface_name(port)] == 'trunk' and port != root_port:
                    port_states[port] = 'BLOCKING'

        if port_states[root_port] == 'BLOCKING':
            port_states[root_port] = 'LISTENING'
        
    
        
        for port in interfaces:
            if port != interface and port_type[get_interface_name(port)] == 'trunk':
                create_bpdu(root_bridge_id, root_path_cost, own_bridge_id, port)
                
                
    elif root_bridge_id_bpdu == root_bridge_id:
        if interface == root_port and root_path_cost_bpdu + 10 < root_path_cost:
            root_path_cost = root_path_cost_bpdu + 10
        elif interface != root_port:
            if root_path_cost_bpdu > root_path_cost and port_states[interface] == 'BLOCKING':
                port_states[interface] = 'LISTENING'

    elif bridge_id_bpdu == own_bridge_id:
        port_states[interface] = 'BLOCKING'

    if own_bridge_id == root_bridge_id:
        for port in interfaces:
            if port_type[get_interface_name(port)] == 'trunk':
                port_states[port] = 'DESIGNATED_PORT'

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


    initialize_stp(interfaces)

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
        dest_mac_init = dest_mac

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        if dest_mac_init == BPDU_MULTICAST_MAC:
            receive_bpdu(interface,data,interfaces)
        else:
            mac_table[src_mac] = (interface,vlan_id)
            # broadcast
            if(is_broadcast(dest_mac)):
                for i in interfaces:
                    if i != interface and port_states[i]!='BLOCKING':
                        forward_frame(i,interface,length,data,vlan_id)
            else:
                if dest_mac in mac_table:
                    target_port,target_vlan = mac_table[dest_mac]
                    if port_states[target_port] != 'BLOCKING':
                        forward_frame(target_port,interface,length,data,vlan_id)
                else:
                    for i in interfaces:
                        if i != interface and port_states[i]!='BLOCKING':
                            forward_frame(i,interface,length,data,vlan_id)
                    


if __name__ == "__main__":
    main()
