#  Switch Implementation with STP

### **Name**: Gheorghe Marius Razvan  
### **Group**: 334CA  
### **Date**: 10.11.2024  
### **Email**: rzvrazvan03@gmail.com


---

## **Project Overview**:
This project involves implementing a **Layer 2 (L2) switch** with support for VLANs, **Spanning Tree Protocol (STP)**, and forwarding Ethernet frames. The switch manages **VLANs**, **ports**, and handles **broadcast**, **unicast**, and **multicast** frames.

The switch has various functionalities to manage VLANs, handle incoming frames, and compute the best paths using the Spanning Tree Protocol (STP). It also processes **BPDU** frames to manage root bridges and port states (e.g., **BLOCKING**, **DESIGNATED**, etc.).

---

## **Key Features**:
1. **VLAN Configuration**: 
   - Switches support VLAN-based traffic segregation.
   - Ports can be configured as **access** (for specific VLANs) or **trunk** (carrying multiple VLANs).

2. **Ethernet Frame Forwarding**:
   - For **broadcast frames**, the switch forwards them on all interfaces.
   - For **unicast frames**, the switch forwards them based on MAC table lookup.
   - Frames arriving on **trunk ports** are tagged with a VLAN ID, while **access ports** are untagged.

3. **Spanning Tree Protocol (STP)**:
   - The **STP** ensures there are no loops in the network by blocking redundant paths.
   - It uses **BPDU** frames to elect a root bridge and to decide which paths should be blocked.

---

## **Detailed Functions**:

### **1. `parse_ethernet_header(data)`**:
   - This function parses an Ethernet frame header.
   - It extracts **destination MAC**, **source MAC**, **ethernet type**, and **VLAN ID** (if the frame is tagged).
   - It checks if the frame has a **VLAN tag** and extracts the **VLAN ID** if available.

### **2. `create_vlan_tag(vlan_id)`**:
   - This function generates a **VLAN tag** to be inserted into an Ethernet frame.
   - It packs the VLAN ID and returns it in the correct format for **802.1Q VLAN tagging**.

### **3. `create_bpdu(root_bridge_id, sender_path_cost, sender_bridge_id, port)`**:
   - This function creates a **BPDU frame** for **Spanning Tree Protocol (STP)**.
   - The BPDU is constructed with information about the **root bridge**, **sender's path cost**, **sender's bridge ID**, and the **port** sending the BPDU.
   - The frame is sent to the network.

### **4. `send_bdpu_every_sec()`**:
   - This is a background thread function that periodically sends **BPDU frames**.
   - The function checks if the current switch is the **root bridge** and sends BPDUs to **trunk ports**.

### **5. `is_broadcast(dest_mac)`**:
   - Checks if the **destination MAC address** is a broadcast address (`ff:ff:ff:ff:ff:ff`).
   - Returns **True** if it is a broadcast address.

### **6. `create_tagged_frame(vlan, data, target_port, length)`**:
   - This function creates a **tagged frame** (with a VLAN tag).
   - If the destination port is a **trunk port**, the frame is tagged with the VLAN ID before forwarding it.

### **7. `create_untagged_frame(data, length, target_port)`**:
   - This function creates an **untagged frame** by removing any VLAN tag.
   - If a frame arrives on a **trunk port** and needs to be forwarded to an **access port**, this function is used to remove the VLAN tag.

### **8. `forward_frame(target_port, interface, length, data, vlan_id)`**:
   - This function forwards an Ethernet frame based on several conditions:
     - If the frame arrives on an **access port** and needs to be sent to a **trunk port**, a VLAN tag is added.
     - If the frame arrives on a **trunk port** and needs to be sent to an **access port**, the VLAN tag is removed.

### **9. `load_vlan_config(switch_id)`**:
   - Loads the VLAN configuration from a file (`switchX.cfg`) based on the switch ID.
   - The configuration contains the **VLAN IDs** for each port (either **access** or **trunk**) and the **priority** for STP.

### **10. `initialize_stp(interfaces)`**:
   - Initializes the **Spanning Tree Protocol** (STP) for the switch.
   - Sets **trunk ports** to **BLOCKING** state and **access ports** to **DESIGNATED_PORT**.
   - Initializes the **root bridge** and **path cost**.

### **11. `receive_bpdu(interface, data, interfaces)`**:
   - Processes a received **BPDU** frame.
   - It extracts the root bridge ID, sender path cost, sender bridge ID, and port ID from the BPDU.
   - Based on the comparison of root bridge IDs, it updates the **root bridge**, **path cost**, and port states.
   - The updated BPDU is forwarded to other **trunk ports**.

### **12. `main()`**:
   - The main function that handles the switch operations.
   - It loads the **VLAN configuration**, initializes **STP**, and starts a background thread to send **BPDU frames** every second.
   - The function listens for incoming frames, processes them (either as **BPDU** or **Ethernet** frames), and forwards them according to the VLAN configuration and STP states.

---

## **VLAN Configuration File** (`switchX.cfg`):
The VLAN configuration file for each switch contains the following format:



## Running

```bash
sudo python3 checker/topo.py
```

This will open 9 terminals, 6 hosts and 3 for the switches. On the switch terminal you will run 

```bash
make run_switch SWITCH_ID=X # X is 0,1 or 2
```

The hosts have the following IP addresses.
```
host0 192.168.1.1
host1 192.168.1.2
host2 192.168.1.3
host3 192.168.1.4
host4 192.168.1.5
host5 192.168.1.6
```

We will be testing using the ICMP. For example, from host0 we will run:

```
ping 192.168.1.2
```

Note: We will use wireshark for debugging. From any terminal you can run `wireshark&`.
