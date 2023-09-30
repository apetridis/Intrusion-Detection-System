# Import usefull libraries
import pcapy
import dpkt
import socket
import numpy as np
import joblib
import pandas as pd
import netifaces


# Filter out FutureWarnings with the specific message
import warnings
warnings.filterwarnings("ignore", category=FutureWarning, module="sklearn")

# Dictionary that has all the active flows
active_flows = {}

# 5995.716184 is the maximum value of the Max Inter Arrival Time of the packages on the dataset
timeout_limit = 5995.716184 + 1000 

class uniFlow:
    def __init__(self, num_pkts, mean_iat, std_iat, min_iat, max_iat, mean_pkt_len, std_pkt_len, min_pkt_len, max_pkt_len, num_bytes, num_psh_flags, num_rst_flags, num_urg_flags):

        self.num_pkts = num_pkts 
        self.mean_iat = mean_iat 
        self.std_iat = std_iat 
        self.min_iat = min_iat
        self.max_iat = max_iat
        self.mean_pkt_len = mean_pkt_len 
        self.std_pkt_len = std_pkt_len 
        self.max_pkt_len = max_pkt_len
        self.min_pkt_len = min_pkt_len
        self.num_bytes = num_bytes
        self.num_psh_flags = num_psh_flags
        self.num_rst_flags = num_rst_flags
        self.num_urg_flags = num_urg_flags

def uniFlow2df(uniflow):
    """Transform to pandas df in order to use it for prediction"""
    df = pd.DataFrame(columns=['num_pkts', 'mean_iat', 'std_iat', 'min_iat', 'max_iat', 'mean_pkt_len', 'num_bytes', 'num_psh_flags', 'num_rst_flags', 'num_urg_flags', 'std_pkt_len', 'min_pkt_len', 'max_pkt_len'])

    df.loc[0,'num_pkts'] = int(uniflow.num_pkts)
    df.loc[0,'mean_iat'] = float(uniflow.mean_iat)
    df.loc[0,'std_iat'] = float(uniflow.std_iat)
    df.loc[0,'min_iat'] = float(uniflow.min_iat)
    df.loc[0,'max_iat'] = float(uniflow.max_iat)
    df.loc[0,'mean_pkt_len'] = float(uniflow.mean_pkt_len)
    df.loc[0,'num_bytes'] = int(uniflow.num_bytes)
    df.loc[0,'num_psh_flags'] = int(uniflow.num_psh_flags)
    df.loc[0,'num_rst_flags'] = int(uniflow.num_rst_flags)
    df.loc[0,'num_urg_flags'] = int(uniflow.num_urg_flags)
    df.loc[0,'std_pkt_len'] = float(uniflow.std_pkt_len)
    df.loc[0,'min_pkt_len'] = float(uniflow.min_pkt_len)
    df.loc[0,'max_pkt_len'] = float(uniflow.max_pkt_len)

    return df

def select_network_interface():
    print("Select one of the available interfaces to capture packets.")
    while True:
        interfaces = netifaces.interfaces()
        print("Available interfaces: ", " ".join(interfaces))
        network_interface = input("Paste the name of the interface here: ")

        if network_interface in interfaces:
            return network_interface
        else:
            print("Invalid interface name. Please enter a valid name.\n")

def time_tuple_to_float(timestamp_tuple):
    """Transforming the tuple timestamp
        Args: 
            (seconds_since_epoch, microseconds_since_epoch)
        Returns: 
            seconds_since_epoch.microseconds_since_epoch
    """
    return timestamp_tuple[0] + timestamp_tuple[1]/1e6


def inet_to_str(inet):
    """Helper function to convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def capture_packets(network_interface, model_name):
    """This function is responsible for capturing the packets on the specific network interface"""
    
    # Initialize packet capturer
    snaplen = 65536  # Maximum number of bytes to capture per packet
    promiscuous = True  # Capture in promiscuous mode
    timeout = 1000  # Timeout for capturing packets in milliseconds
    capture = pcapy.open_live(network_interface, snaplen, promiscuous, timeout)

    # Capture packets
    print("Press Ctrl-C to terminate capturing packets.")
    try:
        while True:
            # Capture packet
            (header, buf) = capture.next()

            # Check if the packet has a meaning to be handled
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                print("Only TCP and UDP packets are captured.")
                print('Non IP Packet type not supported %s.\n' % eth.data.__class__.__name__)
                continue
            l3 = eth.data
            if isinstance(l3.data, dpkt.icmp.ICMP):
                print("Only TCP and UDP packets are captured.")
                print("ICMP Packet disarded.")
                continue
            elif isinstance(l3.data, dpkt.igmp.IGMP):
                print("Only TCP and UDP packets are captured.")
                print("IGMP Packet disarded.")
                continue
            l4 = l3.data
            if not isinstance(l4, dpkt.tcp.TCP) and not isinstance(l4, dpkt.udp.UDP):
                print("Only TCP and UDP packets are captured.")
                print("Unknown Transport Layer.")
                continue

            if isinstance(l4, dpkt.tcp.TCP):
                # Connection on TCP is finished when one is sending FIN and the other response with ACK
                proto = 'TCP'
                rst_flag = ( l4.flags & dpkt.tcp.TH_RST ) != 0
                psh_flag = ( l4.flags & dpkt.tcp.TH_PUSH) != 0
                urg_flag = ( l4.flags & dpkt.tcp.TH_URG ) != 0
                fin_flag = ( l4.flags & dpkt.tcp.TH_FIN ) != 0
            elif isinstance(l4, dpkt.udp.UDP):
                proto = 'UDP' 
                rst_flag = False
                psh_flag = False
                urg_flag = False
                fin_flag = False
            
            flow_name = "_".join(str(v) for v in (inet_to_str(l3.src), inet_to_str(l3.dst), l4.sport, l4.dport, proto))
            flow_data = ((rst_flag, psh_flag, urg_flag, fin_flag), header.getts(), len(eth.data))

            update_flow(flow_name, flow_data, model_name)

    except KeyboardInterrupt:
                # Ctrl-C (EOF) was pressed, so exit the loop
                print("\nTerminating...")

def update_flow(flow_name, flow_data, model_name):
    """This function is responsible for creating or updating each flow with the new packets
        Args:
            flow_name: string like the following ipsrc_ipdst_portsrc_portdst_protocol
            flow_data: turple that contains ((rst_flag, psh_flag, urg_flag, fin_flag), timestamp, ip_len)
                timestamp is a tuple with two elements: the number of seconds since the Epoch, and the amount of microseconds past the current second.
    """
    # Create the flow if it does not exists
    if flow_name not in active_flows:
        active_flows[flow_name] = []
        time_diff = -1
    else: # Find the time difference between the current and the last packet of the flow
        time_diff = time_tuple_to_float(flow_data[1]) - time_tuple_to_float(active_flows[flow_name][-1][1])
        
    proto = flow_name[-3:]
    if proto == 'TCP': # TCP packet analysis
        # If package has FIN flag or has excide timeout limit delete from active flows
        if (flow_data[0][3] != 0) or (time_diff > timeout_limit):
            # Update, analyze and delete the flow
            active_flows[flow_name].append(flow_data)
            analyze_flow(flow_name, model_name)     
            del active_flows[flow_name] 
        else: 
            # Update and analyze the flow
            active_flows[flow_name].append(flow_data)
            analyze_flow(flow_name, model_name)  
    elif proto == 'UDP': # UDP packet analysis
        if time_diff > timeout_limit:
            # Update, analyze and delete the flow
            active_flows[flow_name].append(flow_data)
            analyze_flow(flow_name, model_name)     
            del active_flows[flow_name]  
        else:
            # Update and analyze the flow
            active_flows[flow_name].append(flow_data)
            analyze_flow(flow_name, model_name)


def analyze_flow(flow_name, model_name):
    """This function is responsible for analyzing the flow each time a new packet is added

        ['num_pkts', 'mean_iat', 'std_iat', 'min_iat', 'max_iat', 'mean_pkt_len',
            'num_bytes', 'num_psh_flags', 'num_rst_flags', 'num_urg_flags',
            'std_pkt_len', 'min_pkt_len', 'max_pkt_len', 'is_attack']
    """
    
    num_pkts = len(active_flows[flow_name])

    if num_pkts > 1:
        time_list = []
        length_list = []
        rst_list = []
        psh_list = []
        urg_list = []
        # active_flow[flow_name][i] ==> ((rst_flag, psh_flag, urg_flag, fin_flag), timestamp, ip_len) 
        for i in range(len(active_flows[flow_name])): 
            time_list.append(time_tuple_to_float(active_flows[flow_name][i][1]))
            length_list.append(active_flows[flow_name][i][2])
            rst_list.append(active_flows[flow_name][i][0][0])
            psh_list.append(active_flows[flow_name][i][0][1])
            urg_list.append(active_flows[flow_name][i][0][2])

        time_list.sort(reverse = True) # put times in descending order
        t_diff = abs(np.diff(time_list)) # find the time differences

        mean_iat = sum(t_diff) / (num_pkts - 1)
        std_iat = np.std(t_diff) # std dev of IAT
        min_iat = min(t_diff)
        max_iat = max(t_diff)

        mean_pkt_len = sum(length_list) / num_pkts
        num_bytes = sum(length_list)

        num_rst_flags = sum(rst_list)
        num_psh_flags = sum(psh_list)
        num_urg_flags = sum(urg_list)

        pkt_len_array = np.array(length_list)
        std_pkt_len = float(np.std(pkt_len_array))
        min_pkt_len = float(min(pkt_len_array))
        max_pkt_len = float(max(pkt_len_array))

    else:
        mean_iat = 0.0
        std_iat = 0.0
        min_iat = 0.0
        max_iat = 0.0

        mean_pkt_len = active_flows[flow_name][0][2]
        num_bytes = active_flows[flow_name][0][2] 

        num_psh_flags = active_flows[flow_name][0][0][0]
        num_rst_flags = active_flows[flow_name][0][0][1]
        num_urg_flags = active_flows[flow_name][0][0][2]

        std_pkt_len = 0.0
        min_pkt_len = active_flows[flow_name][0][2]
        max_pkt_len = active_flows[flow_name][0][2]


    uniflow = uniFlow(num_pkts, mean_iat, std_iat, min_iat, max_iat, mean_pkt_len, std_pkt_len,
                      min_pkt_len, max_pkt_len, num_bytes, num_psh_flags, num_rst_flags, num_urg_flags)

    flow_df = uniFlow2df(uniflow)  

    loaded_model = joblib.load(f"../models/{model_name}.pkl")
    is_attack = loaded_model.predict(flow_df)

    print(f"Flow {flow_name}")
    if is_attack == 1:
        print("Is an attack")
    else:
        print("It's normal")
