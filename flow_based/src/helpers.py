# Import usefull libraries
import pcapy
import dpkt
import socket
import numpy as np
import joblib
import pandas as pd
import netifaces
import time
import datetime
import psutil
from prettytable import PrettyTable
from contextlib import redirect_stdout, redirect_stderr
import io

# Filter out FutureWarnings with the specific message
import warnings
warnings.filterwarnings("ignore", category=FutureWarning, module="sklearn")

# Dictionary that has all the active flows
active_flows = {}

# 5995.716184 is the maximum value of the Max Inter Arrival Time of the packages on the dataset
timeout_limit = 5995.716184 + 1000 

class uniFlow:
    def __init__(self, num_pkts, std_iat, min_iat, max_iat, mean_pkt_len, std_pkt_len, min_pkt_len, max_pkt_len, num_bytes, num_psh_flags, num_rst_flags):

        self.num_pkts = num_pkts 
        # self.mean_iat = mean_iat 
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
        # self.num_urg_flags = num_urg_flags

def uniFlow2df(uniflow):
    """Transform to pandas df in order to use it for prediction"""
    df = pd.DataFrame(columns=['num_pkts', 'std_iat', 'min_iat', 'max_iat', 'mean_pkt_len', 'num_bytes', 'num_psh_flags', 'num_rst_flags', 'std_pkt_len', 'min_pkt_len', 'max_pkt_len'])

    df.loc[0,'num_pkts'] = int(uniflow.num_pkts)
    # df.loc[0,'mean_iat'] = float(uniflow.mean_iat)
    df.loc[0,'std_iat'] = float(uniflow.std_iat)
    df.loc[0,'min_iat'] = float(uniflow.min_iat)
    df.loc[0,'max_iat'] = float(uniflow.max_iat)
    df.loc[0,'mean_pkt_len'] = float(uniflow.mean_pkt_len)
    df.loc[0,'num_bytes'] = int(uniflow.num_bytes)
    df.loc[0,'num_psh_flags'] = int(uniflow.num_psh_flags)
    df.loc[0,'num_rst_flags'] = int(uniflow.num_rst_flags)
    # df.loc[0,'num_urg_flags'] = int(uniflow.num_urg_flags)
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

def clear_screen(network_interface, model_name, display):
    print("\033c", end="") # Clear the screen
    print(f"Capturing packets on {network_interface}")
    print(f"Press 'r' to clear the table")
    print(f"Machine learning model `{model_name}` has predicted the following flows as Malicious")
    print(display)
    print("Press Ctrl-C to terminate capturing packets.")
    print("Only TCP and UDP packets are captured.")


def capture_packets(network_interface, model_name):
    """This function is responsible for capturing the packets on the specific network interface"""
    start_of_time = time.time()
    packet_count = 0
    filtered_packet_count = 0
    flow_creation_count = 0
    sum_of_time = 0
    malicious_flows = 0 
    resource_utilization = []
    start_time = time.time()
    current_date = datetime.datetime.now().strftime("%d-%m-%y_%H-%M-%S")
    report_file_name = f"report_{current_date}.log"
    display = PrettyTable()
    display.field_names = ["Source IP", "Source port", "Destination IP", "Destination port", "Protocol"]

    # Initialize packet capturer
    snaplen = 65536  # Maximum number of bytes to capture per packet
    promiscuous = True  # Capture in promiscuous mode
    timeout = 1000  # Timeout for capturing packets in milliseconds
    capture = pcapy.open_live(network_interface, snaplen, promiscuous, timeout)

    # Capture packets
    try:
        print("\033c", end="") # Clear the screen
        print(f"Capturing packets on {network_interface}")
        print(f"Machine learning model `{model_name}` has predicted the following flows as Malicious")
        print(display)
        print("Press Ctrl-C to terminate capturing packets.")
        print("Only TCP and UDP packets are captured.")
        while True:
            # Capture packet
            (header, buf) = capture.next()
            packet_count += 1

            # Check if the packet has a meaning to be handled
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            l3 = eth.data
            if isinstance(l3.data, dpkt.icmp.ICMP):
                continue
            elif isinstance(l3.data, dpkt.igmp.IGMP):
                continue
            l4 = l3.data
            if not isinstance(l4, dpkt.tcp.TCP) and not isinstance(l4, dpkt.udp.UDP):
                continue

            if isinstance(l4, dpkt.tcp.TCP):
                # Connection on TCP is finished when one is sending FIN and the other response with ACK
                proto = 'TCP'
                rst_flag = ( l4.flags & dpkt.tcp.TH_RST ) != 0
                psh_flag = ( l4.flags & dpkt.tcp.TH_PUSH) != 0
                # urg_flag = ( l4.flags & dpkt.tcp.TH_URG ) != 0
                fin_flag = ( l4.flags & dpkt.tcp.TH_FIN ) != 0
            elif isinstance(l4, dpkt.udp.UDP):
                proto = 'UDP' 
                rst_flag = False
                psh_flag = False
                # urg_flag = False
                fin_flag = False
            
            filtered_packet_count += 1
            flow_name = "_".join(str(v) for v in (inet_to_str(l3.src), inet_to_str(l3.dst), l4.sport, l4.dport, proto))
            flow_data = ((rst_flag, psh_flag, fin_flag), header.getts(), len(eth.data))

            not_exist, time_taken, is_attack = update_flow(flow_name, flow_data, model_name)
            if not_exist:
                flow_creation_count += 1
                if is_attack:
                    parts = flow_name.split('_')
                    data = [parts[0], parts[2], parts[1], parts[3], parts[4]]
                    display.add_row(data)
                    # Display only 10 latest malicious flows
                    if len(display._rows) > 10:
                        display.del_row(0) 
                    print("\033c", end="") # Clear the screen
                    print(f"Capturing packets on {network_interface}")
                    print(f"Machine learning model `{model_name}` has predicted the following flows as Malicious")
                    print(display)
                    print("Press Ctrl-C to terminate capturing packets.")
                    print("Only TCP and UDP packets are captured.")
                    malicious_flows += 1
            sum_of_time += time_taken

    except KeyboardInterrupt:
        # Ctrl-C (EOF) was pressed
        print("\033c", end="") # Clear the screen
        q_or_any = input("Enter q to quit or any other key to restart capturing: ")
        if (q_or_any == 'q'):
            print(f"Generating report to 'flow_based/src/reports/{report_file_name}' and terminating...")
        else:
            capture_packets(network_interface, model_name)

    # Calculate packet capture rate
    elapsed_time = time.time() - start_time
    packet_capture_rate = packet_count / elapsed_time

    # Resource utilization metrics
    resource_utilization.append({
        "CPU Usage (%)": psutil.cpu_percent(),
        "Memory Usage (%)": psutil.virtual_memory().percent
    })

    end_of_time = time.time() - start_of_time
    # Store the report in a file
    with open(f"flow_based/src/reports/{report_file_name}", 'w') as file:
        file.write("###### Report for Intrusion Detection System ######\n")
        file.write("###################################################\n")
        file.write(f"Starting date and time: {datetime.datetime.now().strftime('%d-%m-%y: %H:%M:%S')}\n")
        file.write(f"Duration: {end_of_time:.4f} seconds\n")
        file.write(f"Packets captured: {packet_count}\n")
        file.write(f"Filtered packets: {filtered_packet_count}\n")
        file.write(f"Packets captured rate: {packet_capture_rate:.4f} packets per second\n")
        file.write("###################################################\n")
        file.write(f"Flows detected: {flow_creation_count}\n")
        file.write(f"Average time to analyse flow: {(sum_of_time/filtered_packet_count):.5f}\n")
        file.write(str(resource_utilization) + "\n")
        file.write("###################################################\n")
        file.write(f"Malicious flows detected: {malicious_flows}\n")
        file.write(f"Machine learning model used: {model_name}\n")
        file.write("###################################################\n")

def update_flow(flow_name, flow_data, model_name):
    """This function is responsible for creating or updating each flow with the new packets
        Args:
            flow_name: string like the following ipsrc_ipdst_portsrc_portdst_protocol
            flow_data: turple that contains ((rst_flag, psh_flag, fin_flag), timestamp, ip_len)
                timestamp is a tuple with two elements: the number of seconds since the Epoch, and the amount of microseconds past the current second.
        Return return_val, time_to_analyse_flow, is_attack:
            return_val:
                1: if the flow is a new one (does not exist on the active_flows)
                0: if the flow is an old one (exist on the active_flows)
            time_to_analyse_flow:
                Time that was needed to analyse the flow
            is_attack:
                0: if it's not an attack
                1: if it's an attack
    """
    # Create the flow if it does not exists
    if flow_name not in active_flows:
        active_flows[flow_name] = []
        time_diff = -1
        return_val = 1
    else: # Find the time difference between the current and the last packet of the flow
        time_diff = time_tuple_to_float(flow_data[1]) - time_tuple_to_float(active_flows[flow_name][-1][1])
        return_val = 0
        
    proto = flow_name[-3:]
    if proto == 'TCP': # TCP packet analysis
        # If package has FIN flag or has excide timeout limit delete from active flows
        if (flow_data[0][2] != 0) or (time_diff > timeout_limit):
            # Update, analyze and delete the flow
            active_flows[flow_name].append(flow_data)
            start_time = time.time()
            is_attack = analyze_flow(flow_name, model_name)     
            time_to_analyse_flow = time.time() - start_time
            del active_flows[flow_name] 
        else: 
            # Update and analyze the flow
            active_flows[flow_name].append(flow_data)
            start_time = time.time()
            is_attack = analyze_flow(flow_name, model_name)     
            time_to_analyse_flow = time.time() - start_time  
    elif proto == 'UDP': # UDP packet analysis
        if time_diff > timeout_limit:
            # Update, analyze and delete the flow
            active_flows[flow_name].append(flow_data)
            start_time = time.time()
            is_attack = analyze_flow(flow_name, model_name)     
            time_to_analyse_flow = time.time() - start_time     
            del active_flows[flow_name]  
        else:
            # Update and analyze the flow
            active_flows[flow_name].append(flow_data)
            start_time = time.time()
            is_attack = analyze_flow(flow_name, model_name)     
            time_to_analyse_flow = time.time() - start_time
    return return_val, time_to_analyse_flow, is_attack


def analyze_flow(flow_name, model_name):
    """This function is responsible for analyzing the flow each time a new packet is added

        ['num_pkts', 'std_iat', 'min_iat', 'max_iat', 'mean_pkt_len',
            'num_bytes', 'num_psh_flags', 'num_rst_flags',
            'std_pkt_len', 'min_pkt_len', 'max_pkt_len', 'is_attack']
        Returns is_attack:
            0: is not an attack
            1: is an attack
    """

    secure_ips = ['192.168.1.22', '192.168.1.138', '192.168.1.200'] # Broker, phone, linux-pc

    parts = flow_name.split('_')
    if parts[0] in secure_ips and parts[2] in secure_ips:
        return 0
    
    
    num_pkts = len(active_flows[flow_name])

    if num_pkts > 1:
        time_list = []
        length_list = []
        rst_list = []
        psh_list = []
        # urg_list = []
        # active_flow[flow_name][i] ==> ((rst_flag, psh_flag, fin_flag), timestamp, ip_len) 
        for i in range(len(active_flows[flow_name])): 
            time_list.append(time_tuple_to_float(active_flows[flow_name][i][1]))
            length_list.append(active_flows[flow_name][i][2])
            rst_list.append(active_flows[flow_name][i][0][0])
            psh_list.append(active_flows[flow_name][i][0][1])
            # urg_list.append(active_flows[flow_name][i][0][2])

        time_list.sort(reverse = True) # put times in descending order
        t_diff = abs(np.diff(time_list)) # find the time differences

        # mean_iat = sum(t_diff) / (num_pkts - 1)
        std_iat = np.std(t_diff) # std dev of IAT
        min_iat = min(t_diff)
        max_iat = max(t_diff)

        mean_pkt_len = sum(length_list) / num_pkts
        num_bytes = sum(length_list)

        num_rst_flags = sum(rst_list)
        num_psh_flags = sum(psh_list)
        # num_urg_flags = sum(urg_list)

        pkt_len_array = np.array(length_list)
        std_pkt_len = float(np.std(pkt_len_array))
        min_pkt_len = float(min(pkt_len_array))
        max_pkt_len = float(max(pkt_len_array))

    else:
        # mean_iat = 0.0
        std_iat = 0.0
        min_iat = 0.0
        max_iat = 0.0

        mean_pkt_len = active_flows[flow_name][0][2]
        num_bytes = active_flows[flow_name][0][2] 

        num_psh_flags = active_flows[flow_name][0][0][0]
        num_rst_flags = active_flows[flow_name][0][0][1]
        # num_urg_flags = active_flows[flow_name][0][0][2]

        std_pkt_len = 0.0
        min_pkt_len = active_flows[flow_name][0][2]
        max_pkt_len = active_flows[flow_name][0][2]


    uniflow = uniFlow(num_pkts, std_iat, min_iat, max_iat, mean_pkt_len, std_pkt_len,
                      min_pkt_len, max_pkt_len, num_bytes, num_psh_flags, num_rst_flags)

    flow_df = uniFlow2df(uniflow)  

    null_output = io.StringIO()
    with redirect_stdout(null_output), redirect_stderr(null_output):
        loaded_model = joblib.load(f"flow_based/src/final_models/{model_name}.pkl")
        is_attack = loaded_model.predict(flow_df)   

    # loaded_model = joblib.load(f"flow_based/src/final_models/{model_name}.pkl")
    # is_attack = loaded_model.predict(flow_df)  

    return is_attack

