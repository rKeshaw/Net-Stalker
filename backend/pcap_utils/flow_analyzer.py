import collections
import time
from scapy.all import IP, IPv6, TCP, UDP, ARP, ICMP, DNS, ICMPv6ND_NS, corrupt_bytes

# Time-series traffic chart data
def time_flow(PCAPS):
    time_flow_dict = collections.OrderedDict()
    start = PCAPS[0].time
    time_flow_dict[time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(PCAPS[0].time)))] = len(corrupt_bytes(PCAPS[0]))
    for pcap in PCAPS:
        timediff = pcap.time - start
        time_flow_dict[float('%.3f'%timediff)] = len(corrupt_bytes(pcap))
    return time_flow_dict

# Get the primary host IP from the capture
def get_host_ip(PCAPS):
    ip_list = list()
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            ip_list.append(pcap.getlayer(IP).src)
            ip_list.append(pcap.getlayer(IP).dst)
    if not ip_list:
        return "0.0.0.0"
    host_ip = collections.Counter(ip_list).most_common(1)[0][0]
    return host_ip

# IN/OUT packet count statistics
def data_flow(PCAPS, host_ip):
    data_flow_dict = {'IN': 0, 'OUT': 0}
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            if pcap.getlayer(IP).src == host_ip:
                data_flow_dict['OUT'] += 1
            elif pcap.getlayer(IP).dst == host_ip:
                data_flow_dict['IN'] += 1
    return data_flow_dict

# Inbound/Outbound IP traffic stats
def data_in_out_ip(PCAPS, host_ip):
    in_ip_packet_dict = dict()
    in_ip_len_dict = dict()
    out_ip_packet_dict = dict()
    out_ip_len_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            dst = pcap.getlayer(IP).dst
            src = pcap.getlayer(IP).src
            pcap_len = len(corrupt_bytes(pcap))
            if dst == host_ip:
                if src in in_ip_packet_dict:
                    in_ip_packet_dict[src] += 1
                    in_ip_len_dict[src] += pcap_len
                else:
                    in_ip_packet_dict[src] = 1
                    in_ip_len_dict[src] = pcap_len
            elif src == host_ip:
                if dst in out_ip_packet_dict:
                    out_ip_packet_dict[dst] += 1
                    out_ip_len_dict[dst] += pcap_len
                else:
                    out_ip_packet_dict[dst] = 1
                    out_ip_len_dict[dst] = pcap_len

    in_packet_dict = sorted(in_ip_packet_dict.items(), key=lambda d:d[1], reverse=False)
    in_len_dict = sorted(in_ip_len_dict.items(), key=lambda d:d[1], reverse=False)
    out_packet_dict = sorted(out_ip_packet_dict.items(), key=lambda d:d[1], reverse=False)
    out_len_dict = sorted(out_ip_len_dict.items(), key=lambda d:d[1], reverse=False)

    return {
        'in_keyp': [k for k,v in in_packet_dict], 'in_packet': [v for k,v in in_packet_dict],
        'in_keyl': [k for k,v in in_len_dict], 'in_len': [v for k,v in in_len_dict],
        'out_keyp': [k for k,v in out_packet_dict], 'out_packet': [v for k,v in out_packet_dict],
        'out_keyl': [k for k,v in out_len_dict], 'out_len': [v for k,v in out_len_dict]
    }

# Total traffic per protocol
def proto_flow(PCAPS):
    proto_flow_dict = collections.OrderedDict({
        'IP': 0, 'IPv6': 0, 'TCP': 0, 'UDP': 0, 'ARP': 0,
        'ICMP': 0, 'DNS': 0, 'HTTP': 0, 'HTTPS': 0, 'Others': 0
    })
    
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        
        # Layer 3
        if pcap.haslayer(IP): proto_flow_dict['IP'] += pcap_len
        elif pcap.haslayer(IPv6): proto_flow_dict['IPv6'] += pcap_len
        
        # Layer 4/5
        if pcap.haslayer(TCP):
            proto_flow_dict['TCP'] += pcap_len
            tcp = pcap.getlayer(TCP)
            if tcp.dport == 80 or tcp.sport == 80: proto_flow_dict['HTTP'] += pcap_len
            elif tcp.dport == 443 or tcp.sport == 443: proto_flow_dict['HTTPS'] += pcap_len
            else: proto_flow_dict['Others'] += pcap_len
            
        elif pcap.haslayer(UDP):
            proto_flow_dict['UDP'] += pcap_len
            udp = pcap.getlayer(UDP)
            if udp.dport == 5353 or udp.sport == 5353: proto_flow_dict['DNS'] += pcap_len
            else: proto_flow_dict['Others'] += pcap_len
            
        elif pcap.haslayer(ARP): proto_flow_dict['ARP'] += pcap_len
        elif pcap.haslayer(ICMP): proto_flow_dict['ICMP'] += pcap_len
        elif pcap.haslayer(DNS): proto_flow_dict['DNS'] += pcap_len
        elif pcap.haslayer(ICMPv6ND_NS): proto_flow_dict['ICMP'] += pcap_len
        else: proto_flow_dict['Others'] += pcap_len
        
    return proto_flow_dict

def most_flow_statistic(PCAPS, PD):
    most_flow_dict = collections.defaultdict(int)
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        most_flow_dict[data['Procotol']] += len(corrupt_bytes(pcap))
    return most_flow_dict
