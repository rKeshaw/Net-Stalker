import collections
import geoip2.database
import os
import threading

_GEO_READER = None
_GEO_READER_LOCK = threading.Lock()
from scapy.all import corrupt_bytes

def pcap_len_statistic(PCAPS):
    pcap_len_dict = {'0-300': 0, '301-600': 0, '601-900': 0, '901-1200': 0, '1201-1500': 0, '1500-more': 0}
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if 0 < pcap_len < 300: pcap_len_dict['0-300'] += 1
        elif 301 <= pcap_len < 600: pcap_len_dict['301-600'] += 1
        elif 601 <= pcap_len < 900: pcap_len_dict['601-900'] += 1
        elif 901 <= pcap_len < 1200: pcap_len_dict['901-1200'] += 1
        elif 1201 <= pcap_len <= 1500: pcap_len_dict['1201-1500'] += 1
        elif pcap_len > 1500: pcap_len_dict['1500-more'] += 1
    return pcap_len_dict

def common_proto_statistic(PCAPS):
    common_proto_dict = collections.OrderedDict({
        'IP': 0, 'IPv6': 0, 'TCP': 0, 'UDP': 0, 'ARP': 0,
        'ICMP': 0, 'DNS': 0, 'HTTP': 0, 'HTTPS': 0, 'Others': 0
    })
    for pcap in PCAPS:
        if pcap.haslayer("IP"): common_proto_dict['IP'] += 1
        elif pcap.haslayer("IPv6"): common_proto_dict['IPv6'] += 1
        if pcap.haslayer("TCP"): common_proto_dict['TCP'] += 1
        elif pcap.haslayer("UDP"): common_proto_dict['UDP'] += 1
        if pcap.haslayer("ARP"): common_proto_dict['ARP'] += 1
        elif pcap.haslayer("ICMP"): common_proto_dict['ICMP'] += 1
        elif pcap.haslayer("DNS"): common_proto_dict['DNS'] += 1
        elif pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            if tcp.dport == 80 or tcp.sport == 80: common_proto_dict['HTTP'] += 1
            elif tcp.dport == 443 or tcp.sport == 443: common_proto_dict['HTTPS'] += 1
            else: common_proto_dict['Others'] += 1
        elif pcap.haslayer("UDP"):
            udp = pcap.getlayer("UDP")
            if udp.dport == 5353 or udp.sport == 5353: common_proto_dict['DNS'] += 1
            else: common_proto_dict['Others'] += 1
        elif pcap.haslayer("ICMPv6ND_NS"): common_proto_dict['ICMP'] += 1
        else: common_proto_dict['Others'] += 1
    return common_proto_dict

def most_proto_statistic(PCAPS, PD):
    protos_list = []
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        protos_list.append(data['Procotol'])
    most_count_dict = collections.OrderedDict(collections.Counter(protos_list).most_common(10))
    return most_count_dict

def http_statistic(PCAPS):
    http_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            ip = None
            if tcp.dport == 80 or tcp.dport == 443:
                ip = pcap.getlayer("IP").dst if pcap.haslayer("IP") else None
            elif tcp.sport == 80 or tcp.sport == 443:
                ip = pcap.getlayer("IP").src if pcap.haslayer("IP") else None
            if ip:
                http_dict[ip] = http_dict.get(ip, 0) + 1
    return http_dict

def dns_statistic(PCAPS):
    dns_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer("DNSQR"):
            qname = pcap.getlayer("DNSQR").qname
            if qname:
                qname = qname.decode('utf-8') if isinstance(qname, bytes) else qname
                dns_dict[qname] = dns_dict.get(qname, 0) + 1
    return dns_dict

def get_geo(ip):
    global _GEO_READER
    base_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(base_dir, 'GeoIP', 'GeoLite2-City.mmdb')
    if _GEO_READER is None:
        with _GEO_READER_LOCK:
            if _GEO_READER is None:
                if not os.path.exists(db_path):
                    return None
                try:
                    _GEO_READER = geoip2.database.Reader(db_path)
                except Exception:
                    return None
    
    try:
        response = _GEO_READER.city(ip)
        city_name = (response.country.names.get('en', '') + " " + response.city.names.get('en', '')).strip()
        return [city_name, response.location.longitude, response.location.latitude]
    except Exception:
        return None

def get_ipmap(PCAPS, host_ip):
    geo_dict = dict()
    ip_value_dict = dict()
    ip_data_list = []

    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            src = pcap.getlayer("IP").src
            dst = pcap.getlayer("IP").dst
            pcap_len = len(corrupt_bytes(pcap))
            target_ip = dst if src == host_ip else src
            
            ip_value_dict[target_ip] = ip_value_dict.get(target_ip, 0) + pcap_len

    for ip, value in ip_value_dict.items():
        geo_list = get_geo(ip)
        if geo_list:
            location_key = geo_list[0]
            if not location_key: location_key = "Unknown Location"
            
            geo_dict[location_key] = [geo_list[1], geo_list[2]]
            
            # Format data for frontend
            ip_data_list.append({
                "ip": ip,
                "traffic": round(value / 1024.0, 2), # KB
                "location": location_key,
                "coordinates": [geo_list[1], geo_list[2]]
            })
            
    return {"geo_locations": geo_dict, "ip_data": ip_data_list}

def protocol_resolution_statistic(PCAPS, PD):
    resolved = 0
    unresolved = 0
    for pcap in PCAPS:
        decoded = PD.ether_decode(pcap)
        proto = decoded.get('Procotol', 'Unknown')
        if proto == 'Unknown':
            unresolved += 1
        else:
            resolved += 1

    total = resolved + unresolved
    resolution_rate = round((resolved / total) * 100, 2) if total else 0.0
    return {
        'resolved_packets': resolved,
        'unresolved_packets': unresolved,
        'resolution_rate_percent': resolution_rate
    }
