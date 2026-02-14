import os
import time
from scapy.all import Ether, IP, TCP, UDP, IPv6, corrupt_bytes
from logging_config import get_logger

logger = get_logger(__name__)

class PcapDecode:
    """
    Enhanced PCAP Decoder Class
    Parses Ethernet, IP, TCP, UDP layers using Scapy.
    """
    
    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        protocol_dir = os.path.join(base_dir, 'protocol')

        self.protocol_sources = {}

        self.ETHER_DICT = self._load_protocol(os.path.join(protocol_dir, 'ETHER'), 'ETHER')
        self.IP_DICT = self._load_protocol(os.path.join(protocol_dir, 'IP'), 'IP')
        self.PORT_DICT = self._load_protocol(os.path.join(protocol_dir, 'PORT'), 'PORT')
        self.TCP_DICT = self._load_protocol(os.path.join(protocol_dir, 'TCP'), 'TCP')
        self.UDP_DICT = self._load_protocol(os.path.join(protocol_dir, 'UDP'), 'UDP')

    def _load_protocol(self, filepath, proto_name):
        """Helper to load protocol dictionaries securely"""
        proto_dict = {}
        try:
            with open(filepath, 'r', encoding='UTF-8') as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if ':' in line:
                        key, value = line.split(':', 1)
                        proto_dict[int(key)] = value
        except Exception as e:
            logger.warning("Could not load protocol file", extra={"file_name": filepath})

        self.protocol_sources[proto_name] = {
            "path": filepath,
            "entries": len(proto_dict),
            "loaded": bool(proto_dict)
        }
        return proto_dict
    
    def get_protocol_sources(self):
        return self.protocol_sources
    
    def ether_decode(self, p):
        data = dict()
        if p.haslayer(Ether):
            data = self.ip_decode(p)
            return data
        else:
            data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
            data['Source'] = 'Unknown'
            data['Destination'] = 'Unknown'
            data['Procotol'] = 'Unknown'
            data['len'] = len(corrupt_bytes(p))
            data['info'] = p.summary()
            return data

    def ip_decode(self, p):
        data = dict()
        if p.haslayer(IP):  # IPv4
            ip = p.getlayer(IP)
            if p.haslayer(TCP):
                data = self.tcp_decode(p, ip)
            elif p.haslayer(UDP):
                data = self.udp_decode(p, ip)
            else:
                data = self._generic_ip_decode(p, ip, self.IP_DICT.get(ip.proto, 'IPv4'))
            return data
        elif p.haslayer(IPv6):  # IPv6
            ipv6 = p.getlayer(IPv6)
            if p.haslayer(TCP):
                data = self.tcp_decode(p, ipv6)
            elif p.haslayer(UDP):
                data = self.udp_decode(p, ipv6)
            else:
                data = self._generic_ip_decode(p, ipv6, self.IP_DICT.get(ipv6.nh, 'IPv6'))
            return data
        else:
            # Non-IP packets (ARP, etc.)
            data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
            data['Source'] = p.src if hasattr(p, 'src') else 'Unknown'
            data['Destination'] = p.dst if hasattr(p, 'dst') else 'Unknown'
            data['Procotol'] = self.ETHER_DICT.get(p.type, hex(p.type)) if hasattr(p, 'type') else 'Unknown'
            data['len'] = len(corrupt_bytes(p))
            data['info'] = p.summary()
            return data

    def _generic_ip_decode(self, p, ip_layer, proto_name):
        data = dict()
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
        data['Source'] = ip_layer.src
        data['Destination'] = ip_layer.dst
        data['Procotol'] = proto_name
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        return data

    def tcp_decode(self, p, ip):
        data = dict()
        tcp = p.getlayer(TCP)
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
        data['Source'] = f"{ip.src}:{ip.sport}"
        data['Destination'] = f"{ip.dst}:{ip.dport}"
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        
        if tcp.dport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[tcp.dport]
        elif tcp.sport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[tcp.sport]
        elif tcp.dport in self.TCP_DICT:
            data['Procotol'] = self.TCP_DICT[tcp.dport]
        elif tcp.sport in self.TCP_DICT:
            data['Procotol'] = self.TCP_DICT[tcp.sport]
        else:
            data['Procotol'] = "TCP"
        return data

    def udp_decode(self, p, ip):
        data = dict()
        udp = p.getlayer(UDP)
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
        data['Source'] = f"{ip.src}:{ip.sport}"
        data['Destination'] = f"{ip.dst}:{ip.dport}"
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        
        if udp.dport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[udp.dport]
        elif udp.sport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[udp.sport]
        elif udp.dport in self.UDP_DICT:
            data['Procotol'] = self.UDP_DICT[udp.dport]
        elif udp.sport in self.UDP_DICT:
            data['Procotol'] = self.UDP_DICT[udp.sport]
        else:
            data['Procotol'] = "UDP"
        return data
