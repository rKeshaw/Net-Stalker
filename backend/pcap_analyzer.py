import asyncio
import os
import time
from scapy.all import rdpcap
from pcap_utils.pcap_decode import PcapDecode
from pcap_utils import flow_analyzer, statistics

class PCAPAnalyzer:
    def __init__(self):
        self.pd = PcapDecode()

    async def analyze_file(self, file_path: str):
        """
        Asynchronously analyze a PCAP file using Scapy (which is blocking).
        """
        if not os.path.exists(file_path):
            return {"error": "File not found"}

        # Scapy is CPU bound and blocking, run in thread
        return await asyncio.to_thread(self._analyze_sync, file_path)

    def _analyze_sync(self, file_path: str):
        try:
            start_time = time.time()
            pcaps = rdpcap(file_path)
            
            if not pcaps:
                return {"error": "Empty or invalid PCAP file"}

            count = len(pcaps)
            duration = pcaps[-1].time - pcaps[0].time
            host_ip = flow_analyzer.get_host_ip(pcaps)

            # Convert Scapy packets to readable dicts 
            raw_packets = []
            for i, p in enumerate(pcaps[:100]): 
                decoded = self.pd.ether_decode(p)
                decoded['id'] = i + 1
                raw_packets.append(decoded)

            stats = {
                "packet_count": count,
                "duration_seconds": float(duration),
                "host_ip": host_ip,
                "protocol_distribution": statistics.common_proto_statistic(pcaps),
                "packet_lengths": statistics.pcap_len_statistic(pcaps),
                "top_protocols": statistics.most_proto_statistic(pcaps, self.pd),
                "http_stats": statistics.http_statistic(pcaps),
                "dns_stats": statistics.dns_statistic(pcaps),
            }

            flow_data = {
                "time_flow": flow_analyzer.time_flow(pcaps),
                "data_flow_direction": flow_analyzer.data_flow(pcaps, host_ip),
                "protocol_flow_bytes": flow_analyzer.proto_flow(pcaps),
                "ip_traffic": flow_analyzer.data_in_out_ip(pcaps, host_ip)
            }

            geo_data = statistics.get_ipmap(pcaps, host_ip)

            processing_time = time.time() - start_time

            return {
                "analysis_type": "pcap",
                "status": "success",
                "filename": os.path.basename(file_path),
                "metadata": {
                    "packet_count": count,
                    "duration": round(float(duration), 2),
                    "processing_time": round(processing_time, 2)
                },
                "statistics": stats,
                "flow_analysis": flow_data,
                "geo_map": geo_data,
                "raw_packets_sample": raw_packets  # First 100 packets
            }

        except Exception as e:
            return {
                "status": "failed",
                "error": str(e)
            }
