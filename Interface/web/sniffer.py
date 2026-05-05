import time
import threading
import asyncio
from scapy.all import sniff, TCP, UDP, ICMP, ARP, DNS, STP, Ether
from scapy.contrib.igmp import IGMP
from scapy.layers.l2 import Dot3, LLC
from engine import predict_traffic
import json
from datetime import datetime
import os

def log_prediction(features, prediction):
    """Log predictions to file for auditing"""
    # Create logs folder if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "prediction": prediction,
        "packet_rate": features.get('packet_rate'),
        "byte_rate": features.get('byte_rate'),
        "tcp_syn": features.get('tcp_syn_count', 0),
        "udp_pkt": features.get('udp_packet_count', 0)
    }
    
    try:
        with open('logs/predictions.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        print(f"❌ Logging error: {e}")


def safe_ratio(a, b):
    return round(a / b, 4) if b > 0 else 0.0

class CaptureEngine:
    def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
        self.queue = queue
        self.loop = loop
        self.running = False
        self.thread = None
        # Window state
        self.window_start = time.time()
        self.window_size = 1.0
        self.ip_mac_map = {}
        self.reset_window()

    def reset_window(self):
        self.stats = {
            "packet_count": 0, "total_bytes": 0, "pkt_sizes": [],
            "tcp_pkt_count": 0, "tcp_syn": 0, "tcp_ack": 0, "tcp_rst": 0, "tcp_fin": 0,
            "udp_pkt": 0,
            "icmp_pkt": 0, "icmp_echo_req": 0, "icmp_echo_rep": 0,
            "arp_req": 0, "arp_rep": 0, "grat_arp": 0, "ip_mac_changes": 0,
            "dns_qry": 0, "dns_resp": 0, "dns_resp_sizes": [], "dns_ttls": [],
            "stp_pkt": 0, "stp_tc": 0,
            "igmp_pkt": 0, "igmp_join": 0,
            "src_ips": set(), "dst_ips": set(), "dst_ports": set(),
            "bcast": 0, "mcast": 0,
        }

    def process_packet(self, pkt):
        if not self.running:
            return

        now = time.time()
        if now - self.window_start >= self.window_size:
            self.finalize_window()
            self.window_start = now

        try:
            w = self.stats
            pkt_len = len(pkt)
            w["packet_count"] += 1
            w["total_bytes"] += pkt_len
            w["pkt_sizes"].append(pkt_len)

            is_bcast, is_mcast = False, False
            if pkt.haslayer(Ether):
                dst_mac = pkt[Ether].dst.lower()
                if dst_mac == "ff:ff:ff:ff:ff:ff":
                    is_bcast = True
                elif dst_mac.startswith("01:00:5e") or dst_mac.startswith("33:33"):
                    is_mcast = True

            if pkt.haslayer("IP"):
                src_ip = pkt["IP"].src
                dst_ip = pkt["IP"].dst
                w["src_ips"].add(src_ip)
                w["dst_ips"].add(dst_ip)
                if dst_ip.endswith(".255") or dst_ip == "255.255.255.255":
                    is_bcast = True
                first_octet = int(dst_ip.split(".")[0])
                if 224 <= first_octet <= 239:
                    is_mcast = True

            if is_bcast: w["bcast"] += 1
            if is_mcast: w["mcast"] += 1

            if TCP in pkt:
                w["tcp_pkt_count"] += 1
                flags = pkt[TCP].flags
                if (flags & 0x02) and not (flags & 0x10): w["tcp_syn"] += 1
                if (flags & 0x10) and not (flags & 0x02) and not (flags & 0x04) and not (flags & 0x01): w["tcp_ack"] += 1
                if flags & 0x04: w["tcp_rst"] += 1
                if flags & 0x01: w["tcp_fin"] += 1
                w["dst_ports"].add(pkt[TCP].dport)

            if UDP in pkt:
                w["udp_pkt"] += 1
                w["dst_ports"].add(pkt[UDP].dport)

            if ICMP in pkt:
                w["icmp_pkt"] += 1
                t = pkt[ICMP].type
                if t == 8: w["icmp_echo_req"] += 1
                elif t == 0: w["icmp_echo_rep"] += 1

            if ARP in pkt:
                arp = pkt[ARP]
                if arp.op == 1: w["arp_req"] += 1
                elif arp.op == 2: w["arp_rep"] += 1
                
                if arp.psrc == arp.pdst or arp.pdst == "0.0.0.0":
                    w["grat_arp"] += 1
                    
                sip, smac = arp.psrc, arp.hwsrc
                if sip in self.ip_mac_map and smac != self.ip_mac_map[sip]:
                    w["ip_mac_changes"] += 1
                else:
                    self.ip_mac_map[sip] = smac

            if DNS in pkt:
                dns = pkt[DNS]
                if dns.qr == 0: w["dns_qry"] += 1
                else:
                    w["dns_resp"] += 1
                    w["dns_resp_sizes"].append(len(dns))
                    try:
                        if dns.ancount and dns.an:
                            w["dns_ttls"].append(dns.an.ttl)
                    except Exception:
                        pass

            if pkt.haslayer(STP):
                w["stp_pkt"] += 1
                try:
                    if pkt[STP].bpduflags & 0x01: w["stp_tc"] += 1
                except: pass
            elif pkt.haslayer(Dot3) and pkt.haslayer(LLC):
                try:
                    payload = bytes(pkt[LLC].payload)
                    if len(payload) >= 4 and payload[0:2] == b'\x00\x00':
                        w["stp_pkt"] += 1
                        if payload[3] == 0x00 and len(payload) > 4 and payload[4] & 0x01:
                            w["stp_tc"] += 1
                        elif payload[3] == 0x80:
                            w["stp_tc"] += 1
                except: pass

            if pkt.haslayer(IGMP):
                w["igmp_pkt"] += 1
                try:
                    if pkt[IGMP].type in [0x12, 0x16, 0x22]: w["igmp_join"] += 1
                except: pass

        except Exception as e:
            pass

    def finalize_window(self):
        d = self.stats
        pr = d["packet_count"]
        # Skip empty windows or very low packet ones that might break model completely
        # although our RF might handle it, skip if pr == 0
        if pr == 0:
            self.reset_window()
            return

        br = d["total_bytes"]
        features = {
            "packet_rate": pr,
            "byte_rate": br,
            "mean_pkt_size": round(br / pr, 2),
            "max_pkt_size": max(d["pkt_sizes"]) if d["pkt_sizes"] else 0,
            
            "tcp_syn_count": d["tcp_syn"],
            "tcp_ack_count": d["tcp_ack"],
            "tcp_rst_count": d["tcp_rst"],
            "tcp_fin_count": d["tcp_fin"],
            
            "syn_to_ack_ratio": min(10.0, safe_ratio(d["tcp_syn"], d["tcp_ack"])),
            "rst_to_syn_ratio": safe_ratio(d["tcp_rst"], d["tcp_syn"]),
            "tcp_to_total_ratio": safe_ratio(d["tcp_pkt_count"], pr),
            
            "udp_packet_count": d["udp_pkt"],
            "udp_to_total_ratio": safe_ratio(d["udp_pkt"], pr),
            
            "icmp_packet_count": d["icmp_pkt"],
            "icmp_to_total_ratio": safe_ratio(d["icmp_pkt"], pr),
            "icmp_echo_request_count": d["icmp_echo_req"],
            "icmp_echo_reply_count": d["icmp_echo_rep"],
            "icmp_reply_to_request_ratio": safe_ratio(d["icmp_echo_rep"], d["icmp_echo_req"]),
            
            "arp_request_count": d["arp_req"],
            "arp_reply_count": d["arp_rep"],
            "arp_reply_ratio": safe_ratio(d["arp_rep"], pr),
            "gratuitous_arp_count": d["grat_arp"],
            "gratuitous_to_reply_ratio": safe_ratio(d["grat_arp"], d["arp_rep"]),
            "ip_mac_mapping_changes": d["ip_mac_changes"],
            
            "dns_query_count": d["dns_qry"],
            "dns_response_count": d["dns_resp"],
            "dns_reply_to_query_ratio": min(5.0, safe_ratio(d["dns_resp"], d["dns_qry"])),
            "dns_avg_response_size": round(sum(d["dns_resp_sizes"]) / len(d["dns_resp_sizes"]), 2) if d["dns_resp_sizes"] else 0,
            "dns_ttl_mean": round(sum(d["dns_ttls"]) / len(d["dns_ttls"]), 2) if d["dns_ttls"] else 0,
            
            "stp_packet_count": d["stp_pkt"],
            "stp_topology_change": d["stp_tc"],
            
            "igmp_packet_count": d["igmp_pkt"],
            "igmp_join_count": d["igmp_join"],
            
            "unique_src_ip_count": len(d["src_ips"]),
            "unique_dst_ip_count": len(d["dst_ips"]),
            "unique_dst_ports": len(d["dst_ports"]),
            "broadcast_pkt_count": d["bcast"],
            "multicast_pkt_count": d["mcast"]
        }

        # Predict
        prediction = predict_traffic(features)

        log_prediction(features, prediction)
        # Prepare result to broadcast
        result = {
            "timestamp": time.time(),
            "prediction": prediction,
            "packet_rate": pr,
            "byte_rate": br,
            "tcp_syn": d["tcp_syn"],
            "udp_pkt": d["udp_pkt"],
        }
        
        # safely push to asyncio queue
        asyncio.run_coroutine_threadsafe(self.queue.put(result), self.loop)
        
        self.reset_window()

    def start(self):
        if self.running: return
        self.running = True
        self.window_start = time.time()
        self.reset_window()
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _capture_loop(self):
        # scapy sniff is blocking, so we use stop_filter or timeout. 
        # Using timeout allows checking self.running flag repeatedly.
        while self.running:
            sniff(timeout=1, prn=self.process_packet, store=False)
