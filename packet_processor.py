from datetime import datetime
import threading
from log_events import logger
import pandas as pd
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP
import os


class PacketProcessor:
    def __init__(self):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()




    def get_protocol_name(self, protocol_number: int) -> str:
        return self.protocol_map.get(protocol_number, f'Unknown ({protocol_number})')
    

    def process_packet(self, packet) -> None:
        """Process a single packet and extract relevant information."""
        try:
            if IP in packet:
                with self.lock:
                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds(),
                    }

                
                    # Add TCP-specific information
                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': packet[TCP].flags,
                        })

                    # Add UDP-specific information
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport,
                        })

                    self.packet_data.append(packet_info)
                    self.packet_count += 1

                    # Keep 10000 packets to prevent memory issues
                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")


    def get_dataframe(self):
        with self.lock:
            return pd.DataFrame(self.packet_data) if self.packet_data else pd.DataFrame()
        


def start_packet_capture(interface=None):
    """Start packet capture on specified interface.
    
    Args:
        interface: Network interface to capture from. If None, tries to auto-detect.
    """
    processor = PacketProcessor()
    
    # Get available interfaces
    available_interfaces = get_if_list()
    logger.info(f"Available interfaces: {available_interfaces}")
    
    # Select interface
    if interface is None:
        # Try to use active interfaces (prefer wlo1, eno1, eth0 over lo)
        preferred = ['wlo1', 'eno1', 'eth0', 'wlan0', 'enp0s3']
        interface = next((iface for iface in preferred if iface in available_interfaces), 
                        available_interfaces[0] if available_interfaces else 'any')
    
    logger.info(f"Starting packet capture on interface: {interface}")
    
    # Check if running with proper privileges
    if os.geteuid() != 0:
        logger.warning("Not running as root. Packet capture may fail. Run with: sudo -E streamlit run app.py")

    def capture_packets():
        try:
            logger.info(f"Sniffing on {interface}...")
            sniff(
                iface=interface,
                prn=processor.process_packet,
                store=False,
                filter="ip",  # Only capture IP packets
                count=0  # Capture indefinitely
            )
        except PermissionError as e:
            logger.error(f"Permission denied. Run with sudo: {e}")
        except Exception as e:
            logger.error(f"Error capturing packets: {e}")

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    return processor