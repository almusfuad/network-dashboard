from datetime import datetime
import threading
from log_events import logger
import pandas as pd
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP
import os
import psutil
import socket
from collections import defaultdict


class ConnectionCache:
    """Cache for mapping network connections to processes.
    
    Maintains a periodically updated cache of local IP:port to process mappings
    to efficiently identify which application generated a packet.
    """
    def __init__(self, refresh_interval=2):
        """Initialize connection cache.
        
        Args:
            refresh_interval: Seconds between cache refreshes (default 2s)
        """
        self.cache = {}  # (ip, port, protocol) -> {pid, process_name, exe_path}
        self.refresh_interval = refresh_interval
        self.last_refresh = 0
        self.lock = threading.Lock()
        self.logger = logger
        
    def _refresh_cache(self):
        """Refresh the connection cache from psutil."""
        try:
            new_cache = {}
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                try:
                    # Skip connections without local address
                    if not conn.laddr:
                        continue
                    
                    local_ip = conn.laddr.ip
                    local_port = conn.laddr.port
                    
                    # Determine protocol
                    if conn.type == socket.SOCK_STREAM:
                        protocol = 'TCP'
                    elif conn.type == socket.SOCK_DGRAM:
                        protocol = 'UDP'
                    else:
                        continue
                    
                    # Try to get process info
                    process_info = None
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process_info = {
                                'pid': conn.pid,
                                'process_name': proc.name(),
                                'exe_path': proc.exe()
                            }
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            pass
                    
                    if process_info:
                        key = (local_ip, local_port, protocol)
                        new_cache[key] = process_info
                
                except Exception as e:
                    self.logger.debug(f"Error processing connection: {e}")
                    continue
            
            with self.lock:
                self.cache = new_cache
            
            self.logger.debug(f"Connection cache refreshed with {len(new_cache)} entries")
        except Exception as e:
            self.logger.error(f"Error refreshing connection cache: {e}")
    
    def get_process_info(self, src_ip, src_port, protocol):
        """Get process info for a given connection.
        
        Args:
            src_ip: Source IP address
            src_port: Source port
            protocol: Protocol (TCP or UDP)
            
        Returns:
            Dict with pid, process_name, exe_path or None if not found
        """
        # Refresh cache if needed
        now = datetime.now().timestamp()
        if now - self.last_refresh >= self.refresh_interval:
            self._refresh_cache()
            self.last_refresh = now
        
        # Lookup in cache
        key = (src_ip, src_port, protocol)
        with self.lock:
            return self.cache.get(key)


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
        self.connection_cache = ConnectionCache(refresh_interval=2)




    def get_protocol_name(self, protocol_number: int) -> str:
        return self.protocol_map.get(protocol_number, f'Unknown ({protocol_number})')
    

    def process_packet(self, packet) -> None:
        """Process a single packet and extract relevant information."""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                protocol_num = packet[IP].proto
                protocol_name = self.get_protocol_name(protocol_num)
                src_port = None
                dst_port = None
                
                # Extract port information
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                
                # Get process information from cache
                process_info = None
                if src_port is not None and protocol_name in ['TCP', 'UDP']:
                    process_info = self.connection_cache.get_process_info(
                        src_ip, src_port, protocol_name
                    )
                
                with self.lock:
                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': src_ip,
                        'destination': packet[IP].dst,
                        'protocol': protocol_name,
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
                    
                    # Add process information if found
                    if process_info:
                        packet_info.update({
                            'process_name': process_info.get('process_name', 'Unknown'),
                            'pid': process_info.get('pid'),
                            'exe_path': process_info.get('exe_path'),
                        })
                    else:
                        packet_info.update({
                            'process_name': 'Unknown',
                            'pid': None,
                            'exe_path': None,
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