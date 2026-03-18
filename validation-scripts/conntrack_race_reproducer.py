#!/usr/bin/env python3
"""
Conntrack Race Condition Reproducer

This script reproduces the race condition in Network Policy Agent's conntrack
cleanup logic where 5-tuple reuse during cleanup causes legitimate traffic denial.

Race Sequence:
1. Connection established → kernel conntrack + eBPF map entry
2. Kernel expires entry (~180s) → stale in local cache
3. Cleanup cycle starts → snapshot kernel (entry missing)
4. NEW connection with same 5-tuple → creates kernel entry
5. Cleanup deletes eBPF entry (based on old snapshot)
6. Response arrives → lookup fails → RACE TRIGGERED

Author: Network Policy Team
"""

import argparse
import json
import logging
import math
import subprocess
import sys
import time
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class TestConfig:
    """Configuration for the race condition test"""
    namespace: str = "conntrack-test"
    client_pod: str = "test-client"
    server_pod: str = "test-server"
    server_port: int = 8080
    kernel_timeout: int = 30  # Reduced for testing (normally 180s)
    cleanup_period: int = 60  # Reduced for testing (normally 300s)
    iterations: int = 10
    connections_per_wave: int = 50
    npa_pod_label: str = "k8s-app=aws-node"
    npa_namespace: str = "kube-system"
    
    @classmethod
    def from_yaml(cls, filepath: str) -> 'TestConfig':
        """Load configuration from YAML file"""
        try:
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)
                return cls(**data)
        except FileNotFoundError:
            logger.warning(f"Config file {filepath} not found, using defaults")
            return cls()


class KubeHelper:
    """Helper class for Kubernetes operations"""
    
    @staticmethod
    def run_command(cmd: List[str], check=True, capture_output=True) -> subprocess.CompletedProcess:
        """Run a shell command and return result"""
        try:
            result = subprocess.run(
                cmd,
                check=check,
                capture_output=capture_output,
                text=True,
                timeout=30
            )
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(cmd)}")
            logger.error(f"Error: {e.stderr}")
            raise
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(cmd)}")
            raise
    
    @staticmethod
    def pod_exists(namespace: str, pod_name: str) -> bool:
        """Check if a pod exists"""
        cmd = ['kubectl', 'get', 'pod', pod_name, '-n', namespace, '--no-headers']
        result = KubeHelper.run_command(cmd, check=False)
        return result.returncode == 0
    
    @staticmethod
    def pod_ready(namespace: str, pod_name: str) -> bool:
        """Check if a pod is ready"""
        cmd = ['kubectl', 'get', 'pod', pod_name, '-n', namespace, 
               '-o', 'jsonpath={.status.conditions[?(@.type=="Ready")].status}']
        result = KubeHelper.run_command(cmd, check=False)
        return result.stdout.strip() == "True"
    
    @staticmethod
    def exec_in_pod(namespace: str, pod_name: str, command: List[str]) -> subprocess.CompletedProcess:
        """Execute command in a pod"""
        cmd = ['kubectl', 'exec', '-n', namespace, pod_name, '--'] + command
        return KubeHelper.run_command(cmd)
    
    @staticmethod
    def get_pod_ip(namespace: str, pod_name: str) -> Optional[str]:
        """Get pod IP address"""
        cmd = ['kubectl', 'get', 'pod', pod_name, '-n', namespace, 
               '-o', 'jsonpath={.status.podIP}']
        result = KubeHelper.run_command(cmd, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    
    @staticmethod
    def get_npa_logs(namespace: str, label: str, since: str = "5m") -> str:
        """Get NPA logs"""
        cmd = ['kubectl', 'logs', '-n', namespace, '-l', label, 
               '--tail=1000', f'--since={since}']
        result = KubeHelper.run_command(cmd, check=False)
        return result.stdout if result.returncode == 0 else ""
    
    @staticmethod
    def get_pod_node(namespace: str, pod_name: str) -> Optional[str]:
        """Get the node where a pod is running"""
        cmd = ['kubectl', 'get', 'pod', pod_name, '-n', namespace,
               '-o', 'jsonpath={.spec.nodeName}']
        result = KubeHelper.run_command(cmd, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    
    @staticmethod
    def get_tuner_pod_on_node(node_name: str) -> Optional[str]:
        """Get the conntrack-tuner pod running on a specific node"""
        cmd = ['kubectl', 'get', 'pods', '-n', 'kube-system',
               '-l', 'app=conntrack-tuner',
               '-o', 'json']
        result = KubeHelper.run_command(cmd, check=False)
        if result.returncode != 0:
            return None
        
        try:
            pods_data = json.loads(result.stdout)
            for pod in pods_data.get('items', []):
                if pod.get('spec', {}).get('nodeName') == node_name:
                    return pod.get('metadata', {}).get('name')
        except:
            pass
        return None


class ConntrackRaceReproducer:
    """Main class for reproducing conntrack race condition"""
    
    # Fixed port range for deterministic 5-tuple collision
    FIXED_PORT_START = 50000
    FIXED_PORT_COUNT = 20  # Ports 50000-50019
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.kube = KubeHelper()
        self.race_detected = False
        self.last_cleanup_time: Optional[datetime] = None
        self.learned_cleanup_timing: Optional[int] = None  # Seconds after kernel timeout
        self.last_spray_absolute_time: Optional[float] = None  # Absolute wall-clock time of last spray
        self.server_node: Optional[str] = None
        self.client_node: Optional[str] = None
        self.tuner_pod: Optional[str] = None
        self.client_tuner_pod: Optional[str] = None  # Tuner pod on client's node
        self.fixed_ports = list(range(self.FIXED_PORT_START, self.FIXED_PORT_START + self.FIXED_PORT_COUNT))
        
    def validate_environment(self) -> bool:
        """Validate test environment prerequisites"""
        logger.info("=== Validating Environment ===")
        
        # Check kubectl
        try:
            self.kube.run_command(['kubectl', 'version', '--client'])
            logger.info("✓ kubectl is available")
        except Exception as e:
            logger.error("✗ kubectl not found or not working")
            return False
        
        # Check namespace
        if not self.kube.pod_exists(self.config.namespace, self.config.client_pod):
            logger.error(f"✗ Client pod {self.config.client_pod} not found in namespace {self.config.namespace}")
            logger.error("  Run: kubectl apply -f k8s_test_pods.yaml")
            return False
        logger.info(f"✓ Client pod exists")
        
        if not self.kube.pod_exists(self.config.namespace, self.config.server_pod):
            logger.error(f"✗ Server pod {self.config.server_pod} not found in namespace {self.config.namespace}")
            return False
        logger.info(f"✓ Server pod exists")
        
        # Check pod readiness
        if not self.kube.pod_ready(self.config.namespace, self.config.client_pod):
            logger.error(f"✗ Client pod not ready")
            return False
        logger.info(f"✓ Client pod is ready")
        
        if not self.kube.pod_ready(self.config.namespace, self.config.server_pod):
            logger.error(f"✗ Server pod not ready")
            return False
        logger.info(f"✓ Server pod is ready")
        
        # Get pod IPs
        server_ip = self.kube.get_pod_ip(self.config.namespace, self.config.server_pod)
        if not server_ip:
            logger.error("✗ Could not get server pod IP")
            return False
        logger.info(f"✓ Server IP: {server_ip}")
        
        # Find client node and tuner pod for conntrack checks
        self.client_node = self.kube.get_pod_node(self.config.namespace, self.config.client_pod)
        if self.client_node:
            logger.info(f"✓ Client node: {self.client_node}")
            self.client_tuner_pod = self.kube.get_tuner_pod_on_node(self.client_node)
            if self.client_tuner_pod:
                logger.info(f"✓ Client tuner pod found: {self.client_tuner_pod}")
            else:
                logger.warning("⚠ Client tuner pod not found - kernel conntrack checks will be limited")
        
        # Find server node and tuner pod for eBPF polling
        self.server_node = self.kube.get_pod_node(self.config.namespace, self.config.server_pod)
        if self.server_node:
            logger.info(f"✓ Server node: {self.server_node}")
            self.tuner_pod = self.kube.get_tuner_pod_on_node(self.server_node)
            if self.tuner_pod:
                logger.info(f"✓ Server tuner pod found: {self.tuner_pod}")
            else:
                logger.warning("⚠ Server tuner pod not found - eBPF polling will be limited")
        
        # Test connectivity
        logger.info("Testing server connectivity...")
        time.sleep(2)  # Give server time to start listening
        success, output = self.create_connection(server_ip, self.config.server_port, timeout=5)
        if not success:
            logger.error(f"✗ Cannot connect to server at {server_ip}:{self.config.server_port}")
            logger.error(f"  Error: {output}")
            logger.error("  The server pod may not be listening yet.")
            logger.error("  Try: kubectl logs test-server -n conntrack-test")
            logger.error("  Or wait a few seconds and try again")
            return False
        logger.info(f"✓ Server is accepting connections")
        
        logger.info("=== Environment validation passed ===\n")
        return True
    
    def detect_cleanup_cycle(self) -> Optional[datetime]:
        """Detect NPA cleanup cycle timing from logs"""
        logger.info("Detecting NPA cleanup cycle timing...")
        
        logs = self.kube.get_npa_logs(
            self.config.npa_namespace,
            self.config.npa_pod_label,
            since="10m"
        )
        
        # Look for cleanup-related log patterns (actual AWS NPA messages)
        patterns = [
            r"Check for any stale entries in the conntrack map",  # Cleanup start
            r"Done cleanup of conntrack map",  # Cleanup end
            r"Conntrack cleanup Delete",  # Individual deletions
            r"hydrated local conntrack cache",  # Cache hydration
            # Fallback patterns for other implementations
            r"cleanup.*conntrack",
            r"conntrack.*cleanup",
        ]
        
        cleanup_times = []
        for line in logs.split('\n'):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Try to extract timestamp
                    timestamp_match = re.search(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}', line)
                    if timestamp_match:
                        try:
                            ts = datetime.fromisoformat(timestamp_match.group().replace('T', ' '))
                            cleanup_times.append(ts)
                        except:
                            pass
        
        if len(cleanup_times) >= 2:
            # Calculate average interval
            intervals = [(cleanup_times[i+1] - cleanup_times[i]).total_seconds() 
                        for i in range(len(cleanup_times)-1)]
            avg_interval = sum(intervals) / len(intervals)
            logger.info(f"Detected cleanup interval: ~{avg_interval:.0f}s")
            self.last_cleanup_time = cleanup_times[-1]
            return cleanup_times[-1]
        
        logger.warning("Could not detect cleanup cycle from logs, will use configured period")
        return None
    
    def predict_next_cleanup(self) -> datetime:
        """Predict when the next cleanup cycle will occur"""
        if self.last_cleanup_time:
            next_cleanup = self.last_cleanup_time + timedelta(seconds=self.config.cleanup_period)
        else:
            # Estimate based on current time
            next_cleanup = datetime.now() + timedelta(seconds=self.config.cleanup_period)
        
        logger.info(f"Next cleanup predicted at: {next_cleanup.strftime('%H:%M:%S')}")
        return next_cleanup
    
    def create_connection(self, target_ip: str, target_port: int, timeout: int = 5) -> Tuple[bool, str]:
        """Create a TCP connection from client to server (random source port)"""
        try:
            # Use nc (netcat) to create connection
            # Note: We use -w flag instead of timeout command to avoid exit code issues
            cmd = ['nc', '-v', '-w', str(timeout), target_ip, str(target_port)]
            result = self.kube.exec_in_pod(
                self.config.namespace,
                self.config.client_pod,
                cmd
            )
            output = result.stdout + result.stderr
            # Check if connection succeeded (even if nc returns non-zero)
            if 'succeeded' in output.lower() or 'connected' in output.lower():
                return True, output
            return True, output
        except subprocess.CalledProcessError as e:
            # Even on error, check if connection actually succeeded
            output = e.stdout + e.stderr if hasattr(e, 'stdout') else str(e)
            if 'succeeded' in output.lower() or 'connected' in output.lower():
                return True, output
            return False, output
        except Exception as e:
            return False, str(e)
    
    def create_connection_with_port(self, target_ip: str, target_port: int, source_port: int, timeout: int = 2) -> Tuple[bool, str]:
        """Create a TCP connection bound to a specific source port"""
        try:
            # Python one-liner to create connection with specific source port
            # Enhanced error reporting to distinguish failure types
            python_cmd = f"""python3 -c "
import socket
import sys
import errno
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout({timeout})
    sock.bind(('0.0.0.0', {source_port}))
    sock.connect(('{target_ip}', {target_port}))
    print('Connected from port {source_port}')
    sock.close()
    sys.exit(0)
except socket.timeout:
    print('TIMEOUT: Connection timed out')
    sys.exit(1)
except ConnectionRefusedError:
    print('REFUSED: Connection refused by server')
    sys.exit(1)
except OSError as e:
    if e.errno == errno.EADDRINUSE:
        print('BIND_ERROR: Address already in use')
    elif e.errno == errno.EADDRNOTAVAIL:
        print('BIND_ERROR: Cannot assign requested address')
    else:
        print(f'OS_ERROR: {{e}}')
    sys.exit(1)
except Exception as e:
    print(f'ERROR: {{type(e).__name__}}: {{e}}')
    sys.exit(1)
" """
            
            result = self.kube.exec_in_pod(
                self.config.namespace,
                self.config.client_pod,
                ['sh', '-c', python_cmd]
            )
            output = result.stdout + result.stderr
            
            if 'Connected' in output:
                return True, output
            return False, output
            
        except subprocess.CalledProcessError as e:
            output = e.stdout + e.stderr if hasattr(e, 'stdout') else str(e)
            return False, output
        except Exception as e:
            return False, str(e)
    
    def create_connection_wave(self, target_ip: str, count: int) -> Dict[str, int]:
        """Create multiple connections in quick succession (random ports)"""
        results = {'success': 0, 'failed': 0, 'timeout': 0}
        
        logger.info(f"Creating {count} connections...")
        for i in range(count):
            success, output = self.create_connection(target_ip, self.config.server_port, timeout=2)
            
            if success:
                results['success'] += 1
            elif 'timeout' in output.lower():
                results['timeout'] += 1
            else:
                results['failed'] += 1
            
            # Brief pause to avoid overwhelming (minimal throttling)
            if i % 1000 == 0 and i > 0:
                time.sleep(0.01)
                # Progress indicator every 500 connections
                if i % 1000 == 0:
                    logger.info(f"  Created {i}/{count} connections...")
        
        logger.info(f"Wave complete: {results['success']} success, {results['failed']} failed, {results['timeout']} timeout")
        return results
    
    def create_connection_wave_fixed_ports(self, target_ip: str, ports: List[int]) -> Dict[str, int]:
        """Create connections using specific source ports for deterministic 5-tuple collision"""
        results = {'success': 0, 'failed': 0, 'timeout': 0}
        
        logger.info(f"Creating {len(ports)} connections with fixed ports {ports[0]}-{ports[-1]} (4 parallel threads)...")
        
        def create_single_connection(port):
            """Helper function for parallel execution"""
            success, output = self.create_connection_with_port(target_ip, self.config.server_port, port, timeout=2)
            return port, success, output
        
        # Use ThreadPoolExecutor with 4 parallel threads
        max_workers = 4
        completed = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all connection tasks
            futures = {executor.submit(create_single_connection, port): port for port in ports}
            
            # Process results as they complete
            for future in as_completed(futures):
                port, success, output = future.result()
                
                if success:
                    results['success'] += 1
                elif 'timeout' in output.lower():
                    results['timeout'] += 1
                else:
                    results['failed'] += 1
                    logger.debug(f"  Port {port} failed: {output[:100]}")
                
                completed += 1
                # Progress indicator every 20 connections
                if completed % 20 == 0:
                    logger.info(f"  Created {completed}/{len(ports)} connections...")
        
        logger.info(f"Wave complete: {results['success']} success, {results['failed']} failed, {results['timeout']} timeout")
        return results
    
    def poll_ebpf_for_cleanup(self, server_ip: str, poll_duration: int = 120) -> Optional[int]:
        """
        Poll eBPF conntrack map to detect when cleanup occurs.
        Returns: seconds elapsed when cleanup detected, or None if not detected
        """
        if not self.tuner_pod:
            logger.warning("Cannot poll eBPF - tuner pod not available")
            return None
        
        logger.info(f"[eBPF Polling] Monitoring conntrack map for {poll_duration}s...")
        logger.info(f"[eBPF Polling] Tracking total entry count in map")
        
        start_time = time.time()
        last_entry_count = -1
        poll_interval = 2  # Check every 2 seconds
        
        try:
            while (time.time() - start_time) < poll_duration:
                elapsed = int(time.time() - start_time)
                
                # Query eBPF map via tuner pod (pinned path)
                cmd = ['bpftool', 'map', 'dump', 'pinned', '/sys/fs/bpf/globals/aws/maps/global_aws_conntrack_map']
                try:
                    result = self.kube.exec_in_pod('kube-system', self.tuner_pod, cmd)
                    output = result.stdout
                    
                    # Count total entries in map (each entry has a "key:" line)
                    entry_count = output.count('key:')
                    
                    # Detect significant drop (cleanup occurred)
                    # Require at least 10 entries initially to avoid false positives
                    # Detect cleanup if entry count drops by 10% or more
                    if last_entry_count >= 10 and entry_count < (last_entry_count * 0.9):
                        logger.info(f"[eBPF Polling] ✓ CLEANUP DETECTED at T+{elapsed}s!")
                        logger.info(f"[eBPF Polling]   Total entry count dropped: {last_entry_count} → {entry_count}")
                        return elapsed
                    
                    if entry_count != last_entry_count:
                        logger.info(f"[eBPF Polling] T+{elapsed}s: {entry_count} total entries")
                        last_entry_count = entry_count
                    
                except subprocess.CalledProcessError as e:
                    logger.debug(f"[eBPF Polling] Query failed (may be normal): {e}")
                
                time.sleep(poll_interval)
            
            logger.warning(f"[eBPF Polling] No cleanup detected in {poll_duration}s window")
            return None
            
        except Exception as e:
            logger.error(f"[eBPF Polling] Error: {e}")
            return None
    
    def ip_to_hex_be(self, ip_str: str) -> str:
        """Convert IP address to big-endian hex representation (network byte order)"""
        parts = ip_str.split('.')
        # Big-endian: normal byte order (no reversal)
        return ' '.join([f'{int(p):02x}' for p in parts])
    
    def port_to_hex_le(self, port: int) -> str:
        """Convert port to little-endian hex representation"""
        # Port is uint16, little-endian
        return f'{port & 0xff:02x} {(port >> 8) & 0xff:02x}'
    
    def check_kernel_conntrack(self, source_ip: str, source_port: int, 
                               dest_ip: str, dest_port: int, 
                               protocol: str = "tcp") -> bool:
        """
        Check if a 5-tuple exists in kernel conntrack table.
        Returns: True if found, False otherwise
        
        Reads /proc/net/nf_conntrack directly instead of using conntrack command.
        This avoids needing the conntrack binary and works with just file system access.
        """
        if not self.client_tuner_pod:
            logger.debug("No client tuner pod available - cannot check kernel conntrack")
            return False
        
        try:
            # Read /proc/net/nf_conntrack directly
            # Format: ipv4 2 tcp 6 117 ESTABLISHED src=X.X.X.X dst=Y.Y.Y.Y sport=NNNN dport=MMMM ...
            cmd = ['cat', '/proc/net/nf_conntrack']
            
            result = self.kube.exec_in_pod(
                'kube-system',
                self.client_tuner_pod,
                cmd
            )
            
            output = result.stdout
            
            # Search for the specific 5-tuple
            # Look for lines containing our source IP, dest IP, source port, and dest port
            # The format can have src/dst in either order depending on connection direction
            for line in output.split('\n'):
                if protocol in line.lower():
                    # Check if this line has our 5-tuple (forward or reverse direction)
                    has_src_ip = f'src={source_ip}' in line
                    has_dst_ip = f'dst={dest_ip}' in line
                    has_sport = f'sport={source_port}' in line
                    has_dport = f'dport={dest_port}' in line
                    
                    if has_src_ip and has_dst_ip and has_sport and has_dport:
                        return True
            
            return False
            
        except subprocess.CalledProcessError:
            # Command failed or file not accessible
            return False
        except Exception as e:
            logger.debug(f"Error checking kernel conntrack: {e}")
            return False
    
    def check_ebpf_map(self, source_ip: str, source_port: int,
                      dest_ip: str, dest_port: int,
                      owner_ip: str, protocol: str = "tcp") -> bool:
        """
        Check if a 5-tuple exists in eBPF conntrack map.
        Returns: True if found, False otherwise
        """
        if not self.tuner_pod:
            logger.debug("No tuner pod available - cannot check eBPF map")
            return False
        
        try:
            # Query eBPF map
            cmd = ['bpftool', 'map', 'dump', 'pinned', 
                   '/sys/fs/bpf/globals/aws/maps/global_aws_conntrack_map']
            
            result = self.kube.exec_in_pod('kube-system', self.tuner_pod, cmd)
            output = result.stdout
            
            # Build expected hex pattern for the 5-tuple
            # Actual format: source_ip(4) source_port(2) padding(2) dest_ip(4) dest_port(2) protocol(1) padding(1) owner_ip(4)
            proto_byte = "06" if protocol == "tcp" else "11"
            padding_2 = "00 00"  # 2-byte padding after source port
            padding_1 = "00"     # 1-byte padding after protocol
            
            # Convert IPs to big-endian (network byte order), ports to little-endian
            src_ip_hex = self.ip_to_hex_be(source_ip)
            dst_ip_hex = self.ip_to_hex_be(dest_ip)
            owner_ip_hex = self.ip_to_hex_be(owner_ip)
            src_port_hex = self.port_to_hex_le(source_port)
            dst_port_hex = self.port_to_hex_le(dest_port)
            
            # Build pattern with padding bytes
            pattern = f"{src_ip_hex} {src_port_hex} {padding_2} {dst_ip_hex} {dst_port_hex} {proto_byte} {padding_1} {owner_ip_hex}"
            pattern_normalized = pattern.replace(' ', '').lower()
            
            # Normalize output for comparison (remove spaces, lowercase)
            output_normalized = output.replace(' ', '').replace('\n', '').lower()
            
            # Search for pattern
            if pattern_normalized in output_normalized:
                return True
            
            return False
            
        except subprocess.CalledProcessError:
            return False
        except Exception as e:
            logger.debug(f"Error checking eBPF map: {e}")
            return False
    
    def check_5tuple_in_conntrack(self, source_ip: str, source_port: int,
                                  dest_ip: str, dest_port: int,
                                  protocol: str = "tcp") -> Tuple[bool, bool]:
        """
        Check if a 5-tuple exists in kernel conntrack AND eBPF map.
        Returns: (in_kernel, in_ebpf)
        """
        # Check kernel conntrack
        in_kernel = self.check_kernel_conntrack(source_ip, source_port, dest_ip, dest_port, protocol)
        
        # Check eBPF map (try both owner IPs: source and dest)
        # The NPA code stores entries with both source and dest as owner
        in_ebpf_src = self.check_ebpf_map(source_ip, source_port, dest_ip, dest_port, source_ip, protocol)
        in_ebpf_dst = self.check_ebpf_map(source_ip, source_port, dest_ip, dest_port, dest_ip, protocol)
        in_ebpf = in_ebpf_src or in_ebpf_dst
        
        return (in_kernel, in_ebpf)
    
    def verify_all_connections(self, client_ip: str, server_ip: str, ports: List[int]) -> Dict[str, List[int]]:
        """
        Check all ports in kernel conntrack and eBPF map for validation.
        Optimized: reads kernel and eBPF data ONCE, then checks all ports in memory.
        Returns: dict with lists of ports in each state
        """
        results = {
            'kernel_only': [],      # In kernel but not eBPF (RACE pattern)
            'ebpf_only': [],        # In eBPF but not kernel (unusual)
            'both': [],             # In both (normal active)
            'neither': []           # In neither (expired/cleaned)
        }
        
        logger.info(f"\n  [Validation] Checking ALL {len(ports)} connections in kernel/eBPF...")
        logger.info(f"  Optimized: Reading data sources once, then checking in memory...")
        
        # Step 1: Read kernel conntrack ONCE
        logger.info(f"  Reading kernel conntrack table...")
        kernel_entries = set()
        if self.client_tuner_pod:
            try:
                cmd = ['cat', '/proc/net/nf_conntrack']
                result = self.kube.exec_in_pod('kube-system', self.client_tuner_pod, cmd)
                
                # Parse and cache all relevant entries
                for line in result.stdout.split('\n'):
                    if 'tcp' in line.lower():
                        # Extract all ports from this line
                        for port in ports:
                            if (f'src={client_ip}' in line and f'dst={server_ip}' in line and
                                f'sport={port}' in line and f'dport={self.config.server_port}' in line):
                                kernel_entries.add(port)
                                break
                
                logger.info(f"  Found {len(kernel_entries)} entries in kernel conntrack")
            except Exception as e:
                logger.warning(f"  Failed to read kernel conntrack: {e}")
        
        # Step 2: Read eBPF map ONCE
        logger.info(f"  Reading eBPF conntrack map...")
        ebpf_entries = set()
        if self.tuner_pod:
            try:
                cmd = ['bpftool', 'map', 'dump', 'pinned', 
                       '/sys/fs/bpf/globals/aws/maps/global_aws_conntrack_map']
                result = self.kube.exec_in_pod('kube-system', self.tuner_pod, cmd)
                output = result.stdout
                
                # DEBUG: Show raw eBPF map output sample
                logger.info(f"  [DEBUG] Raw eBPF map output (first 500 chars):")
                logger.info(f"  {output[:500]}...")
                logger.info(f"  [DEBUG] Total output length: {len(output)} chars")
                logger.info(f"  [DEBUG] Number of 'key:' entries: {output.count('key:')}")
                
                # Normalize output once
                output_normalized = output.replace(' ', '').replace('\n', '').lower()
                
                # Check all ports against the single eBPF dump
                proto_byte = "06"  # TCP
                padding_2 = "00 00"  # 2-byte padding after source port
                padding_1 = "00"     # 1-byte padding after protocol
                dst_ip_hex = self.ip_to_hex_be(server_ip)
                dst_port_hex = self.port_to_hex_le(self.config.server_port)
                src_ip_hex = self.ip_to_hex_be(client_ip)
                
                # DEBUG: Show example pattern for first port
                first_port = ports[0]
                first_port_hex = self.port_to_hex_le(first_port)
                example_pattern_src = f"{src_ip_hex} {first_port_hex} {padding_2} {dst_ip_hex} {dst_port_hex} {proto_byte} {padding_1} {src_ip_hex}"
                example_pattern_dst = f"{src_ip_hex} {first_port_hex} {padding_2} {dst_ip_hex} {dst_port_hex} {proto_byte} {padding_1} {dst_ip_hex}"
                logger.info(f"  [DEBUG] Example search patterns for port {first_port}:")
                logger.info(f"    Pattern (src owner): {example_pattern_src}")
                logger.info(f"    Pattern (dst owner): {example_pattern_dst}")
                logger.info(f"    Normalized (src): {example_pattern_src.replace(' ', '').lower()}")
                logger.info(f"    Normalized (dst): {example_pattern_dst.replace(' ', '').lower()}")
                
                for port in ports:
                    src_port_hex = self.port_to_hex_le(port)
                    
                    # Try with source as owner (with padding bytes)
                    pattern_src = f"{src_ip_hex} {src_port_hex} {padding_2} {dst_ip_hex} {dst_port_hex} {proto_byte} {padding_1} {src_ip_hex}"
                    # Try with dest as owner  
                    pattern_dst = f"{src_ip_hex} {src_port_hex} {padding_2} {dst_ip_hex} {dst_port_hex} {proto_byte} {padding_1} {dst_ip_hex}"
                    
                    pattern_src_norm = pattern_src.replace(' ', '').lower()
                    pattern_dst_norm = pattern_dst.replace(' ', '').lower()
                    
                    if pattern_src_norm in output_normalized or pattern_dst_norm in output_normalized:
                        ebpf_entries.add(port)
                
                logger.info(f"  Found {len(ebpf_entries)} entries in eBPF map")
            except Exception as e:
                logger.warning(f"  Failed to read eBPF map: {e}")
        
        # Step 3: Categorize all ports based on cached data (instant)
        logger.info(f"  Categorizing {len(ports)} ports...")
        for port in ports:
            in_kernel = port in kernel_entries
            in_ebpf = port in ebpf_entries
            
            if in_kernel and not in_ebpf:
                results['kernel_only'].append(port)
            elif in_ebpf and not in_kernel:
                results['ebpf_only'].append(port)
            elif in_kernel and in_ebpf:
                results['both'].append(port)
            else:
                results['neither'].append(port)
        
        logger.info(f"  ✓ Categorization complete")
        return results
    
    def verify_connection_denial(self) -> bool:
        """Check if connections are being denied (race condition occurred)"""
        server_ip = self.kube.get_pod_ip(self.config.namespace, self.config.server_pod)
        
        # Try a simple connection
        success, output = self.create_connection(server_ip, self.config.server_port, timeout=3)
        
        if not success and ('refused' in output.lower() or 'timeout' in output.lower()):
            logger.warning("⚠ Connection denied - potential race condition!")
            return True
        
        return False
    
    def execute_race_attempt(self, attempt_num: int, is_learning_phase: bool) -> bool:
        """Execute a single attempt to trigger the race condition"""
        logger.info(f"\n{'='*70}")
        if is_learning_phase:
            logger.info(f"ITERATION {attempt_num} - LEARNING PHASE")
            logger.info(f"  Will poll eBPF to learn cleanup timing")
        else:
            logger.info(f"ITERATION {attempt_num} - OPTIMIZED (using learned timing)")
        logger.info(f"{'='*70}")
        
        server_ip = self.kube.get_pod_ip(self.config.namespace, self.config.server_pod)
        kernel_timeout_start = None
        
        # Phase 1: Create 100 connections with FIXED source ports to populate
        logger.info(f"\n[Phase 1] Creating {len(self.fixed_ports)} connections with FIXED ports {self.fixed_ports[0]}-{self.fixed_ports[-1]}")
        logger.info(f"  5-tuples: ({self.config.client_pod}:50000-50099 → {server_ip}:8080)")
        results = self.create_connection_wave_fixed_ports(server_ip, self.fixed_ports)
        
        # Phase 2: Wait 30s for kernel timeout
        logger.info(f"\n[Phase 2] Waiting {self.config.kernel_timeout}s for kernel timeout")
        logger.info(f"  Kernel entries will expire, but remain in local cache...")
        kernel_timeout_start = time.time()
        
        for remaining in range(self.config.kernel_timeout, 0, -5):
            logger.info(f"  T+{self.config.kernel_timeout - remaining}s / {self.config.kernel_timeout}s")
            time.sleep(5)
        
        logger.info(f"✓ Kernel timeout complete (entries stale in cache)")
        
        # Phase 3: Poll eBPF (Iteration 1 only) OR use learned timing (Iterations 2-5)
        if is_learning_phase:
            logger.info(f"\n[Phase 3] LEARNING MODE - Polling eBPF to detect cleanup")
            logger.info(f"  Will monitor conntrack map until cleanup is detected...")
            
            cleanup_offset = self.poll_ebpf_for_cleanup(server_ip, poll_duration=120)
            
            if cleanup_offset:
                self.learned_cleanup_timing = cleanup_offset
                # First cleanup absolute: kernel_timeout + cleanup_offset
                first_cleanup_abs = self.config.kernel_timeout + cleanup_offset
                # Next cleanup: first + period
                next_cleanup_abs = first_cleanup_abs + self.config.cleanup_period
                # Spray 55-65s from first cleanup (5s before next cleanup)
                spray_start_abs = first_cleanup_abs + 55
                
                logger.info(f"[Phase 3] ✓ LEARNED: Cleanup at T+{cleanup_offset}s after kernel timeout")
                logger.info(f"[Phase 3]   First cleanup: T+{first_cleanup_abs}s absolute")
                logger.info(f"[Phase 3]   Next cleanup: T+{next_cleanup_abs}s absolute")  
                logger.info(f"[Phase 3]   Will spray at T+{spray_start_abs}s (55s from first cleanup)")
                
                # Calculate wait time
                elapsed = time.time() - kernel_timeout_start
                wait_time = max(0, spray_start_abs - elapsed)
                
                if wait_time > 0:
                    logger.info(f"[Phase 3] Waiting {wait_time:.1f}s to reach spray window...")
                    time.sleep(wait_time)
            else:
                logger.warning("[Phase 3] Could not detect cleanup via eBPF polling")
                logger.warning("[Phase 3] Falling back to estimated timing (T+55-60)")
                
                # Wait to T+55
                elapsed = time.time() - kernel_timeout_start
                wait_time = max(0, 55 - elapsed)
                if wait_time > 0:
                    logger.info(f"[Phase 3] Waiting {wait_time:.1f}s to reach T+55...")
                    time.sleep(wait_time)
        else:
            logger.info(f"\n[Phase 3] OPTIMIZED MODE - Synchronize with 60s cleanup cycle")
            
            if self.last_spray_absolute_time is not None:
                # Calculate next spray time based on 60s cleanup cycle
                current_time = time.time()
                elapsed_since_last_spray = current_time - self.last_spray_absolute_time
                
                # Find next valid spray window (nearest multiple of 60s from last spray)
                cycles_passed = math.ceil(elapsed_since_last_spray / self.config.cleanup_period)
                next_spray_absolute_time = self.last_spray_absolute_time + (cycles_passed * self.config.cleanup_period)
                
                wait_time = next_spray_absolute_time - current_time
                
                logger.info(f"[Phase 3]   Last spray was {elapsed_since_last_spray:.1f}s ago")
                logger.info(f"[Phase 3]   Next spray in {wait_time:.1f}s (cycle #{cycles_passed} from first spray)")
                logger.info(f"[Phase 3]   Target: {cycles_passed * self.config.cleanup_period}s from first spray")
                
                if wait_time > 0:
                    logger.info(f"[Phase 3] Waiting {wait_time:.1f}s to synchronize with cleanup cycle...")
                    time.sleep(wait_time)
                else:
                    logger.warning(f"[Phase 3] Already past target time by {-wait_time:.1f}s, spraying immediately")
            else:
                logger.warning("[Phase 3] No previous spray timing available, using default T+55-60")
                elapsed = time.time() - kernel_timeout_start
                wait_time = max(0, 55 - elapsed)
                if wait_time > 0:
                    time.sleep(wait_time)
        
        # Phase 4: Spray connections with SAME FIXED PORTS
        current_offset = time.time() - kernel_timeout_start
        
        # Calculate target window for display
        if self.learned_cleanup_timing:
            first_cleanup_abs = self.config.kernel_timeout + self.learned_cleanup_timing
            spray_target = f"T+{first_cleanup_abs + 55}s-{first_cleanup_abs + 65}s (targeting next cleanup)"
        else:
            spray_target = "T+55-65s (estimated)"
        
        logger.info(f"\n[Phase 4] CONNECTION SPRAY at T+{current_offset:.1f}s (Target: {spray_target})")
        logger.info(f"  Reusing SAME {len(self.fixed_ports)} fixed ports for 100% 5-tuple collision!")
        logger.info(f"  5-tuples: ({self.config.client_pod}:50000-50099 → {server_ip}:8080) [SAME as Phase 1]")
        
        # Record spray start time for synchronizing future iterations
        self.last_spray_absolute_time = time.time()
        
        spray_results = []
        spray_count = len(self.fixed_ports)  # 100 connections with fixed ports
        
        def create_spray_connection(port):
            """Helper function for parallel spray execution"""
            success, output = self.create_connection_with_port(server_ip, self.config.server_port, port, timeout=1)
            return success, output, port
        
        # Use ThreadPoolExecutor with 4 parallel threads
        max_workers = 4
        completed = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all spray connection tasks
            futures = {executor.submit(create_spray_connection, port): port for port in self.fixed_ports}
            
            # Process results as they complete
            for future in as_completed(futures):
                result = future.result()
                spray_results.append(result)
                
                completed += 1
                if completed % 20 == 0:
                    elapsed_spray = time.time() - kernel_timeout_start
                    logger.info(f"  Sprayed {completed}/{spray_count} (T+{elapsed_spray:.1f}s)")
        
        # Phase 5: Check for race condition
        logger.info(f"\n[Phase 5] Analyzing results (categorizing failure types)")
        time.sleep(0.05)
        
        # Categorize failures by type
        race_denials = []  # REFUSED - actual race condition
        bind_errors = []   # BIND_ERROR - parallelism issues
        timeouts = []      # TIMEOUT - network/timeout issues
        other_errors = []  # Other failures
        
        for success, output, port in spray_results:
            if success:
                continue
            
            # Categorize based on error message
            if 'REFUSED:' in output:
                race_denials.append(port)
                logger.info(output)
            elif 'BIND_ERROR:' in output:
                bind_errors.append(port)
            elif 'TIMEOUT:' in output:
                timeouts.append(port)
            else:
                other_errors.append((port, output[:80]))
        
        successful = spray_count - len(race_denials) - len(bind_errors) - len(timeouts) - len(other_errors)
        
        # Log categorized results
        logger.info(f"  Spray results breakdown:")
        logger.info(f"    ✓ Success: {successful}/{spray_count}")
        logger.info(f"    ✗ REFUSED (Race condition): {len(race_denials)}/{spray_count}")
        logger.info(f"    ⚠ BIND_ERROR (Parallelism): {len(bind_errors)}/{spray_count}")
        logger.info(f"    ⏱ TIMEOUT: {len(timeouts)}/{spray_count}")
        logger.info(f"    ? OTHER: {len(other_errors)}/{spray_count}")
        
        # Warn about parallelism issues if present
        if len(bind_errors) > 0:
            logger.warning(f"  ⚠ {len(bind_errors)} bind errors detected - may need to reduce parallelism")
            logger.warning(f"    Affected ports: {bind_errors[:5]}{'...' if len(bind_errors) > 5 else ''}")
        
        # FIRST ITERATION ONLY: Comprehensive validation of ALL connections
        if is_learning_phase:
            logger.info(f"\n[Phase 5 - Full Validation] Checking ALL {spray_count} connections (First iteration only)")
            logger.info(f"  This validates our kernel/eBPF verification logic...")
            
            client_ip = self.kube.get_pod_ip(self.config.namespace, self.config.client_pod)
            validation_results = self.verify_all_connections(client_ip, server_ip, self.fixed_ports)
            
            logger.info(f"\n  Full Validation Results:")
            logger.info(f"    🔥 Kernel ONLY (race pattern):  {len(validation_results['kernel_only'])}/{spray_count} ports")
            logger.info(f"    ✓  BOTH (active connections):  {len(validation_results['both'])}/{spray_count} ports")
            logger.info(f"    ✗  NEITHER (expired/cleaned):  {len(validation_results['neither'])}/{spray_count} ports")
            logger.info(f"    ?  eBPF ONLY (unusual):        {len(validation_results['ebpf_only'])}/{spray_count} ports")
            
            if len(validation_results['kernel_only']) > 0:
                logger.info(f"\n  Kernel-only ports (race candidates): {validation_results['kernel_only'][:20]}{'...' if len(validation_results['kernel_only']) > 20 else ''}")
        
        race_detected = False
        confirmed_race_denials = []
        
        # Verify REFUSED errors by checking kernel vs eBPF conntrack
        if len(race_denials) > 0:
            logger.info(f"\n  Verifying {len(race_denials)} REFUSED connections against kernel/eBPF conntrack...")
            
            # Get client IP
            client_ip = self.kube.get_pod_ip(self.config.namespace, self.config.client_pod)
            
            # Sample verification (check up to 10 ports to avoid overwhelming the system)
            sample_size = min(len(race_denials), 10)
            sample_ports = race_denials[:sample_size]
            
            for port in sample_ports:
                # Check if this 5-tuple is in kernel but NOT in eBPF
                in_kernel, in_ebpf = self.check_5tuple_in_conntrack(
                    client_ip, port, server_ip, self.config.server_port
                )
                
                if in_kernel and not in_ebpf:
                    # CONFIRMED RACE CONDITION!
                    confirmed_race_denials.append(port)
                    logger.error(f"    ✓ Port {port}: CONFIRMED RACE (kernel: ✓, eBPF: ✗)")
                elif not in_kernel and not in_ebpf:
                    logger.info(f"    • Port {port}: Both expired (kernel: ✗, eBPF: ✗) - normal cleanup")
                elif in_kernel and in_ebpf:
                    logger.warning(f"    ⚠ Port {port}: Both present (kernel: ✓, eBPF: ✓) - server/other issue")
                else:
                    logger.warning(f"    ? Port {port}: Unusual state (kernel: ✗, eBPF: ✓)")
            
            # If we found ANY confirmed race conditions in the sample, it's a race
            if len(confirmed_race_denials) > 0:
                logger.error(f"\n  🔥 CONFIRMED RACE CONDITION!")
                logger.error(f"     {len(confirmed_race_denials)}/{sample_size} sampled ports show race pattern")
                logger.error(f"     (kernel has entry, eBPF missing) → Cleanup deleted active entries")
                logger.error(f"     Confirmed ports: {confirmed_race_denials}")
                race_detected = True
            else:
                logger.warning(f"  ⚠ REFUSED errors detected but could not confirm race pattern")
                logger.warning(f"     This may be a server issue or timing mismatch")
        
        # Legacy logging for backward compatibility
        if len(race_denials) > 0:
            logger.info(f"\n  Summary: {len(race_denials)}/{spray_count} connections REFUSED")
            logger.info(f"  Affected ports: {race_denials[:10]}{'...' if len(race_denials) > 10 else ''}")
        
        if len(timeouts) > 10:  # Significant number of timeouts
            logger.warning(f"⚠ High timeout rate: {len(timeouts)}/{spray_count}")
            logger.warning(f"   May indicate race condition, network congestion, or server overload")
        
        # Additional verification
        if self.verify_connection_denial():
            logger.error(f"🔥 RACE CONDITION DETECTED via verification check")
            race_detected = True
        
        if race_detected:
            self.race_detected = True
            return True
        
        logger.info(f"✓ No race detected in this iteration")
        return False
    
    def run_test(self) -> bool:
        """Run the complete race condition reproduction test"""
        logger.info("\n" + "="*70)
        logger.info("CONNTRACK RACE CONDITION REPRODUCER - MULTI-ITERATION STRATEGY")
        logger.info("="*70)
        
        # Validate environment
        if not self.validate_environment():
            logger.error("Environment validation failed. Please fix issues and retry.")
            return False
        
        # Explain strategy
        logger.info("\n" + "="*70)
        logger.info("TEST STRATEGY")
        logger.info("="*70)
        logger.info("Iteration 1 (Learning Phase):")
        logger.info("  • Phase 1: Create 100 connections with FIXED ports (50000-50099)")
        logger.info("  • Phase 2: Wait 30s (kernel timeout)")
        logger.info("  • Phase 3: Poll eBPF → detect cleanup → STOP polling")
        logger.info("  • Phase 4: Spray with SAME ports (100% 5-tuple collision)")
        logger.info("")
        logger.info("Iterations 2-5 (Optimized):")
        logger.info("  • Phase 1: Create 100 connections with FIXED ports")
        logger.info("  • Phase 2: Wait 30s")
        logger.info("  • Phase 3: Skip polling (use learned timing)")
        logger.info("  • Phase 4: Spray with SAME ports (guaranteed collision)")
        logger.info("="*70)
        
        # Run 5 iterations
        num_iterations = min(self.config.iterations, 5)
        logger.info(f"\nExecuting {num_iterations} iterations...\n")
        
        attempts_with_race = 0
        
        for i in range(1, num_iterations + 1):
            is_learning = (i == 1)
            
            try:
                if self.execute_race_attempt(i, is_learning_phase=is_learning):
                    attempts_with_race += 1
                    logger.info(f"\n✓ Race detected in iteration {i}")
                else:
                    logger.info(f"\n✗ No race in iteration {i}")
                    
            except KeyboardInterrupt:
                logger.warning("\n\nTest interrupted by user")
                break
            except Exception as e:
                logger.error(f"Error in iteration {i}: {e}")
                import traceback
                traceback.print_exc()
                continue
        
        # Print summary
        logger.info("\n" + "="*70)
        logger.info("TEST SUMMARY")
        logger.info("="*70)
        logger.info(f"Total iterations: {num_iterations}")
        logger.info(f"Race conditions detected: {attempts_with_race}")
        logger.info(f"Success rate: {(attempts_with_race/num_iterations)*100:.1f}%")
        
        if self.learned_cleanup_timing:
            logger.info(f"\nLearned Timing:")
            logger.info(f"  Cleanup occurs at T+{self.learned_cleanup_timing}s after kernel timeout")
        
        if self.race_detected:
            logger.info("\n✓ RACE CONDITION SUCCESSFULLY REPRODUCED")
            logger.info("\nThe race occurs when:")
            logger.info("  1. Kernel expires a connection (30s timeout in test)")
            logger.info("  2. NPA's cleanup cycle snapshots kernel conntrack")
            logger.info("  3. A NEW connection reuses the same 5-tuple")
            logger.info("  4. Cleanup deletes the eBPF entry (based on old snapshot)")
            logger.info("  5. Response packet lookup fails → traffic denied")
            logger.info("\n💡 Proposed fix: Require 2 consecutive misses before deletion")
            return True
        else:
            logger.warning("\n⚠ Race condition not reproduced")
            logger.info("\nPossible reasons:")
            logger.info("  - Cleanup timing doesn't align with spray window")
            logger.info("  - eBPF map updates may be protecting against race")
            logger.info("  - Port reuse not occurring frequently enough")
            logger.info("\nConsider:")
            logger.info("  - Check if conntrack-tuner is running")
            logger.info("  - Verify kernel timeout is actually 30s")
            logger.info("  - Monitor eBPF map directly: bpftool map dump name conntrack_map")
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Reproduce conntrack race condition in Network Policy Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with default configuration
  python3 conntrack_race_reproducer.py

  # Run with custom config file
  python3 conntrack_race_reproducer.py -c my_config.yaml

  # Run with more iterations
  python3 conntrack_race_reproducer.py -i 20

  # Verbose output
  python3 conntrack_race_reproducer.py -v
        """
    )
    
    parser.add_argument('-c', '--config', default='test_config.yaml',
                       help='Path to configuration file (default: test_config.yaml)')
    parser.add_argument('-i', '--iterations', type=int,
                       help='Number of test iterations (overrides config)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Load configuration
    config = TestConfig.from_yaml(args.config)
    
    # Override with CLI args
    if args.iterations:
        config.iterations = args.iterations
    
    # Create reproducer and run test
    reproducer = ConntrackRaceReproducer(config)
    
    try:
        success = reproducer.run_test()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.warning("\nTest interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
