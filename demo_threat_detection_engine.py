"""Demonstration of ThreatDetectionEngine with all detectors"""

from scapy.layers.inet import IP, TCP, ICMP, UDP
from ids.services.threat_detection_engine import ThreatDetectionEngine
from ids.detectors.port_scan_detector import PortScanDetector
from ids.detectors.icmp_scan_detector import ICMPScanDetector
from ids.detectors.brute_force_detector import BruteForceDetector
from ids.detectors.malware_detector import MalwareDetector
from ids.detectors.data_exfiltration_detector import DataExfiltrationDetector
from ids.detectors.attacker_identifier import AttackerIdentifier


def main():
    print("\n" + "="*60)
    print("ThreatDetectionEngine Demonstration")
    print("="*60 + "\n")
    
    # Initialize the engine
    engine = ThreatDetectionEngine()
    print("✓ ThreatDetectionEngine initialized")
    
    # Register all detectors
    print("\nRegistering detectors...")
    engine.register_detector(PortScanDetector(threshold=3, time_window=60))
    print("  ✓ PortScanDetector registered")
    
    engine.register_detector(ICMPScanDetector(threshold=3, time_window=30))
    print("  ✓ ICMPScanDetector registered")
    
    engine.register_detector(BruteForceDetector(threshold=3, time_window=60))
    print("  ✓ BruteForceDetector registered")
    
    engine.register_detector(MalwareDetector())
    print("  ✓ MalwareDetector registered")
    
    engine.register_detector(DataExfiltrationDetector(threshold_bytes=5*1024*1024, time_window=60))
    print("  ✓ DataExfiltrationDetector registered")
    
    engine.register_detector(AttackerIdentifier(threshold=3, time_window=300))
    print("  ✓ AttackerIdentifier registered")
    
    # Display statistics
    stats = engine.get_statistics()
    print(f"\nEngine Statistics:")
    print(f"  Registered Detectors: {stats['registered_detectors']}")
    print(f"  Detector Types: {', '.join(stats['detector_types'])}")
    
    # Simulate port scan attack
    print("\n" + "-"*60)
    print("Simulating Port Scan Attack...")
    print("-"*60)
    
    attacker_ip = "192.168.1.100"
    target_ip = "10.0.0.1"
    
    for port in range(80, 85):
        packet = IP(src=attacker_ip, dst=target_ip) / TCP(sport=12345, dport=port, flags="S")
        result = engine.analyze_packet(packet)
        
        if result:
            print(f"\n🚨 THREAT DETECTED!")
            print(f"  Type: {result.threat_type.value}")
            print(f"  Source: {result.source_ip}")
            print(f"  Destination: {result.destination_ip}")
            print(f"  Protocol: {result.protocol}")
            print(f"  Details: {result.raw_data}")
            break
        else:
            print(f"  Scanning port {port}... (no alert yet)")
    
    # Simulate ICMP scan
    print("\n" + "-"*60)
    print("Simulating ICMP Scan...")
    print("-"*60)
    
    for host in range(1, 5):
        target = f"10.0.0.{host}"
        packet = IP(src=attacker_ip, dst=target) / ICMP(type=8)
        result = engine.analyze_packet(packet)
        
        if result:
            print(f"\n🚨 THREAT DETECTED!")
            print(f"  Type: {result.threat_type.value}")
            print(f"  Source: {result.source_ip}")
            print(f"  Details: {result.raw_data}")
            break
        else:
            print(f"  Pinging {target}... (no alert yet)")
    
    # Simulate brute force attack
    print("\n" + "-"*60)
    print("Simulating Brute Force Attack...")
    print("-"*60)
    
    for attempt in range(1, 5):
        packet = IP(src=attacker_ip, dst=target_ip) / TCP(sport=12345, dport=22, flags="R")
        result = engine.analyze_packet(packet)
        
        if result:
            print(f"\n🚨 THREAT DETECTED!")
            print(f"  Type: {result.threat_type.value}")
            print(f"  Source: {result.source_ip}")
            print(f"  Details: {result.raw_data}")
            break
        else:
            print(f"  Failed login attempt {attempt}... (no alert yet)")
    
    # Display final statistics
    print("\n" + "="*60)
    print("Final Engine Statistics")
    print("="*60)
    
    final_stats = engine.get_statistics()
    print(f"  Packets Analyzed: {final_stats['packets_analyzed']}")
    print(f"  Threats Detected: {final_stats['threats_detected']}")
    print(f"  Registered Detectors: {final_stats['registered_detectors']}")
    
    print("\n✓ Demonstration complete!\n")


if __name__ == "__main__":
    main()
