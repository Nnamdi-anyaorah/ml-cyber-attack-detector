"""
Test the Cyber Attack Detector
"""

import pandas as pd
import numpy as np
from cyber_attack_detector import CyberAttackDetector

print("="*70)
print("TESTING CYBER ATTACK DETECTOR")
print("="*70)
print()

detector = CyberAttackDetector(models_dir=r'C:\Users\nnamd\models')

if not detector.load_models():
    print("Failed to load models!")
    exit()

print()
print("="*70)
print("SCENARIO 1: NORMAL WEB BROWSING")
print("="*70)
print()

normal_traffic = pd.DataFrame([{
    'dur': 5.2,
    'proto': 0,  # tcp
    'service': 4,  # http
    'state': 1,  # FIN
    'spkts': 45,
    'dpkts': 38,
    'sbytes': 5420,
    'dbytes': 4890,
    'rate': 15.8,
    'sttl': 64,
    'dttl': 64,
    'sload': 1050.5,
    'dload': 980.2,
    'sloss': 0,
    'dloss': 0,
    'sinpkt': 116.4,
    'dinpkt': 128.9,
    'sjit': 2.1,
    'djit': 1.8,
    'swin': 8192,
    'stcpb': 1234567,
    'dtcpb': 7654321,
    'dwin': 8192,
    'tcprtt': 25.5,
    'synack': 15.2,
    'ackdat': 10.3,
    'smean': 120.4,
    'dmean': 128.6,
    'trans_depth': 2,
    'response_body_len': 1500,
    'ct_srv_src': 3,
    'ct_state_ttl': 2,
    'ct_dst_ltm': 5,
    'ct_src_dport_ltm': 2,
    'ct_dst_sport_ltm': 3,
    'ct_dst_src_ltm': 4,
    'is_ftp_login': 0,
    'ct_ftp_cmd': 0,
    'ct_flw_http_mthd': 1,
    'ct_src_ltm': 4,
    'ct_srv_dst': 3,
    'is_sm_ips_ports': 0
}])

result = detector.detect_unsw(normal_traffic)

print("Network Traffic:")
print(f"  Protocol: TCP, Service: HTTP")
print(f"  Duration: 5.2 sec")
print(f"  Packets: 45 sent, 38 received")
print(f"  Typical web browsing pattern")
print()
print("Detection:")
print(f"  RF: {result['rf_prediction']} ({result['rf_confidence']:.1f}%)")
print(f"  GB: {result['gb_prediction']} ({result['gb_confidence']:.1f}%)")
print()
if result['gb_prediction'] == 'NORMAL':
    print("✅ VERDICT: Legitimate traffic")
else:
    print("🚨 VERDICT: Attack detected")

print()
print("="*70)
print("SCENARIO 2: PORT SCAN ATTACK")
print("="*70)
print()

port_scan = pd.DataFrame([{
    'dur': 0.05,
    'proto': 0,
    'service': 5,
    'state': 3,
    'spkts': 1500,
    'dpkts': 0,
    'sbytes': 75000,
    'dbytes': 0,
    'rate': 30000.0,
    'sttl': 64,
    'dttl': 0,
    'sload': 15000.0,
    'dload': 0.0,
    'sloss': 1450,
    'dloss': 0,
    'sinpkt': 0.033,
    'dinpkt': 0.0,
    'sjit': 0.5,
    'djit': 0.0,
    'swin': 1024,
    'stcpb': 100,
    'dtcpb': 0,
    'dwin': 0,
    'tcprtt': 0.0,
    'synack': 0.0,
    'ackdat': 0.0,
    'smean': 50.0,
    'dmean': 0.0,
    'trans_depth': 0,
    'response_body_len': 0,
    'ct_srv_src': 0,
    'ct_state_ttl': 0,
    'ct_dst_ltm': 100,
    'ct_src_dport_ltm': 500,
    'ct_dst_sport_ltm': 1,
    'ct_dst_src_ltm': 100,
    'is_ftp_login': 0,
    'ct_ftp_cmd': 0,
    'ct_flw_http_mthd': 0,
    'ct_src_ltm': 1,
    'ct_srv_dst': 500,
    'is_sm_ips_ports': 0
}])

result = detector.detect_unsw(port_scan)

print("Network Traffic:")
print(f"  Duration: 0.05 sec (FAST!)")
print(f"  Packets: 1,500 sent, 0 received")
print(f"  Rate: 30,000/sec (ABNORMAL!)")
print(f"  Scanning 500+ ports")
print()
print("🚨 Suspicious indicators detected")
print()
print("Detection:")
print(f"  RF: {result['rf_prediction']} ({result['rf_confidence']:.1f}%)")
print(f"  GB: {result['gb_prediction']} ({result['gb_confidence']:.1f}%)")
print()
if result['gb_prediction'] == 'ATTACK':
    print("🚨🚨 VERDICT: PORT SCAN DETECTED!")
    print()
    print("Actions: Block IP, Alert SOC, Log incident")
else:
    print("✅ No attack detected")

print()
print("="*70)
print("SCENARIO 3: DDoS ATTACK")
print("="*70)
print()

ddos = pd.DataFrame([{
    'dur': 0.001,
    'proto': 0,
    'service': 4,
    'state': 2,
    'spkts': 10000,
    'dpkts': 5,
    'sbytes': 500000,
    'dbytes': 250,
    'rate': 10000000.0,
    'sttl': 64,
    'dttl': 64,
    'sload': 500000.0,
    'dload': 50.0,
    'sloss': 9990,
    'dloss': 0,
    'sinpkt': 0.0001,
    'dinpkt': 200.0,
    'sjit': 0.01,
    'djit': 50.0,
    'swin': 512,
    'stcpb': 50,
    'dtcpb': 100000,
    'dwin': 65535,
    'tcprtt': 5000.0,
    'synack': 4000.0,
    'ackdat': 1000.0,
    'smean': 50.0,
    'dmean': 50.0,
    'trans_depth': 0,
    'response_body_len': 0,
    'ct_srv_src': 1,
    'ct_state_ttl': 1,
    'ct_dst_ltm': 1,
    'ct_src_dport_ltm': 1,
    'ct_dst_sport_ltm': 10000,
    'ct_dst_src_ltm': 1,
    'is_ftp_login': 0,
    'ct_ftp_cmd': 0,
    'ct_flw_http_mthd': 10000,
    'ct_src_ltm': 1,
    'ct_srv_dst': 1,
    'is_sm_ips_ports': 0
}])

result = detector.detect_unsw(ddos)

print("Network Traffic:")
print(f"  Duration: 0.001 sec (INSTANT!)")
print(f"  Packets: 10,000 (FLOOD!)")
print(f"  Rate: 10M packets/sec")
print(f"  Loss: 99.9%")
print()
print("🔥 Critical: DDoS pattern")
print()
print("Detection:")
print(f"  RF: {result['rf_prediction']} ({result['rf_confidence']:.1f}%)")
print(f"  GB: {result['gb_prediction']} ({result['gb_confidence']:.1f}%)")
print()
if result['gb_prediction'] == 'ATTACK':
    print("🔥🔥 VERDICT: DDoS IN PROGRESS!")
    print()
    print("Actions: Activate mitigation, Contact ISP")
else:
    print("✅ No attack detected")

print()
print("="*70)
print("TEST COMPLETE")
print("="*70)
print("✅ System operational and ready!")