import joblib
import pandas as pd
import pathlib
import os
import json
from datetime import datetime

# Base paths
BASE_DIR = pathlib.Path(__file__).parent.parent.absolute()
MODELS_DIR = os.path.join(BASE_DIR, "models")

MODEL_PATH = os.path.join(MODELS_DIR, "tIDS_RandomForest_Model.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "tIDS_Scaler.pkl")

# Load models safely
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("AI Models successfully loaded!")
except Exception as e:
    print(f"Error loading models: {e}")
    model, scaler = None, None

# The exact 35 feature names required by the trained model
REQUIRED_FEATURES = [
    'packet_rate', 'byte_rate', 'mean_pkt_size', 'max_pkt_size', 'tcp_syn_count',
    'tcp_ack_count', 'tcp_rst_count', 'tcp_fin_count', 'syn_to_ack_ratio',
    'rst_to_syn_ratio', 'tcp_to_total_ratio', 'udp_packet_count',
    'udp_to_total_ratio', 'icmp_packet_count', 'icmp_to_total_ratio',
    'icmp_echo_request_count', 'icmp_echo_reply_count',
    'icmp_reply_to_request_ratio', 'arp_request_count', 'arp_reply_count',
    'arp_reply_ratio', 'ip_mac_mapping_changes', 'dns_query_count',
    'dns_response_count', 'dns_reply_to_query_ratio', 'dns_avg_response_size',
    'dns_ttl_mean', 'stp_packet_count', 'igmp_packet_count', 'igmp_join_count',
    'unique_src_ip_count', 'unique_dst_ip_count', 'unique_dst_ports',
    'broadcast_pkt_count', 'multicast_pkt_count'
]

def predict_traffic(raw_features: dict) -> str:
    """
    Takes a dictionary of features from the sniffer.
    Filters to match the 35 features expected by the model,
    scales them, and returns a string prediction.
    """
    if model is None or scaler is None:
        return "Model Error"
        
    filtered = {k: [raw_features.get(k, 0.0)] for k in REQUIRED_FEATURES}
    df = pd.DataFrame(filtered, columns=REQUIRED_FEATURES)
    
    scaled_data = scaler.transform(df)
    prediction = model.predict(scaled_data)
    
    return prediction[0]


def log_prediction(features, prediction):
    """Log predictions to file for auditing"""
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
        print(f"Logging error: {e}")