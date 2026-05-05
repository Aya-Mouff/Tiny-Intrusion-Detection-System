# ===== web/engine.py (TEMPLATE) =====
"""
The AI Brain Controller

This file handles:
1. Loading the trained model and scaler
2. Defining the 35 required features
3. Processing raw packet data
4. Making predictions
"""

import joblib
import pandas as pd
import os
import pathlib
from typing import Dict, Any

# ===== PATH SETUP (Correct for any location) =====
# This automatically finds the models folder no matter where you run from
BASE_DIR = pathlib.Path(__file__).parent.parent.absolute()
MODELS_DIR = os.path.join(BASE_DIR, "models")

print(f"[Engine] Base directory: {BASE_DIR}")
print(f"[Engine] Models directory: {MODELS_DIR}")

# ===== LOAD THE AI MODEL AND SCALER =====
# This happens ONCE when the app starts
try:
    model_path = os.path.join(MODELS_DIR, "tIDS_RandomForest_Model.pkl")
    model = joblib.load(model_path)
    print(f"✓ [Engine] Model loaded from {model_path}")
except FileNotFoundError:
    print(f"✗ [Engine] ERROR: Model not found at {model_path}")
    print(f"  Make sure tIDS_RandomForest_Model.pkl exists in the models/ folder")
    raise

try:
    scaler_path = os.path.join(MODELS_DIR, "tIDS_Scaler.pkl")
    scaler = joblib.load(scaler_path)
    print(f"✓ [Engine] Scaler loaded from {scaler_path}")
except FileNotFoundError:
    print(f"✗ [Engine] ERROR: Scaler not found at {scaler_path}")
    print(f"  Make sure tIDS_Scaler.pkl exists in the models/ folder")
    raise

# ===== DEFINE THE 35 REQUIRED FEATURES =====
# IMPORTANT: These MUST match EXACTLY what the model was trained on
# Feature names are case-sensitive! 'Feature_1' is different from 'feature_1'
# 
# TODO: Replace this list with your actual 35 feature names
# Get them from your ML team or from training script output
REQUIRED_FEATURES = [
    # Example features - REPLACE WITH ACTUAL FEATURES
    'Dst_Port',
    'Protocol',
    'Timestamp',
    'Flow_Duration',
    'Tot_Fwd_Pkts',
    'Tot_Bwd_Pkts',
    'TotLen_Fwd_Pkts',
    'TotLen_Bwd_Pkts',
    'Fwd_Pkt_Len_Max',
    'Fwd_Pkt_Len_Min',
    'Fwd_Pkt_Len_Mean',
    'Fwd_Pkt_Len_Std',
    'Bwd_Pkt_Len_Max',
    'Bwd_Pkt_Len_Min',
    'Bwd_Pkt_Len_Mean',
    'Bwd_Pkt_Len_Std',
    'Flow_Byts_s',
    'Flow_Pkts_s',
    'Flow_IAT_Mean',
    'Flow_IAT_Std',
    'Flow_IAT_Max',
    'Flow_IAT_Min',
    'Fwd_IAT_Mean',
    'Fwd_IAT_Std',
    'Fwd_IAT_Max',
    'Fwd_IAT_Min',
    'Bwd_IAT_Mean',
    'Bwd_IAT_Std',
    'Bwd_IAT_Max',
    'Bwd_IAT_Min',
    'Fwd_PSH_Cnt',
    'Bwd_PSH_Cnt',
    'Fwd_URG_Cnt',
    'Bwd_URG_Cnt',
    'Fwd_RST_Cnt',
    # Add 2 more to reach 35
]

print(f"✓ [Engine] Loaded {len(REQUIRED_FEATURES)} required features")
if len(REQUIRED_FEATURES) != 35:
    print(f"⚠️  WARNING: Expected 35 features, but got {len(REQUIRED_FEATURES)}")
    print("   Add or remove features to make it exactly 35")


# ===== THE PREDICTION FUNCTION =====
def predict_traffic(raw_features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Make a prediction about network traffic.
    
    Args:
        raw_features: Dictionary with 35 features from a packet
                      Example: {
                          'Dst_Port': 80,
                          'Protocol': 6,
                          'Timestamp': 1234567890,
                          ...
                      }
    
    Returns:
        Dictionary with prediction results:
        {
            'prediction': 'Normal',           # or 'DoS', 'PortScan', etc.
            'confidence': 0.95,               # probability (0-1)
            'success': True                   # whether prediction worked
        }
        
        On error:
        {
            'success': False,
            'error': 'Error message here'
        }
    """
    
    try:
        # ===== STEP 1: Validate input =====
        if not isinstance(raw_features, dict):
            raise ValueError("raw_features must be a dictionary")
        
        if len(raw_features) < 35:
            raise ValueError(f"Expected 35 features, got {len(raw_features)}")
        
        # ===== STEP 2: Filter to required 35 features =====
        # Only keep features that the model knows about
        try:
            filtered_features = {
                feature: raw_features[feature]
                for feature in REQUIRED_FEATURES
            }
        except KeyError as e:
            missing_feature = str(e)
            raise ValueError(f"Missing feature in raw_features: {missing_feature}")
        
        # ===== STEP 3: Create DataFrame =====
        # The model expects data in a specific format (Pandas DataFrame)
        df = pd.DataFrame([filtered_features])
        
        print(f"[Engine] Input shape: {df.shape}")
        print(f"[Engine] Feature columns: {list(df.columns)}")
        
        # ===== STEP 4: Scale the data =====
        # Apply the SAME scaling that was used during training
        # This is CRITICAL - without it, the model will be confused
        scaled_data = scaler.transform(df)
        
        print(f"[Engine] Scaled data shape: {scaled_data.shape}")
        
        # ===== STEP 5: Make prediction =====
        prediction = model.predict(scaled_data)[0]
        
        # ===== STEP 6: Get confidence =====
        # How sure is the model about its prediction?
        probabilities = model.predict_proba(scaled_data)[0]
        confidence = float(max(probabilities))
        
        print(f"[Engine] Prediction: {prediction}")
        print(f"[Engine] Confidence: {confidence:.2%}")
        
        # ===== STEP 7: Return results =====
        return {
            'prediction': str(prediction),
            'confidence': confidence,
            'success': True
        }
    
    except Exception as e:
        # If anything goes wrong, return error details
        error_message = f"{type(e).__name__}: {str(e)}"
        print(f"✗ [Engine] Prediction error: {error_message}")
        
        return {
            'success': False,
            'error': error_message
        }


# ===== HELPER FUNCTION: Validate features =====
def validate_features(features: Dict[str, Any]) -> tuple[bool, str]:
    """
    Check if a features dictionary has all required features.
    
    Returns:
        (is_valid, message)
    """
    missing = []
    for feature in REQUIRED_FEATURES:
        if feature not in features:
            missing.append(feature)
    
    if missing:
        return False, f"Missing {len(missing)} features: {missing[:3]}..."
    
    return True, "All features present"


# ===== HELPER FUNCTION: Get model info =====
def get_model_info() -> Dict[str, Any]:
    """
    Get information about the loaded model.
    
    Returns:
        Dictionary with model details
    """
    try:
        return {
            'model_type': type(model).__name__,
            'classes': list(model.classes_) if hasattr(model, 'classes_') else None,
            'n_features': model.n_features_in_ if hasattr(model, 'n_features_in_') else None,
            'scaler_type': type(scaler).__name__,
            'required_features': len(REQUIRED_FEATURES),
            'feature_names': REQUIRED_FEATURES
        }
    except Exception as e:
        return {'error': str(e)}


# ===== OPTIONAL: Main function for testing =====
if __name__ == "__main__":
    # This runs when you execute: python web/engine.py
    
    print("\n" + "="*60)
    print("ENGINE TEST")
    print("="*60)
    
    # Show model info
    info = get_model_info()
    print("\nModel Information:")
    for key, value in info.items():
        if key != 'feature_names':
            print(f"  {key}: {value}")
    
    # Test with fake data
    print("\n\nTesting with fake data...")
    fake_features = {feature: 0.5 for feature in REQUIRED_FEATURES}
    result = predict_traffic(fake_features)
    
    print(f"\nResult:")
    print(f"  Prediction: {result.get('prediction')}")
    print(f"  Confidence: {result.get('confidence'):.2%}")
    print(f"  Success: {result.get('success')}")
