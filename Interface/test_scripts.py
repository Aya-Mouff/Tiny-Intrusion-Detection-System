# ===== test_scripts.py =====
# Run these tests to verify everything is working!
# Usage: python test_scripts.py

import sys
import os
from pathlib import Path

print("=" * 60)
print("tIDS MODEL & SETUP TEST SUITE")
print("=" * 60)

# ===== TEST 1: Check Paths =====
print("\n[TEST 1] Checking file paths...")
print("-" * 60)

BASE_DIR = Path(__file__).parent.absolute()
MODELS_DIR = os.path.join(BASE_DIR, "models")
model_path = os.path.join(MODELS_DIR, "tIDS_RandomForest_Model.pkl")
scaler_path = os.path.join(MODELS_DIR, "tIDS_Scaler.pkl")

print(f"Base directory: {BASE_DIR}")
print(f"Models directory: {MODELS_DIR}")
print(f"Model path: {model_path}")
print(f"Scaler path: {scaler_path}")

model_exists = os.path.exists(model_path)
scaler_exists = os.path.exists(scaler_path)

print(f"\n✓ Model file exists: {model_exists}" if model_exists else f"✗ Model file NOT FOUND: {model_exists}")
print(f"✓ Scaler file exists: {scaler_exists}" if scaler_exists else f"✗ Scaler file NOT FOUND: {scaler_exists}")

if os.path.exists(MODELS_DIR):
    print(f"\nFiles in models folder:")
    for file in os.listdir(MODELS_DIR):
        print(f"  - {file}")


# ===== TEST 2: Check Dependencies =====
print("\n[TEST 2] Checking Python dependencies...")
print("-" * 60)

packages = {
    'fastapi': 'Web framework',
    'uvicorn': 'Server',
    'pandas': 'Data processing',
    'sklearn': 'Machine learning',
    'joblib': 'Model loading',
    'scapy': 'Packet capture',
    'jinja2': 'Template engine',
}

missing_packages = []
for package, description in packages.items():
    try:
        __import__(package if package != 'sklearn' else 'sklearn')
        print(f"✓ {package:20} - {description}")
    except ImportError:
        print(f"✗ {package:20} - {description} [MISSING]")
        missing_packages.append(package)

if missing_packages:
    print(f"\n⚠️  Missing packages: {', '.join(missing_packages)}")
    print("   Fix: Run: pip install -r requirements.txt")
else:
    print("\n✓ All dependencies installed!")


# ===== TEST 3: Load Model =====
print("\n[TEST 3] Loading model and scaler...")
print("-" * 60)

try:
    import joblib
    model = joblib.load(model_path)
    print(f"✓ Model loaded successfully")
    print(f"  Type: {type(model).__name__}")
    print(f"  Classes: {list(model.classes_) if hasattr(model, 'classes_') else 'Unknown'}")
except Exception as e:
    print(f"✗ Error loading model: {e}")
    model = None

try:
    scaler = joblib.load(scaler_path)
    print(f"✓ Scaler loaded successfully")
    print(f"  Type: {type(scaler).__name__}")
except Exception as e:
    print(f"✗ Error loading scaler: {e}")
    scaler = None


# ===== TEST 4: Check Features =====
print("\n[TEST 4] Checking required features...")
print("-" * 60)

try:
    # Try to import from engine.py
    sys.path.insert(0, str(BASE_DIR))
    from web.engine import REQUIRED_FEATURES
    
    print(f"✓ Found REQUIRED_FEATURES in engine.py")
    print(f"  Number of features: {len(REQUIRED_FEATURES)}")
    
    if len(REQUIRED_FEATURES) == 35:
        print(f"✓ Feature count is correct (35)")
    else:
        print(f"⚠️  Feature count is {len(REQUIRED_FEATURES)}, expected 35")
    
    print(f"\n  First 5 features:")
    for i, feature in enumerate(REQUIRED_FEATURES[:5]):
        print(f"    {i+1}. {feature}")
    print(f"  ...")
    print(f"\n  Last 5 features:")
    for i, feature in enumerate(REQUIRED_FEATURES[-5:], start=len(REQUIRED_FEATURES)-4):
        print(f"    {i}. {feature}")
        
except ImportError as e:
    print(f"✗ Could not import REQUIRED_FEATURES: {e}")
    print("  Fix: Make sure engine.py defines REQUIRED_FEATURES")


# ===== TEST 5: Test Prediction =====
print("\n[TEST 5] Testing prediction with fake data...")
print("-" * 60)

if model and scaler:
    try:
        import pandas as pd
        from web.engine import predict_traffic
        
        # Create fake data
        fake_data = {feature: 0.5 for feature in REQUIRED_FEATURES}
        
        print(f"Creating fake packet with 35 features (all values = 0.5)...")
        result = predict_traffic(fake_data)
        
        if result.get('success'):
            print(f"✓ Prediction successful!")
            print(f"  Prediction: {result.get('prediction')}")
            print(f"  Confidence: {result.get('confidence'):.2%}")
        else:
            print(f"✗ Prediction failed: {result.get('error')}")
            
    except Exception as e:
        print(f"✗ Error during prediction: {e}")
        import traceback
        traceback.print_exc()
else:
    print("⚠️  Skipping prediction test (model or scaler not loaded)")


# ===== SUMMARY =====
print("\n" + "=" * 60)
print("TEST SUMMARY")
print("=" * 60)

tests_passed = 0
tests_total = 5

if model_exists and scaler_exists:
    tests_passed += 1
    print("✓ Files exist")
else:
    print("✗ Files missing")

if not missing_packages:
    tests_passed += 1
    print("✓ Dependencies installed")
else:
    print("✗ Missing dependencies")

if model is not None:
    tests_passed += 1
    print("✓ Model loads")
else:
    print("✗ Model failed to load")

if scaler is not None:
    tests_passed += 1
    print("✓ Scaler loads")
else:
    print("✗ Scaler failed to load")

try:
    from web.engine import REQUIRED_FEATURES
    if len(REQUIRED_FEATURES) == 35:
        tests_passed += 1
        print("✓ Features configured correctly")
    else:
        print(f"✗ Feature count mismatch ({len(REQUIRED_FEATURES)} != 35)")
except:
    print("✗ Could not check features")

print("\n" + "=" * 60)
print(f"RESULT: {tests_passed}/{tests_total} tests passed")
print("=" * 60)

if tests_passed == tests_total:
    print("\n✓✓✓ Everything looks good! Ready to run the application! ✓✓✓")
else:
    print("\n⚠️  Some tests failed. Please fix the issues above.")
    print("Common fixes:")
    print("  1. Make sure you're in the project root folder")
    print("  2. Activate virtual environment: .\\venv\\Scripts\\Activate.ps1")
    print("  3. Install dependencies: pip install -r requirements.txt")
    print("  4. Verify model files exist in models/ folder")
