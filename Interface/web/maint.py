# ===== web/main.py (TEMPLATE) =====
"""
FastAPI Web Application

This file sets up the web server and defines:
1. Routes (URLs users can visit)
2. API endpoints (for predictions)
3. WebSocket for real-time updates
4. Static files (CSS, JS, images)
5. HTML templates
"""

from fastapi import FastAPI, WebSocket, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
import asyncio
import json

# Import the AI engine
from web.engine import predict_traffic, get_model_info

# ===== SETUP =====

# Create FastAPI app
app = FastAPI(
    title="tIDS - Traffic Intrusion Detection System",
    description="AI-powered network security monitoring",
    version="1.0.0"
)

# Setup file paths
BASE_DIR = Path(__file__).parent.parent
STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"

# Mount static files (CSS, JS, images)
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Setup templates (HTML pages)
templates = Jinja2Templates(directory=TEMPLATES_DIR)

print("[Main] FastAPI application initialized")
print(f"[Main] Static files: {STATIC_DIR}")
print(f"[Main] Templates: {TEMPLATES_DIR}")


# ===== GLOBAL STATE =====
# Store recent predictions to show in dashboard
recent_predictions = []
MAX_PREDICTIONS_TO_STORE = 100


def add_prediction(prediction_data: Dict[str, Any]):
    """Add a prediction to the recent history"""
    global recent_predictions
    
    prediction_data['timestamp'] = datetime.now().isoformat()
    recent_predictions.append(prediction_data)
    
    # Keep only the last 100 predictions
    if len(recent_predictions) > MAX_PREDICTIONS_TO_STORE:
        recent_predictions.pop(0)


# ===== ROUTES =====

@app.get("/")
async def home(request: Request):
    """
    Display the main dashboard
    
    GET /
    Returns: HTML page (dashboard.html)
    """
    try:
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "title": "tIDS Dashboard"
        })
    except Exception as e:
        return HTMLResponse(f"<h1>Error loading dashboard</h1><p>{e}</p>", status_code=500)


@app.get("/test")
async def test_page(request: Request):
    """
    Simple test page to verify the server is running
    
    GET /test
    Returns: Simple HTML test page
    """
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>tIDS Server Test</title>
        <style>
            body { font-family: Arial; margin: 20px; }
            .success { color: green; }
            .code { background: #f0f0f0; padding: 10px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>✓ tIDS Server is Running!</h1>
        <p>FastAPI server is up and responding to requests.</p>
        
        <h2>Next Steps:</h2>
        <ol>
            <li><a href="/docs">View API documentation</a></li>
            <li><a href="/">Go to Dashboard</a></li>
            <li>Test the prediction API</li>
        </ol>
        
        <h2>Quick Test:</h2>
        <div class="code">
            <p>Try this in PowerShell:</p>
            <code>python test_api.py</code>
        </div>
    </body>
    </html>
    """)


# ===== API ENDPOINTS =====

@app.post("/api/predict")
async def predict_endpoint(request: Request):
    """
    Make a prediction about network traffic
    
    POST /api/predict
    Body: JSON with 35 features
    
    Example:
    {
        "Dst_Port": 80,
        "Protocol": 6,
        "Timestamp": 1234567890,
        ...
        (35 features total)
    }
    
    Returns:
    {
        "prediction": "Normal",
        "confidence": 0.95,
        "success": true,
        "timestamp": "2024-04-24T15:30:00"
    }
    """
    try:
        # Get JSON data from request
        data = await request.json()
        
        print(f"[Main] Received prediction request with {len(data)} features")
        
        # Call the AI engine
        result = predict_traffic(data)
        
        # Add to recent predictions for dashboard
        if result.get('success'):
            add_prediction(result)
        
        # Return result
        return {
            "prediction": result.get('prediction'),
            "confidence": result.get('confidence'),
            "success": result.get('success', True),
            "error": result.get('error'),
            "timestamp": datetime.now().isoformat()
        }
    
    except ValueError as e:
        print(f"[Main] Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        print(f"[Main] Prediction error: {e}")
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


@app.post("/api/predict-batch")
async def predict_batch(request: Request):
    """
    Make multiple predictions at once
    
    POST /api/predict-batch
    Body: JSON array of feature dictionaries
    
    Example:
    [
        {"Dst_Port": 80, "Protocol": 6, ...},
        {"Dst_Port": 443, "Protocol": 6, ...},
        {"Dst_Port": 22, "Protocol": 6, ...}
    ]
    
    Returns:
    [
        {"prediction": "Normal", "confidence": 0.95, "success": true},
        {"prediction": "DoS", "confidence": 0.87, "success": true},
        ...
    ]
    """
    try:
        data = await request.json()
        
        if not isinstance(data, list):
            raise ValueError("Expected a list of feature dictionaries")
        
        print(f"[Main] Received batch prediction request for {len(data)} packets")
        
        results = []
        for features in data:
            result = predict_traffic(features)
            if result.get('success'):
                add_prediction(result)
            results.append(result)
        
        return results
    
    except Exception as e:
        print(f"[Main] Batch prediction error: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/info")
async def get_info():
    """
    Get information about the model
    
    GET /api/info
    
    Returns model details, feature count, etc.
    """
    try:
        info = get_model_info()
        return {
            "success": True,
            "model_info": info,
            "recent_predictions_count": len(recent_predictions)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.get("/api/predictions")
async def get_predictions(limit: int = 10):
    """
    Get recent predictions
    
    GET /api/predictions?limit=10
    
    Returns the last N predictions made
    """
    try:
        return {
            "success": True,
            "count": len(recent_predictions),
            "predictions": recent_predictions[-limit:] if recent_predictions else []
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.get("/api/predictions/stats")
async def get_stats():
    """
    Get statistics about predictions
    
    GET /api/predictions/stats
    
    Returns attack vs normal counts, etc.
    """
    try:
        if not recent_predictions:
            return {
                "success": True,
                "total": 0,
                "normal": 0,
                "attacks": 0,
                "predictions": []
            }
        
        # Count predictions
        normal_count = 0
        attack_count = 0
        predictions_by_type = {}
        
        for pred in recent_predictions:
            pred_type = pred.get('prediction', 'Unknown')
            
            if pred_type in ['Normal', 'Benign']:
                normal_count += 1
            else:
                attack_count += 1
            
            predictions_by_type[pred_type] = predictions_by_type.get(pred_type, 0) + 1
        
        return {
            "success": True,
            "total": len(recent_predictions),
            "normal": normal_count,
            "attacks": attack_count,
            "by_type": predictions_by_type,
            "attack_rate": f"{(attack_count / len(recent_predictions) * 100):.1f}%" if recent_predictions else "0%"
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


# ===== WEBSOCKET ENDPOINTS =====

@app.websocket("/ws/predictions")
async def websocket_predictions(websocket: WebSocket):
    """
    WebSocket endpoint for real-time predictions
    
    Allows the browser to receive predictions in real-time
    as the sniffer captures packets
    
    Usage from JavaScript:
    const ws = new WebSocket("ws://localhost:8000/ws/predictions");
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log("New prediction:", data.prediction);
    };
    """
    await websocket.accept()
    
    print(f"[Main] WebSocket client connected")
    
    try:
        while True:
            # Wait for client to send packet features
            try:
                data = await websocket.receive_json()
                
                print(f"[Main] WebSocket received {len(data)} features")
                
                # Make prediction
                result = predict_traffic(data)
                
                # Store if successful
                if result.get('success'):
                    add_prediction(result)
                
                # Send result back to browser in real-time
                await websocket.send_json({
                    "prediction": result.get('prediction'),
                    "confidence": result.get('confidence'),
                    "success": result.get('success'),
                    "timestamp": datetime.now().isoformat(),
                    "error": result.get('error')
                })
            
            except Exception as e:
                print(f"[Main] WebSocket error: {e}")
                await websocket.send_json({
                    "success": False,
                    "error": str(e)
                })
    
    except Exception as e:
        print(f"[Main] WebSocket connection closed: {e}")
    
    finally:
        await websocket.close()
        print(f"[Main] WebSocket client disconnected")


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """
    Alternative WebSocket endpoint that broadcasts predictions
    to all connected clients
    
    Useful for monitoring dashboard updates across multiple browsers
    """
    await websocket.accept()
    
    print(f"[Main] Live WebSocket client connected")
    
    connected_clients = []
    connected_clients.append(websocket)
    
    try:
        while True:
            data = await websocket.receive_json()
            result = predict_traffic(data)
            
            if result.get('success'):
                add_prediction(result)
            
            # Broadcast to all connected clients
            for client in connected_clients:
                try:
                    await client.send_json({
                        "prediction": result.get('prediction'),
                        "confidence": result.get('confidence'),
                        "timestamp": datetime.now().isoformat()
                    })
                except:
                    pass  # Client disconnected
    
    except:
        pass
    
    finally:
        connected_clients.remove(websocket)
        await websocket.close()


# ===== ERROR HANDLERS =====

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP errors gracefully"""
    return {
        "success": False,
        "error": exc.detail,
        "status_code": exc.status_code
    }


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors"""
    print(f"[Main] Unhandled exception: {exc}")
    return {
        "success": False,
        "error": "Internal server error",
        "detail": str(exc)
    }


# ===== STARTUP AND SHUTDOWN =====

@app.on_event("startup")
async def startup_event():
    """Called when the server starts"""
    print("[Main] ====== tIDS Server Starting ======")
    print(f"[Main] Time: {datetime.now()}")
    
    # Get model info
    info = get_model_info()
    print(f"[Main] Model loaded: {info.get('model_type')}")
    print(f"[Main] Classes: {info.get('classes')}")
    print(f"[Main] Expected features: {info.get('required_features')}")


@app.on_event("shutdown")
async def shutdown_event():
    """Called when the server shuts down"""
    print("[Main] ====== tIDS Server Shutting Down ======")
    print(f"[Main] Total predictions made: {len(recent_predictions)}")
    print(f"[Main] Time: {datetime.now()}")


# ===== MAIN =====

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*60)
    print("Starting tIDS Web Application")
    print("="*60)
    print(f"Host: 0.0.0.0")
    print(f"Port: 8000")
    print(f"URL: http://localhost:8000")
    print(f"API Docs: http://localhost:8000/docs")
    print("="*60 + "\n")
    
    # Start the server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
