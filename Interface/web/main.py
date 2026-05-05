import asyncio
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.templating import Jinja2Templates
import os
import sys
from pathlib import Path
import json
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from sniffer import CaptureEngine

app = FastAPI(title="tIDS Dashboard API")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()
capture_queue = asyncio.Queue()
sniffer_engine = None

@app.on_event("startup")
async def startup_event():
    global sniffer_engine
    loop = asyncio.get_running_loop()
    sniffer_engine = CaptureEngine(capture_queue, loop)
    asyncio.create_task(broadcast_worker())

async def broadcast_worker():
    while True:
        result = await capture_queue.get()
        await manager.broadcast(result)

@app.get("/")
async def read_index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.post("/api/start")
async def start_capture():
    if sniffer_engine:
        sniffer_engine.start()
        return {"status": "started"}
    return {"error": "Engine not initialized"}

@app.post("/api/stop")
async def stop_capture():
    if sniffer_engine:
        sniffer_engine.stop()
        return {"status": "stopped"}
    return {"error": "Engine not initialized"}

@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/api/alerts")
async def get_alerts():
    """Get recent attack alerts"""
    alerts = []
    log_file = Path('logs/predictions.log')
    
    if not log_file.exists():
        return {"alerts": [], "total_alerts": 0}
    
    try:
        with open(log_file, 'r') as f:
            for line in f.readlines()[-100:]:  # Last 100 entries
                if line.strip():
                    data = json.loads(line)
                    # Only show non-Normal predictions
                    if data.get('prediction') != 'Normal':
                        alerts.append(data)
    except Exception as e:
        print(f"Error reading alerts: {e}")
    
    return {
        "alerts": alerts,
        "total_alerts": len(alerts),
        "last_updated": datetime.now().isoformat()
    }

@app.get("/admin")
async def admin_page(request: Request):
    """Admin dashboard for viewing alerts"""
    return templates.TemplateResponse(request, "admin.html")
