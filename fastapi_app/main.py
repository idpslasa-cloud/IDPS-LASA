import asyncio
import json
import os
import sys
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi_app.schemas import ChatRequest, ChatResponse, StatsResponse
from fastapi_app import detector
from fastapi_app.agent import get_ai_response

# ── WebSocket connection manager ──────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)


manager = ConnectionManager()
packet_queue: asyncio.Queue = asyncio.Queue(maxsize=500)


async def _packet_broadcaster():
    """Drains the packet queue and broadcasts to all WebSocket clients."""
    while True:
        pkt = await packet_queue.get()
        await manager.broadcast(pkt)


async def _alert_callback(alert: dict):
    await manager.broadcast({"type": "alert", **alert})


# ── Lifespan ──────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    loop = asyncio.get_event_loop()
    detector.alert_callbacks.append(_alert_callback)
    detector.start_sniffing(loop, packet_queue)
    task = asyncio.create_task(_packet_broadcaster())
    yield
    task.cancel()


app = FastAPI(title="IDPS API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── REST endpoints ────────────────────────────────────────────────────────
@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    return StatsResponse(
        idps_on=detector.idps_on,
        alert_count=detector.alert_count,
        active_threats=detector.active_threats,
    )


@app.post("/api/toggle")
async def toggle_ids():
    on = detector.toggle()
    return {"idps_on": on}


@app.post("/api/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(None, get_ai_response, req.message)
    return ChatResponse(response=response)


@app.get("/api/alerts")
async def get_alerts():
    """Returns recent alerts from Django DB."""
    try:
        import django
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "IDPS.settings")
        django.setup()
        from dashboard.models import Alert
        alerts = list(
            Alert.objects.order_by("-timestamp")[:50].values(
                "attack_type", "source_ip", "destination_ip",
                "status", "description", "timestamp"
            )
        )
        # Convert datetime to str
        for a in alerts:
            a["timestamp"] = str(a["timestamp"])
        return {"alerts": alerts}
    except Exception as e:
        return {"alerts": [], "error": str(e)}


# ── WebSocket endpoint ────────────────────────────────────────────────────
@app.websocket("/ws/packets")
async def websocket_packets(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()   # keep alive
    except WebSocketDisconnect:
        manager.disconnect(ws)
