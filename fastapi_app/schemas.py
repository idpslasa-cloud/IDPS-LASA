from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class PacketData(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    size: int
    timestamp: str
    flagged: bool = False


class AlertData(BaseModel):
    attack_type: str
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    description: str
    timestamp: str


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str


class StatsResponse(BaseModel):
    idps_on: bool
    alert_count: int
    active_threats: int
