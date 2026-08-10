import httpx
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from django.db.models.functions import TruncDate
from .models import Alert, BlockedIP
import json
import os

FASTAPI_URL = os.getenv("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


def _fastapi_stats():
    """Fetch live stats from FastAPI. Returns defaults on failure."""
    try:
        r = httpx.get(f"{FASTAPI_URL}/api/stats", timeout=2.0)
        return r.json()
    except Exception:
        return {"idps_on": False, "alert_count": 0, "active_threats": 0}


# ── Page 1: Dashboard ────────────────────────────────────────────────────────
def dashboard(request):
    stats = _fastapi_stats()
    recent_alerts = Alert.objects.order_by("-timestamp")[:10]
    context = {
        "idps_on": stats.get("idps_on", False),
        "alert_count": Alert.objects.count(),
        "active_threats": Alert.objects.filter(status="ACTIVE").count(),
        "blocked_count": BlockedIP.objects.count(),
        "recent_alerts": recent_alerts,
        "fastapi_url": FASTAPI_URL,
    }
    return render(request, "dashboard/index.html", context)


# ── Page 2: Packet Monitor ───────────────────────────────────────────────────
def monitor(request):
    context = {"fastapi_url": FASTAPI_URL}
    return render(request, "dashboard/monitor.html", context)


# ── Page 3: Analysis ────────────────────────────────────────────────────────
def analysis(request):
    days = 15
    since = timezone.now() - timedelta(days=days)
    daily_attacks = (
        Alert.objects.filter(timestamp__gte=since)
        .annotate(day=TruncDate("timestamp"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )
    # Build a full 15-day range (fill missing days with 0)
    date_map = {row["day"].isoformat(): row["count"] for row in daily_attacks}
    labels, values = [], []
    for i in range(days - 1, -1, -1):
        d = (timezone.now() - timedelta(days=i)).date()
        labels.append(d.strftime("%b %d"))
        values.append(date_map.get(d.isoformat(), 0))

    # Top attacking IPs
    top_ips = (
        Alert.objects.filter(timestamp__gte=since)
        .values("source_ip")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )
    blocked_ips = BlockedIP.objects.order_by("-blocked_at")[:20]
    context = {
        "chart_labels": json.dumps(labels),
        "chart_values": json.dumps(values),
        "top_ips": top_ips,
        "blocked_ips": blocked_ips,
        "total_blocked": Alert.objects.filter(status="BLOCKED").count(),
        "total_alerts": Alert.objects.filter(timestamp__gte=since).count(),
    }
    return render(request, "dashboard/analysis.html", context)


# ── AJAX: AI Chatbot proxy ───────────────────────────────────────────────────
@csrf_exempt
@require_POST
def chatbot(request):
    try:
        data = json.loads(request.body)
        message = data.get("message", "").strip()
        if not message:
            return JsonResponse({"error": "Empty message"}, status=400)
        r = httpx.post(
            f"{FASTAPI_URL}/api/chat",
            json={"message": message},
            timeout=30.0,
        )
        return JsonResponse(r.json())
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


# ── AJAX: Toggle IDS ─────────────────────────────────────────────────────────
@csrf_exempt
@require_POST
def toggle_ids(request):
    try:
        r = httpx.post(f"{FASTAPI_URL}/api/toggle", timeout=5.0)
        return JsonResponse(r.json())
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
