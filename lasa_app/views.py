from django.http import JsonResponse
from django.shortcuts import render

from lasa_core.firewall import get_blocked_ips, get_permanent_bans, reset_firewall


# -----------------------------
# DASHBOARD PAGE
# -----------------------------
def dashboard(request):

    return render(request, "dashboard.html")


# -----------------------------
# ALERTS PAGE
# -----------------------------
def alerts(request):

    # If you later store alerts in a file/db
     return render(request, "alerts.html")

#    alerts_data = []

#    return JsonResponse({
 #       "alerts": alerts_data
  #  })


# -----------------------------
# BLOCKED IPS
# -----------------------------
def blocked_ips(request):

    ips = get_blocked_ips()

    return JsonResponse({
        "blocked_ips": ips
    })


# -----------------------------
# PERMANENT BANS
# -----------------------------
def permanent_bans(request):

    ips = get_permanent_bans()

    return JsonResponse({
        "permanent_bans": ips
    })


# -----------------------------
# RESET FIREWALL
# -----------------------------
def reset_firewall_view(request):

    if request.method == "POST":

        reset_firewall()

        return JsonResponse({
            "status": "Firewall Reset"
        })

    return JsonResponse({
        "status": "Invalid request"
    })
