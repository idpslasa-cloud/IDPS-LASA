from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
import json

# Import after fixing circular imports - safe imports inside functions
def dashboard(request):
    from lasa_core.ids_detector import get_status, get_recent_alerts, get_arp_table
    context = {
        'status': get_status(),
        'alerts': get_recent_alerts()[-5:],
        'arp_table': get_arp_table(),
        'blocked_ips': [],  # Placeholder
        'permanent_bans': [],  # Placeholder
    }
    return render(request, "dashboard.html", context)

def alerts(request):
    from lasa_core.ids_detector import get_recent_alerts
    return JsonResponse({'alerts': get_recent_alerts()})

def blocked_ips(request):
    from lasa_core.firewall import get_blocked_ips
    return JsonResponse({'blocked_ips': get_blocked_ips()})

def permanent_bans(request):
    from lasa_core.firewall import get_permanent_bans
    return JsonResponse({'permanent_bans': get_permanent_bans()})

def arp_status(request):
    from lasa_core.ids_detector import get_arp_table
    return JsonResponse({'arp_table': get_arp_table()})

@csrf_exempt
def start_ids(request):
    if request.method == "POST":
        from lasa_core.ids_detector import start_sniffer
        start_sniffer()
        return JsonResponse({'status': 'started'})
    return JsonResponse({'error': 'POST required'}, status=405)

@csrf_exempt
def stop_ids(request):
    if request.method == "POST":
        from lasa_core.ids_detector import stop_sniffer
        stop_sniffer()
        return JsonResponse({'status': 'stopped'})
    return JsonResponse({'error': 'POST required'}, status=405)

@csrf_exempt
def unblock_ip_view(request, ip):
    if request.method == "POST":
        from lasa_core.firewall import unblock_ip
        unblock_ip(ip)
        return JsonResponse({'status': f'Unblocked {ip}'})
    return JsonResponse({'error': 'POST required'}, status=405)

@csrf_exempt
def remove_ban_view(request, ip):
    if request.method == "POST":
        from lasa_core.firewall import remove_permanent_ban
        remove_permanent_ban(ip)
        return JsonResponse({'status': f'Removed ban {ip}'})
    return JsonResponse({'error': 'POST required'}, status=405)

@csrf_exempt
def reset_firewall_view(request):
    if request.method == "POST":
        from lasa_core.firewall import reset_firewall
        reset_firewall()
        return JsonResponse({'status': 'Reset complete'})
    return JsonResponse({'error': 'POST required'}, status=405)

