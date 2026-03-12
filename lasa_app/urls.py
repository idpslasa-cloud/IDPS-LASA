from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('api/alerts/', views.alerts, name='alerts'),
    path('api/blocked/', views.blocked_ips, name='blocked_ips'),
    path('api/bans/', views.permanent_bans, name='permanent_bans'),
    path('api/arp/', views.arp_status, name='arp_status'),
    path('api/start/', views.start_ids, name='start_ids'),
    path('api/stop/', views.stop_ids, name='stop_ids'),
    path('api/unblock/<str:ip>/', views.unblock_ip_view, name='unblock_ip'),
    path('api/unban/<str:ip>/', views.remove_ban_view, name='remove_ban'),
    path('api/reset/', views.reset_firewall_view, name='reset_firewall'),
]

