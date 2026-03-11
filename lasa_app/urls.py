from django.urls import path
from . import views

urlpatterns = [

    path('', views.dashboard),
    path('alerts/', views.alerts),

    path('blocked/', views.blocked_ips),
    path('permanent/', views.permanent_bans),

    path('reset/', views.reset_firewall_view),

]
