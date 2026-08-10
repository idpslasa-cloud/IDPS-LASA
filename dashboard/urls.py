from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("monitor/", views.monitor, name="monitor"),
    path("analysis/", views.analysis, name="analysis"),
    path("api/chat/", views.chatbot, name="chatbot"),
    path("api/toggle/", views.toggle_ids, name="toggle_ids"),
]
