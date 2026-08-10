from django.contrib import admin
from .models import Alert, BlockedIP, PacketLog

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("attack_type", "source_ip", "status", "timestamp")
    list_filter = ("attack_type", "status")
    search_fields = ("source_ip",)

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "reason", "blocked_at", "permanent")

@admin.register(PacketLog)
class PacketLogAdmin(admin.ModelAdmin):
    list_display = ("src_ip", "dst_ip", "protocol", "size", "timestamp", "flagged")
