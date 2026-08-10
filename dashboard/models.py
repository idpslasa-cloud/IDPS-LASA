from django.db import models


class Alert(models.Model):
    ATTACK_TYPES = [
        ("ARP_SPOOF", "ARP Spoofing"),
        ("ICMP_FLOOD", "ICMP Flood"),
        ("PORT_SCAN", "Port Scan"),
    ]
    STATUS_CHOICES = [
        ("ACTIVE", "Active"),
        ("BLOCKED", "Blocked"),
        ("RESOLVED", "Resolved"),
    ]

    attack_type = models.CharField(max_length=20, choices=ATTACK_TYPES)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    source_port = models.IntegerField(null=True, blank=True)
    destination_port = models.IntegerField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="ACTIVE")
    description = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    extra_data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"[{self.attack_type}] {self.source_ip} @ {self.timestamp:%Y-%m-%d %H:%M}"


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255)
    blocked_at = models.DateTimeField(auto_now_add=True)
    permanent = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.ip_address} ({'permanent' if self.permanent else 'temp'})"


class PacketLog(models.Model):
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    src_port = models.IntegerField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10)
    size = models.IntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)
    flagged = models.BooleanField(default=False)

    class Meta:
        ordering = ["-timestamp"]
