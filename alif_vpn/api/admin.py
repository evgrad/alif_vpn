from django.contrib import admin
from .models import AdView, Device, Server, StoreNotification, Subscription, VpnSession


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "region_code",
        "country",
        "city",
        "status",
        "is_premium_only",
        "current_load_percent",
    )
    list_filter = ("status", "is_premium_only", "region_code")
    search_fields = ("name", "country", "city", "region_code")
    exclude = ("agent_token_hash",)


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("device_identifier", "platform", "status", "user", "last_seen_at")
    list_filter = ("platform", "status")
    search_fields = ("device_identifier", "user__email")
    exclude = ("token_hash",)


@admin.register(VpnSession)
class VpnSessionAdmin(admin.ModelAdmin):
    list_display = ("id", "device", "server", "protocol", "status", "started_at")
    list_filter = ("protocol", "status")
    exclude = ("client_uuid",)


admin.site.register(AdView)
admin.site.register(Subscription)
admin.site.register(StoreNotification)
