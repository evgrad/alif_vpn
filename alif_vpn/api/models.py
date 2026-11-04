import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class Device(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        REVOKED = "revoked", "Revoked"
        BANNED = "banned", "Banned"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="devices",
    )
    device_identifier = models.CharField(max_length=255, unique=True)
    token_hash = models.CharField(max_length=64, blank=True)
    platform = models.CharField(max_length=30)  # android, ios, windows, macos
    app_version = models.CharField(max_length=30, blank=True)
    status = models.CharField(
        max_length=10,
        choices=Status.choices,
        default=Status.ACTIVE,
    )
    last_seen_at = models.DateTimeField(default=timezone.now)
    allocation_window_started_at = models.DateTimeField(null=True, blank=True)
    allocations_in_window = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.platform}: {self.device_identifier}"


class Server(models.Model):
    class Status(models.TextChoices):
        PROVISIONING = "provisioning", "Provisioning"
        ACTIVE = "active", "Active"
        DEGRADED = "degraded", "Degraded"
        BLOCKED = "blocked", "Blocked"
        OFFLINE = "offline", "Offline"
        RETIRED = "retired", "Retired"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    region_code = models.CharField(max_length=10, db_index=True)
    country = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    endpoint = models.CharField(max_length=255)
    supported_protocols = models.JSONField(default=list)
    address_pool_cidr = models.CharField(max_length=43, blank=True)
    dns_servers = models.JSONField(default=list, blank=True)
    wireguard_server_public_key = models.CharField(max_length=64, blank=True)
    wireguard_port = models.PositiveIntegerField(default=51820)
    xray_port = models.PositiveIntegerField(default=443)
    xray_reality_public_key = models.CharField(max_length=255, blank=True)
    xray_sni = models.CharField(max_length=255, blank=True)
    xray_flow = models.CharField(max_length=100, blank=True)
    agent_token_hash = models.CharField(max_length=64, blank=True)
    is_premium_only = models.BooleanField(default=False)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PROVISIONING,
        db_index=True,
    )

    # Agent synchronization state
    desired_version = models.PositiveBigIntegerField(default=0)
    applied_version = models.PositiveBigIntegerField(default=0)
    last_agent_check_in = models.DateTimeField(null=True, blank=True)

    # Aggregate health data; do not store per-user traffic history here.
    current_load_percent = models.FloatField(default=0)
    active_peers_count = models.PositiveIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.region_code})"


class AdView(models.Model):
    class Status(models.TextChoices):
        ISSUED = "issued", "Issued"
        VERIFIED = "verified", "Verified"
        CONSUMED = "consumed", "Consumed"
        EXPIRED = "expired", "Expired"
        REJECTED = "rejected", "Rejected"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        related_name="ad_views",
    )
    # Store a hash of the nonce, not the raw nonce returned to the app.
    nonce_hash = models.CharField(max_length=64, unique=True)
    status = models.CharField(
        max_length=10,
        choices=Status.choices,
        default=Status.ISSUED,
        db_index=True,
    )
    expires_at = models.DateTimeField()
    verified_at = models.DateTimeField(null=True, blank=True)
    consumed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class VpnSession(models.Model):
    class Status(models.TextChoices):
        CONNECTING = "connecting", "Connecting"
        CONNECTED = "connected", "Connected"
        DISCONNECTED = "disconnected", "Disconnected"
        EXPIRED = "expired", "Expired"
        REVOKE_PENDING = "revoke_pending", "Revoke pending"

    class Protocol(models.TextChoices):
        WIREGUARD = "wireguard", "WireGuard"
        XRAY = "xray", "Xray"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(
        Device,
        on_delete=models.PROTECT,
        related_name="vpn_sessions",
    )
    server = models.ForeignKey(
        Server,
        on_delete=models.PROTECT,
        related_name="vpn_sessions",
    )
    protocol = models.CharField(max_length=20, choices=Protocol.choices)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.CONNECTING,
        db_index=True,
    )

    # Public/client identifier only. Never store a client's private key.
    client_public_key = models.CharField(max_length=255, blank=True)
    client_uuid = models.UUIDField(null=True, blank=True)
    internal_ip = models.GenericIPAddressField(null=True, blank=True)

    ad_view = models.ForeignKey(
        AdView,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="sessions",
    )
    idempotency_key = models.CharField(max_length=64, null=True, blank=True)

    started_at = models.DateTimeField(default=timezone.now)
    last_heartbeat_at = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["device", "status"]),
            models.Index(fields=["server", "status"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["server", "internal_ip"],
                condition=models.Q(internal_ip__isnull=False),
                name="unique_server_internal_ip",
            ),
            models.UniqueConstraint(
                fields=["device", "idempotency_key"],
                condition=models.Q(idempotency_key__isnull=False),
                name="unique_device_session_idempotency",
            ),
        ]

    def __str__(self):
        return f"{self.protocol} session {self.id}"


class Subscription(models.Model):
    class Store(models.TextChoices):
        APPLE = "apple", "Apple App Store"
        GOOGLE = "google", "Google Play"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        ACTIVE = "active", "Active"
        EXPIRED = "expired", "Expired"
        REFUNDED = "refunded", "Refunded"
        REVOKED = "revoked", "Revoked"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="subscriptions",
    )
    store = models.CharField(max_length=10, choices=Store.choices)
    product_id = models.CharField(max_length=255)
    original_transaction_id = models.CharField(max_length=255)
    transaction_id = models.CharField(max_length=255, blank=True)
    status = models.CharField(
        max_length=10,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["store", "original_transaction_id"],
                name="unique_store_original_transaction",
            )
        ]

    def __str__(self):
        return f"{self.store}: {self.product_id} ({self.status})"


class StoreNotification(models.Model):
    """Deduplication record for App Store / Google Play webhooks."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    store = models.CharField(max_length=10, choices=Subscription.Store.choices)
    notification_id = models.CharField(max_length=255)
    received_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    processing_error = models.TextField(blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["store", "notification_id"],
                name="unique_store_notification",
            )
        ]
