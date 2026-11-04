import base64
import binascii

from rest_framework import serializers
from django.contrib.auth import get_user_model, password_validation
from django.core.exceptions import ValidationError as DjangoValidationError

from .models import (
    AdView,
    Device,
    Server,
    StoreNotification,
    Subscription,
    VpnSession,
)

User = get_user_model()


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=150)
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
        min_length=8,
        style={"input_type": "password"},
    )
    password_confirm = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
        style={"input_type": "password"},
    )

    def validate_email(self, value):
        value = value.strip().lower()
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("Пользователь с таким email уже зарегистрирован.")
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("Этот email уже занят.")
        return value

    def validate(self, attrs):
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError({"password_confirm": "Пароли не совпадают."})

        candidate = User(email=attrs["email"], username=attrs["email"])
        try:
            password_validation.validate_password(attrs["password"], user=candidate)
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"password": list(exc.messages)})
        return attrs

    def create(self, validated_data):
        password = validated_data["password"]
        email = validated_data["email"]
        return User.objects.create_user(
            username=email,
            email=email,
            password=password,
        )


class EmailLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
        style={"input_type": "password"},
    )


# Users and Devices

class DeviceRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = (
            "id",
            "device_identifier",
            "platform",
            "app_version",
            "status",
            "last_seen_at",
            "created_at",
        )
        read_only_fields = ("id", "status", "last_seen_at", "created_at")


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = (
            "id",
            "platform",
            "app_version",
            "status",
            "last_seen_at",
            "created_at",
        )
        read_only_fields = fields


class DeviceRegistrationResponseSerializer(DeviceSerializer):
    device_token = serializers.CharField()


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
        style={"input_type": "password"},
    )


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(write_only=True)


class AccountSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    email = serializers.EmailField(read_only=True)
    is_premium = serializers.BooleanField(read_only=True)
    subscription_status = serializers.CharField(read_only=True)


class AccountDeletionSerializer(serializers.Serializer):
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
        required=False,
        style={"input_type": "password"},
    )
    confirmation = serializers.BooleanField()


# Servers

class ServerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Server
        fields = (
            "id",
            "name",
            "region_code",
            "country",
            "city",
            "endpoint",
            "supported_protocols",
            "is_premium_only",
            "status",
            "current_load_percent",
        )
        read_only_fields = fields


# Advertisements

class AdViewCreateSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()


class AdViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdView
        fields = ("id", "status", "expires_at", "created_at")
        read_only_fields = fields


class AdViewCreatedResponseSerializer(serializers.Serializer):
    ad_view_id = serializers.UUIDField()
    nonce = serializers.CharField()
    expires_at = serializers.DateTimeField()


class AdVerificationSerializer(serializers.Serializer):
    # Поля зависят от рекламной сети.
    # Подпись callback обязательно проверяй серверным кодом.
    notification_id = serializers.CharField()
    nonce = serializers.CharField(write_only=True)
    signature = serializers.CharField(write_only=True)


# VPN Sessions

class VpnSessionCreateSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()
    server_id = serializers.UUIDField()
    protocol = serializers.ChoiceField(choices=VpnSession.Protocol.choices)
    ad_view_id = serializers.UUIDField(required=False)
    client_public_key = serializers.CharField(max_length=64, required=False, allow_blank=False)

    # Ключ идемпотентности можно передавать в заголовке,
    # поэтому здесь он необязателен.
    idempotency_key = serializers.UUIDField(required=False)

    def validate(self, attrs):
        if (
            attrs["protocol"] == VpnSession.Protocol.WIREGUARD
            and not attrs.get("client_public_key")
        ):
            raise serializers.ValidationError({
                "client_public_key": "Для WireGuard нужен публичный ключ, созданный на устройстве."
            })
        public_key = attrs.get("client_public_key")
        if public_key:
            try:
                decoded = base64.b64decode(public_key, validate=True)
            except (ValueError, binascii.Error):
                raise serializers.ValidationError({
                    "client_public_key": "Ожидается корректный base64 WireGuard public key."
                })
            if len(decoded) != 32:
                raise serializers.ValidationError({
                    "client_public_key": "WireGuard public key должен декодироваться в 32 байта."
                })
        return attrs


class VpnConfigurationSerializer(serializers.Serializer):
    protocol = serializers.ChoiceField(choices=VpnSession.Protocol.choices)

    # WireGuard config fields
    endpoint = serializers.CharField(required=False)
    client_public_key = serializers.CharField(required=False)
    server_public_key = serializers.CharField(required=False)
    internal_ip = serializers.IPAddressField(required=False)
    allowed_ips = serializers.ListField(
        child=serializers.CharField(),
        required=False,
    )
    dns = serializers.ListField(
        child=serializers.IPAddressField(),
        required=False,
    )

    # Xray config fields
    client_uuid = serializers.UUIDField(required=False)
    port = serializers.IntegerField(required=False)
    server_name = serializers.CharField(required=False)
    sni = serializers.CharField(required=False)
    public_key = serializers.CharField(required=False)
    flow = serializers.CharField(required=False)


class VpnSessionCreatedSerializer(serializers.ModelSerializer):
    configuration = VpnConfigurationSerializer(read_only=True)

    class Meta:
        model = VpnSession
        fields = (
            "id",
            "protocol",
            "status",
            "started_at",
            "configuration",
        )
        read_only_fields = fields


class VpnSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = VpnSession
        fields = (
            "id",
            "server",
            "protocol",
            "status",
            "started_at",
            "last_heartbeat_at",
            "ended_at",
        )
        read_only_fields = fields


class SessionHeartbeatSerializer(serializers.Serializer):
    pass


# Subscriptions

class PurchaseConfirmationSerializer(serializers.Serializer):
    store = serializers.ChoiceField(choices=Subscription.Store.choices)
    product_id = serializers.CharField()
    receipt_data = serializers.CharField(write_only=True)
    transaction_id = serializers.CharField(required=False)


class SubscriptionRestoreSerializer(serializers.Serializer):
    store = serializers.ChoiceField(choices=Subscription.Store.choices)
    receipt_data = serializers.CharField(write_only=True)


class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields = (
            "id",
            "store",
            "product_id",
            "status",
            "expires_at",
            "created_at",
        )
        read_only_fields = fields


class StoreNotificationSerializer(serializers.Serializer):
    store = serializers.ChoiceField(choices=Subscription.Store.choices)
    notification_id = serializers.CharField()
    signed_payload = serializers.CharField(write_only=True)


class AgentMetricsSerializer(serializers.Serializer):
    cpu_usage_percent = serializers.FloatField(min_value=0, max_value=100, default=0)
    memory_usage_percent = serializers.FloatField(min_value=0, max_value=100, default=0)
    active_peers_count = serializers.IntegerField(min_value=0, default=0)
    network_tx_bytes_sec = serializers.IntegerField(min_value=0, default=0)
    network_rx_bytes_sec = serializers.IntegerField(min_value=0, default=0)


class AgentCheckInSerializer(serializers.Serializer):
    node_id = serializers.UUIDField()
    agent_version = serializers.CharField(max_length=40)
    applied_version = serializers.IntegerField(min_value=0)
    metrics = AgentMetricsSerializer()


class AgentAcknowledgementSerializer(serializers.Serializer):
    applied_version = serializers.IntegerField(min_value=0)
    revoked_session_ids = serializers.ListField(
        child=serializers.UUIDField(), required=False, default=list
    )
