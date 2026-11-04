import hashlib
import hmac
import ipaddress
import secrets
import uuid
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import authenticate
from django.db import transaction
from django.db.models import F, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework import generics, status
from rest_framework.exceptions import (
    NotAuthenticated,
    NotFound,
    PermissionDenied,
    Throttled,
    ValidationError,
)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .authentication import AgentTokenAuthentication
from .models import AdView, Device, Server, Subscription, VpnSession
from .permissions import IsDeviceOrUser, IsServerAgent
from .serializers import (
    AdVerificationSerializer,
    AdViewCreateSerializer,
    AdViewCreatedResponseSerializer,
    AgentAcknowledgementSerializer,
    AgentCheckInSerializer,
    DeviceRegistrationSerializer,
    DeviceSerializer,
    EmailLoginSerializer,
    RegisterSerializer,
    ServerSerializer,
    SubscriptionRestoreSerializer,
    PurchaseConfirmationSerializer,
    SubscriptionSerializer,
    VpnSessionCreateSerializer,
    VpnSessionSerializer,
)


def _device_for_request(request, device_id):
    if isinstance(request.auth, Device):
        if str(request.auth.pk) != str(device_id):
            raise NotFound("Устройство не найдено.")
        return request.auth
    if request.user and request.user.is_authenticated:
        return get_object_or_404(
            Device,
            id=device_id,
            user=request.user,
            status=Device.Status.ACTIVE,
        )
    raise NotAuthenticated("Нужен JWT или токен зарегистрированного устройства.")


def _session_for_request(request, session_id):
    session = get_object_or_404(VpnSession, id=session_id)
    if isinstance(request.auth, Device):
        if session.device_id != request.auth.pk:
            raise NotFound("Сессия не найдена.")
    elif request.user and request.user.is_authenticated:
        if session.device.user_id != request.user.pk:
            raise NotFound("Сессия не найдена.")
    else:
        raise NotAuthenticated()
    return session


def _user_has_premium(user):
    if not user or not user.is_authenticated:
        return False
    now = timezone.now()
    return Subscription.objects.filter(
        user=user,
        status=Subscription.Status.ACTIVE,
    ).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=now)
    ).exists()


def _session_response(session):
    server = session.server
    endpoint = server.endpoint.strip()
    port = server.wireguard_port if session.protocol == VpnSession.Protocol.WIREGUARD else server.xray_port
    if endpoint.startswith("[") and "]:" in endpoint:
        endpoint, configured_port = endpoint[1:].split("]:", 1)
        if configured_port.isdigit():
            port = int(configured_port)
    elif endpoint.count(":") == 1:
        candidate_host, candidate_port = endpoint.rsplit(":", 1)
        if candidate_port.isdigit():
            endpoint, port = candidate_host, int(candidate_port)
    elif endpoint.count(":") > 1:
        endpoint = f"[{endpoint}]"  # Unbracketed IPv6 literal.

    if session.protocol == VpnSession.Protocol.WIREGUARD:
        config = {
            "protocol": "wireguard",
            "endpoint": endpoint,
            "port": port,
            "client_public_key": session.client_public_key,
            "server_public_key": server.wireguard_server_public_key,
            "internal_ip": session.internal_ip,
            "allowed_ips": ["0.0.0.0/0"],
            "dns": server.dns_servers,
        }
    else:
        config = {
            "protocol": "xray",
            "endpoint": endpoint,
            "port": port,
            "client_uuid": session.client_uuid,
            "server_name": server.xray_sni,
            "public_key": server.xray_reality_public_key,
            "flow": server.xray_flow,
        }

    return {
        **VpnSessionSerializer(session).data,
        "configuration": config,
    }


def _allocate_ipv4(server):
    if not server.address_pool_cidr:
        raise ValidationError({"server": "Для узла не настроен address_pool_cidr."})
    try:
        network = ipaddress.ip_network(server.address_pool_cidr, strict=False)
    except ValueError:
        raise ValidationError({"server": "Некорректный address_pool_cidr у узла."})
    if network.version != 4 or network.num_addresses > 65536:
        raise ValidationError({"server": "Для MVP требуется IPv4-пул не больше /16."})

    used = set(
        VpnSession.objects.filter(server=server, internal_ip__isnull=False)
        .values_list("internal_ip", flat=True)
    )
    hosts = network.hosts()
    next(hosts, None)  # Первый host зарезервирован как адрес VPN-шлюза.
    for address in hosts:
        if str(address) not in used:
            return address
    raise ValidationError({"server": "В адресном пуле узла закончились адреса."})


class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        return Response(
            {
                "user": {"id": user.pk, "email": user.email},
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        serializer = EmailLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"].strip().lower()
        user = authenticate(
            request=request,
            username=email,
            password=serializer.validated_data["password"],
        )
        if user is None or not user.is_active:
            return Response(
                {"detail": "Неверный email или пароль."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        refresh = RefreshToken.for_user(user)
        return Response(
            {
                "user": {"id": user.pk, "email": user.email},
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }
        )


class DeviceRegistrationView(APIView):
    """Create a device identity; the device token is returned only once."""

    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        serializer = DeviceRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        identifier = serializer.validated_data["device_identifier"]

        existing = Device.objects.filter(device_identifier=identifier).first()
        if existing:
            owns_device = (
                isinstance(request.auth, Device)
                and request.auth.pk == existing.pk
            ) or (
                request.user.is_authenticated
                and existing.user_id == request.user.pk
            )
            if not owns_device:
                raise PermissionDenied(
                    "Устройство уже зарегистрировано. Используй его сохранённый токен."
                )
            existing.platform = serializer.validated_data["platform"]
            existing.app_version = serializer.validated_data.get("app_version", "")
            existing.last_seen_at = timezone.now()
            existing.save(update_fields=["platform", "app_version", "last_seen_at"])
            return Response(DeviceSerializer(existing).data)

        raw_token = secrets.token_urlsafe(32)
        device = Device.objects.create(
            device_identifier=identifier,
            platform=serializer.validated_data["platform"],
            app_version=serializer.validated_data.get("app_version", ""),
            user=request.user if request.user.is_authenticated else None,
            token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
        )
        return Response(
            {**DeviceSerializer(device).data, "device_token": raw_token},
            status=status.HTTP_201_CREATED,
        )


class ServerListView(generics.ListAPIView):
    serializer_class = ServerSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        queryset = Server.objects.filter(status=Server.Status.ACTIVE)
        region_code = self.request.query_params.get("region_code")
        protocol = self.request.query_params.get("protocol")
        if region_code:
            queryset = queryset.filter(region_code=region_code)
        if protocol:
            queryset = queryset.filter(supported_protocols__contains=[protocol])
        if not _user_has_premium(self.request.user):
            queryset = queryset.filter(is_premium_only=False)
        return queryset.order_by("current_load_percent")


class AdViewCreateView(APIView):
    permission_classes = [IsDeviceOrUser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "ads"

    def post(self, request):
        serializer = AdViewCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        device = _device_for_request(request, serializer.validated_data["device_id"])
        nonce = secrets.token_urlsafe(32)
        ad_view = AdView.objects.create(
            device=device,
            nonce_hash=hashlib.sha256(nonce.encode()).hexdigest(),
            expires_at=timezone.now() + timedelta(seconds=120),
        )
        return Response(
            AdViewCreatedResponseSerializer(
                {
                    "ad_view_id": ad_view.id,
                    "nonce": nonce,
                    "expires_at": ad_view.expires_at,
                }
            ).data,
            status=status.HTTP_201_CREATED,
        )


class AdViewVerifyView(APIView):
    """Generic HMAC callback adapter; map a provider's signature to this contract."""

    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "ads"

    def post(self, request, ad_view_id):
        serializer = AdVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        secret = getattr(settings, "AD_CALLBACK_SECRET", "")
        if not secret:
            return Response(
                {"detail": "AD_CALLBACK_SECRET не настроен."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        nonce = serializer.validated_data["nonce"]
        notification_id = serializer.validated_data["notification_id"]
        signature = serializer.validated_data["signature"]
        signed_value = f"{ad_view_id}:{nonce}:{notification_id}".encode()
        expected = hmac.new(secret.encode(), signed_value, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise PermissionDenied("Подпись callback недействительна.")

        with transaction.atomic():
            ad_view = get_object_or_404(
                AdView.objects.select_for_update(), id=ad_view_id
            )
            if ad_view.status != AdView.Status.ISSUED:
                return Response(
                    {"detail": "Callback уже обработан или nonce использован."},
                    status=status.HTTP_409_CONFLICT,
                )
            if ad_view.expires_at <= timezone.now():
                ad_view.status = AdView.Status.EXPIRED
                ad_view.save(update_fields=["status"])
                raise ValidationError("Срок действия рекламного nonce истёк.")
            nonce_hash = hashlib.sha256(nonce.encode()).hexdigest()
            if not hmac.compare_digest(ad_view.nonce_hash, nonce_hash):
                raise PermissionDenied("Nonce не совпадает.")
            ad_view.status = AdView.Status.VERIFIED
            ad_view.verified_at = timezone.now()
            ad_view.save(update_fields=["status", "verified_at"])

        return Response({"status": "verified"}, status=status.HTTP_200_OK)


class VpnSessionListCreateView(APIView):
    permission_classes = [IsDeviceOrUser]

    def get(self, request):
        if isinstance(request.auth, Device):
            sessions = VpnSession.objects.filter(device=request.auth)
        else:
            sessions = VpnSession.objects.filter(device__user=request.user)
        sessions = sessions.order_by("-started_at")
        return Response(VpnSessionSerializer(sessions, many=True).data)

    def post(self, request):
        serializer = VpnSessionCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        device = _device_for_request(request, data["device_id"])

        with transaction.atomic():
            device = Device.objects.select_for_update().get(pk=device.pk)
            server = get_object_or_404(
                Server.objects.select_for_update(),
                id=data["server_id"],
                status=Server.Status.ACTIVE,
            )

            if request.user.is_authenticated and device.user_id != request.user.pk:
                raise NotFound("Устройство не найдено.")
            if data["protocol"] not in server.supported_protocols:
                raise ValidationError({"protocol": "Протокол не поддерживается узлом."})

            idempotency_key = str(data.get("idempotency_key", "")) or None
            if idempotency_key:
                previous = VpnSession.objects.filter(
                    device=device, idempotency_key=idempotency_key
                ).first()
                if previous:
                    if (
                        previous.server_id != server.pk
                        or previous.protocol != data["protocol"]
                        or previous.client_public_key != data.get("client_public_key", "")
                    ):
                        raise ValidationError({
                            "idempotency_key": "Ключ уже использован с другим запросом."
                        })
                    return Response(_session_response(previous))

            now = timezone.now()
            if (
                device.allocation_window_started_at is None
                or device.allocation_window_started_at <= now - timedelta(minutes=1)
            ):
                device.allocation_window_started_at = now
                device.allocations_in_window = 0
            if device.allocations_in_window >= 3:
                raise Throttled(detail="Превышен лимит: 3 выдачи в минуту на устройство.")

            premium = _user_has_premium(request.user)
            if server.is_premium_only and not premium:
                raise PermissionDenied("Для этого сервера нужна активная Premium-подписка.")

            if premium:
                # Locking the user row serializes concurrent Premium allocations.
                from django.contrib.auth import get_user_model
                User = get_user_model()
                User.objects.select_for_update().get(pk=request.user.pk)
                active_count = VpnSession.objects.filter(
                    device__user=request.user,
                    status__in=[
                        VpnSession.Status.CONNECTING,
                        VpnSession.Status.CONNECTED,
                        VpnSession.Status.REVOKE_PENDING,
                    ],
                ).count()
                if active_count >= 5:
                    raise ValidationError(
                        {"sessions": "Достигнут лимит в 5 одновременных сессий."},
                        code="SESSION_LIMIT_REACHED",
                    )

            ad_view = None
            if not premium:
                if not data.get("ad_view_id"):
                    raise PermissionDenied("Для бесплатного подключения нужно подтвердить рекламу.")
                ad_view = get_object_or_404(
                    AdView.objects.select_for_update(),
                    id=data["ad_view_id"],
                    device=device,
                )
                if ad_view.status != AdView.Status.VERIFIED or ad_view.expires_at <= now:
                    raise PermissionDenied("Нет действительного подтверждённого просмотра рекламы.")

            session_fields = {
                "device": device,
                "server": server,
                "protocol": data["protocol"],
                "status": VpnSession.Status.CONNECTING,
                "client_public_key": data.get("client_public_key", ""),
                "ad_view": ad_view,
                "idempotency_key": idempotency_key,
            }
            if data["protocol"] == VpnSession.Protocol.WIREGUARD:
                if not server.wireguard_server_public_key or not server.address_pool_cidr:
                    raise ValidationError("Узел не настроен для WireGuard.")
                session_fields["internal_ip"] = _allocate_ipv4(server)
            else:
                if not server.xray_reality_public_key or not server.xray_sni:
                    raise ValidationError("Узел не настроен для Xray/Reality.")
                session_fields["client_uuid"] = uuid.uuid4()

            session = VpnSession.objects.create(**session_fields)
            if ad_view:
                ad_view.status = AdView.Status.CONSUMED
                ad_view.consumed_at = now
                ad_view.save(update_fields=["status", "consumed_at"])

            device.allocations_in_window += 1
            device.save(update_fields=["allocation_window_started_at", "allocations_in_window"])
            server.desired_version = F("desired_version") + 1
            server.save(update_fields=["desired_version"])
            server.refresh_from_db(fields=["desired_version"])

        return Response(_session_response(session), status=status.HTTP_201_CREATED)


class VpnSessionHeartbeatView(APIView):
    permission_classes = [IsDeviceOrUser]

    def post(self, request, session_id):
        session = _session_for_request(request, session_id)
        if session.status not in [VpnSession.Status.CONNECTING, VpnSession.Status.CONNECTED]:
            raise ValidationError("Сессия уже не активна.")
        session.status = VpnSession.Status.CONNECTED
        session.last_heartbeat_at = timezone.now()
        session.save(update_fields=["status", "last_heartbeat_at"])
        return Response(VpnSessionSerializer(session).data)


class VpnSessionDetailView(APIView):
    permission_classes = [IsDeviceOrUser]

    def delete(self, request, session_id):
        with transaction.atomic():
            session = _session_for_request(request, session_id)
            if session.status not in [
                VpnSession.Status.DISCONNECTED,
                VpnSession.Status.EXPIRED,
                VpnSession.Status.REVOKE_PENDING,
            ]:
                session.status = VpnSession.Status.REVOKE_PENDING
                session.ended_at = timezone.now()
                session.save(update_fields=["status", "ended_at"])
                Server.objects.filter(pk=session.server_id).update(
                    desired_version=F("desired_version") + 1
                )
        return Response(VpnSessionSerializer(session).data, status=status.HTTP_200_OK)


class AgentAPIView(APIView):
    authentication_classes = [AgentTokenAuthentication]
    permission_classes = [IsServerAgent]


class AgentPollView(AgentAPIView):
    def post(self, request):
        serializer = AgentCheckInSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        server = request.auth
        if str(data["node_id"]) != str(server.pk):
            raise NotFound("VPN-узел не найден.")

        metrics = data["metrics"]
        if data["applied_version"] > server.desired_version:
            raise ValidationError("Агент сообщил неизвестную версию конфигурации.")
        server.last_agent_check_in = timezone.now()
        server.applied_version = data["applied_version"]
        server.active_peers_count = metrics["active_peers_count"]
        server.current_load_percent = max(
            metrics["cpu_usage_percent"], metrics["memory_usage_percent"]
        )
        if server.status not in [Server.Status.BLOCKED, Server.Status.RETIRED]:
            server.status = Server.Status.ACTIVE
        server.save(update_fields=[
            "last_agent_check_in", "applied_version", "active_peers_count",
            "current_load_percent", "status",
        ])

        peers = []
        if data["applied_version"] != server.desired_version:
            sessions = VpnSession.objects.filter(
                server=server,
                status__in=[
                    VpnSession.Status.CONNECTING,
                    VpnSession.Status.CONNECTED,
                    VpnSession.Status.REVOKE_PENDING,
                ],
            )
            for session in sessions:
                peer = {
                    "peer_id": str(session.pk),
                    "protocol": session.protocol,
                    "action": "REVOKE" if session.status == VpnSession.Status.REVOKE_PENDING else "REGISTER",
                }
                if session.protocol == VpnSession.Protocol.WIREGUARD:
                    peer.update({
                        "public_key": session.client_public_key,
                        "internal_ip": f"{session.internal_ip}/32",
                        "bandwidth_limit_mbps": None if _user_has_premium(session.device.user) else 2.0,
                    })
                else:
                    peer["xray_uuid"] = str(session.client_uuid)
                peers.append(peer)

        return Response({
            "data": {
                "desired_version": server.desired_version,
                "full_sync": data["applied_version"] == 0,
                "peers": peers,
            },
            "error": None,
        })


class AgentAcknowledgementView(AgentAPIView):
    def post(self, request):
        serializer = AgentAcknowledgementSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        server = request.auth
        if data["applied_version"] < server.applied_version:
            raise ValidationError("Нельзя откатить подтверждённую версию конфигурации.")
        if data["applied_version"] > server.desired_version:
            raise ValidationError("Агент подтвердил неизвестную версию конфигурации.")

        revoked_ids = data["revoked_session_ids"]
        if revoked_ids:
            targets = VpnSession.objects.filter(
                pk__in=revoked_ids,
                server=server,
                status=VpnSession.Status.REVOKE_PENDING,
            )
            if targets.count() != len(set(revoked_ids)):
                raise ValidationError("Список содержит неизвестные или неотзываемые сессии.")
            targets.update(
                status=VpnSession.Status.DISCONNECTED,
                internal_ip=None,
                client_public_key="",
                client_uuid=None,
            )

        server.applied_version = data["applied_version"]
        server.save(update_fields=["applied_version"])
        return Response({"status": "acknowledged", "applied_version": server.applied_version})


class MySubscriptionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        subscription = (
            Subscription.objects.filter(user=request.user)
            .order_by("-created_at")
            .first()
        )
        return Response({
            "subscription": SubscriptionSerializer(subscription).data if subscription else None
        })


class MyAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        subscription = (
            Subscription.objects.filter(user=request.user)
            .order_by("-created_at")
            .first()
        )
        return Response({
            "id": request.user.pk,
            "email": request.user.email,
            "is_premium": _user_has_premium(request.user),
            "subscription": SubscriptionSerializer(subscription).data if subscription else None,
        })


class StoreVerificationPendingView(APIView):
    """Fail-closed until a real Apple/Google verifier and credentials are configured."""

    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer_class = self.serializer_class
        serializer = serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {
                "code": "STORE_VERIFICATION_NOT_CONFIGURED",
                "detail": "Проверка чеков магазина не настроена; Premium не активирован.",
            },
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class PurchaseConfirmationView(StoreVerificationPendingView):
    serializer_class = PurchaseConfirmationSerializer


class PurchaseRestoreView(StoreVerificationPendingView):
    serializer_class = SubscriptionRestoreSerializer


class StoreWebhookPendingView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        return Response(
            {
                "code": "STORE_WEBHOOK_VERIFICATION_NOT_CONFIGURED",
                "detail": "Подпись уведомления App Store/Google Play пока не проверяется.",
            },
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
