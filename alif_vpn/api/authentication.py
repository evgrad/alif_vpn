import hashlib
import hmac

from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import Device, Server


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class DeviceTokenAuthentication(BaseAuthentication):
    """Authenticate an app installation using X-Device-ID and X-Device-Token."""

    def authenticate(self, request):
        device_id = request.headers.get("X-Device-ID")
        token = request.headers.get("X-Device-Token")
        if not device_id and not token:
            return None
        if not device_id or not token:
            raise AuthenticationFailed("Нужны X-Device-ID и X-Device-Token.")

        try:
            device = Device.objects.select_related("user").get(
                id=device_id,
                status=Device.Status.ACTIVE,
            )
        except (Device.DoesNotExist, ValueError):
            raise AuthenticationFailed("Устройство не найдено или заблокировано.")

        if not device.token_hash or not hmac.compare_digest(
            device.token_hash, _digest(token)
        ):
            raise AuthenticationFailed("Неверный токен устройства.")

        user = device.user or AnonymousUser()
        return user, device

    def authenticate_header(self, request):
        return "X-Device-Token"


class AgentTokenAuthentication(BaseAuthentication):
    """Development agent auth; production should use mutual TLS."""

    def authenticate(self, request):
        server_id = request.headers.get("X-Agent-ID")
        token = request.headers.get("X-Agent-Token")
        if not server_id and not token:
            return None
        if not server_id or not token:
            raise AuthenticationFailed("Нужны X-Agent-ID и X-Agent-Token.")

        try:
            server = Server.objects.get(id=server_id)
        except (Server.DoesNotExist, ValueError):
            raise AuthenticationFailed("VPN-узел не найден.")

        if not server.agent_token_hash or not hmac.compare_digest(
            server.agent_token_hash, _digest(token)
        ):
            raise AuthenticationFailed("Неверный токен агента.")

        return AnonymousUser(), server

    def authenticate_header(self, request):
        return "X-Agent-Token"
