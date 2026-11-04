from rest_framework.permissions import BasePermission

from .models import Device, Server


class IsDeviceOrUser(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and request.user.is_authenticated
        ) or isinstance(request.auth, Device)


class IsServerAgent(BasePermission):
    def has_permission(self, request, view):
        return isinstance(request.auth, Server)
