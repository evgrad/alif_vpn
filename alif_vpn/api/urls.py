from django.urls import path
from rest_framework_simplejwt.views import TokenBlacklistView, TokenRefreshView

from .views import (
    AdViewCreateView,
    AdViewVerifyView,
    AgentAcknowledgementView,
    AgentPollView,
    DeviceRegistrationView,
    LoginView,
    MyAccountView,
    MySubscriptionView,
    PurchaseConfirmationView,
    PurchaseRestoreView,
    RegisterView,
    ServerListView,
    StoreWebhookPendingView,
    VpnSessionDetailView,
    VpnSessionHeartbeatView,
    VpnSessionListCreateView,
)

app_name = "api"

urlpatterns = [
    # Authentication
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("auth/logout/", TokenBlacklistView.as_view(), name="logout"),

    # Users and Devices
    path("devices/", DeviceRegistrationView.as_view(), name="device-registration"),
    path("me/", MyAccountView.as_view(), name="my-account"),

    # Servers
    path("servers/", ServerListView.as_view(), name="server-list"),

    # Advertisements
    path("ad-views/", AdViewCreateView.as_view(), name="ad-view-create"),
    path(
        "ad-views/<uuid:ad_view_id>/verify/",
        AdViewVerifyView.as_view(),
        name="ad-view-verify",
    ),

    # VPN Sessions
    path("sessions/", VpnSessionListCreateView.as_view(), name="session-list-create"),
    path(
        "sessions/<uuid:session_id>/heartbeat/",
        VpnSessionHeartbeatView.as_view(),
        name="session-heartbeat",
    ),
    path(
        "sessions/<uuid:session_id>/",
        VpnSessionDetailView.as_view(),
        name="session-detail",
    ),

    # Subscriptions
    path("subscription/", MySubscriptionView.as_view(), name="my-subscription"),
    path("subscription/purchases/", PurchaseConfirmationView.as_view(), name="purchase-confirm"),
    path("subscription/restore/", PurchaseRestoreView.as_view(), name="purchase-restore"),
    path("webhooks/store-notifications/", StoreWebhookPendingView.as_view(), name="store-webhook"),

    # VPN node agent
    path("agent/check-in/", AgentPollView.as_view(), name="agent-check-in"),
    path("agent/acknowledgements/", AgentAcknowledgementView.as_view(), name="agent-acknowledgement"),
]
