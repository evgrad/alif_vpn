import time
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import F
from django.utils import timezone

from api.models import AdView, Server, Subscription, VpnSession


class Command(BaseCommand):
    help = "Expire stale sessions/ads/subscriptions and mark silent VPN nodes offline."

    def add_arguments(self, parser):
        parser.add_argument("--loop", action="store_true")
        parser.add_argument("--interval", type=int, default=30)

    def handle(self, *args, **options):
        if options["loop"]:
            interval = max(5, options["interval"])
            self.stdout.write(f"Maintenance loop started; interval={interval}s")
            while True:
                self.run_once()
                time.sleep(interval)
        else:
            self.run_once()

    def run_once(self):
        now = timezone.now()
        stale_before = now - timedelta(
            seconds=getattr(settings, "VPN_SESSION_HEARTBEAT_TIMEOUT_SECONDS", 300)
        )
        offline_before = now - timedelta(
            seconds=getattr(settings, "AGENT_STALE_AFTER_SECONDS", 180)
        )

        with transaction.atomic():
            AdView.objects.filter(
                status=AdView.Status.ISSUED,
                expires_at__lte=now,
            ).update(status=AdView.Status.EXPIRED)

            stale_sessions = list(VpnSession.objects.filter(
                status__in=[VpnSession.Status.CONNECTING, VpnSession.Status.CONNECTED],
                last_heartbeat_at__lte=stale_before,
            ).values_list("id", "server_id"))
            if stale_sessions:
                ids = [row[0] for row in stale_sessions]
                server_ids = {row[1] for row in stale_sessions}
                VpnSession.objects.filter(id__in=ids).update(
                    status=VpnSession.Status.REVOKE_PENDING,
                    ended_at=now,
                )
                Server.objects.filter(id__in=server_ids).update(
                    desired_version=F("desired_version") + 1
                )

            expired_subscriptions = Subscription.objects.filter(
                status=Subscription.Status.ACTIVE,
                expires_at__isnull=False,
                expires_at__lte=now,
            ).update(status=Subscription.Status.EXPIRED)

            offline_nodes = Server.objects.filter(
                status__in=[Server.Status.ACTIVE, Server.Status.DEGRADED],
                last_agent_check_in__isnull=False,
                last_agent_check_in__lte=offline_before,
            ).update(status=Server.Status.OFFLINE)

        self.stdout.write(
            f"Expired ads; revoke_pending_sessions={len(stale_sessions)}; "
            f"expired_subscriptions={expired_subscriptions}; offline_nodes={offline_nodes}"
        )
