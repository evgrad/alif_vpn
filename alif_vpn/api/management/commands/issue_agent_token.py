import hashlib
import secrets

from django.core.management.base import BaseCommand, CommandError

from api.models import Server


class Command(BaseCommand):
    help = "Create/rotate a VPN node agent token. The raw token is shown only once."

    def add_arguments(self, parser):
        parser.add_argument("server_id")

    def handle(self, *args, **options):
        try:
            server = Server.objects.get(pk=options["server_id"])
        except (Server.DoesNotExist, ValueError):
            raise CommandError("Server with this UUID was not found.")

        raw_token = secrets.token_urlsafe(48)
        server.agent_token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        server.save(update_fields=["agent_token_hash"])
        self.stdout.write(self.style.SUCCESS("Agent token (copy now; it cannot be recovered):"))
        self.stdout.write(raw_token)
        self.stdout.write(self.style.WARNING(
            "Development bearer token only. Use HTTPS and replace with mTLS before production."
        ))
