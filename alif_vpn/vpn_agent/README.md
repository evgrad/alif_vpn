# Alif VPN node agent (WireGuard MVP)

This Linux agent synchronizes WireGuard peers with the Django API. It uses the
existing `POST /api/v1/agent/check-in/` and `POST /api/v1/agent/acknowledgements/`
endpoints. The agent does not support Xray/Reality and refuses unknown actions.

## Requirements on the VPN node

- Linux with WireGuard installed and an already configured interface (default `wg0`)
- Python 3.10 or newer
- HTTPS access to the Django API
- A VPN node record configured with protocol `wireguard`

Create a virtual environment, install the agent dependencies, copy
`.env.example` to `.env`, then set the API URL, node UUID, and token. Restrict
the env file to root (`chmod 600 .env`). Run as root because `wg set` needs
network administration privileges:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
set -a
. ./.env
set +a
sudo --preserve-env=ALIF_API_BASE_URL,ALIF_NODE_ID,ALIF_NODE_TOKEN,WG_INTERFACE,AGENT_STATE_FILE,AGENT_POLL_INTERVAL,LOG_LEVEL .venv/bin/python agent.py
```

Generate a token in the Django project after creating the Server record:

```powershell
python manage.py issue_agent_token <SERVER_UUID>
```

The raw token is printed once. Keep it secret. The existing agent API uses
`X-Agent-ID` and `X-Agent-Token`; deploy behind HTTPS. Production should replace
static bearer credentials with mutual TLS and a managed secret rotation process.

## Important limitations

- The agent applies/removes WireGuard peers only. Configure `supported_protocols`
  as `["wireguard"]` until an Xray adapter is implemented.
- It reports CPU and memory metrics. Network throughput metrics are currently
  zero; active peers are counted from `wg show`.
- Keep the API and server clocks synchronized. Do not expose the agent token in
  logs, screenshots, or source control.
- The VPN server itself (interface, forwarding, firewall/NAT, DNS and key
  generation) must be configured separately. This agent does not install or
  alter those system settings.
