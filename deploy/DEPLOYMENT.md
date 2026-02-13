# SchemaClient Tunnel Deployment On EC2 (Production + SQLite)

This guide deploys the Django ASGI gateway on one EC2 instance using SQLite and systemd.

## 1) DNS and TLS
- Point root and wildcard subdomain to the EC2 public IP:
  - `A mysmeclabs.com -> <EC2_IP>`
  - `A *.mysmeclabs.com -> <EC2_IP>`
- If using Cloudflare:
  - SSL mode `Full (Strict)`
  - WebSockets enabled

## 2) Server bootstrap (Ubuntu)
```bash
sudo apt update
sudo apt install -y python3 python3-venv nginx
sudo mkdir -p /home/ubuntu/schemaclient-gateway
sudo chown -R ubuntu:www-data /home/ubuntu/schemaclient-gateway
```

## 3) App install
```bash
cd /home/ubuntu/schemaclient-gateway
git clone <your-repo-url> .
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r schemaclienttunnel/requirements.txt
```

## 4) Optional: one-shot provisioning script
```bash
cd /home/ubuntu/schemaclient-gateway/schemaclienttunnel
sudo bash deploy/scripts/provision_ec2.sh
```

## 5) Environment for production SQLite
```bash
cp schemaclienttunnel/deploy/env/gateway.env.example /home/ubuntu/schemaclient-gateway/.env
```
- Set a real `DJANGO_SECRET_KEY`.
- Keep `DJANGO_ENV=production` and `DJANGO_DEBUG=false`.
- Keep `DJANGO_SQLITE_PATH=/home/ubuntu/schemaclient-gateway/data/gateway.sqlite3`.
- Keep `CHANNEL_REDIS_URL` empty unless you switch to Redis + multi-worker.

## 6) Systemd (ASGI)
```bash
sudo cp schemaclienttunnel/deploy/systemd/schemaclient-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now schemaclient-gateway
sudo systemctl status schemaclient-gateway
```

## 7) Nginx reverse proxy (WebSocket capable)
```bash
sudo cp schemaclienttunnel/deploy/nginx/schemaclient-gateway.conf /etc/nginx/sites-available/
sudo ln -sf /etc/nginx/sites-available/schemaclient-gateway.conf /etc/nginx/sites-enabled/schemaclient-gateway.conf
sudo nginx -t
sudo systemctl reload nginx
```

## 8) Validate deployment
1. Health endpoint
```bash
curl -sS https://mysmeclabs.com/api/tunnels/health
```
Expected: JSON with `"ok": true`.

2. Create tunnel
```bash
curl -sS -X POST https://mysmeclabs.com/api/tunnels/create \
  -H "Content-Type: application/json" \
  -d '{"tunnel_id":"check1234"}'
```

3. Full smoke test
```bash
.venv/bin/pip install requests websockets
.venv/bin/python schemaclienttunnel/scripts/smoke_check_gateway.py --gateway https://mysmeclabs.com
```
Expected final line: `[PASS] gateway is ready for desktop tunnel client`.

## 9) Scaling note
- Current production profile is SQLite + in-memory channel layer + one worker.
- If you need multiple workers, add Redis, set `CHANNEL_REDIS_URL`, and increase gunicorn workers.
