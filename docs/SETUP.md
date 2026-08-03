# Setup & Deployment

## Prerequisites

- Python 3.10+
- (Optional, for PDF export) system libraries required by WeasyPrint:
  Pango, Cairo, GDK-Pixbuf, libffi. On Debian/Ubuntu:
  ```bash
  sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
       libgdk-pixbuf2.0-0 libffi-dev
  ```
- (Optional, for screenshot capture) Google Chrome or Chromium
  installed. `webdriver-manager` will download a matching ChromeDriver
  automatically on first run outside a container.

## Local installation

```bash
git clone <this-repo-url> webapp-recon-tool
cd webapp-recon-tool

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python app.py
```

Open `http://127.0.0.1:5001`.

Set `FLASK_DEBUG=1` to enable Flask's debug/reload mode during
development (do not use in any shared/production environment).

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `RECON_TOOL_SECRET_KEY` | Flask session/flash signing key | random per-process |
| `FLASK_DEBUG` | `1` enables Flask debug mode | `0` |
| `CHROME_BIN` | Path to Chrome/Chromium binary (used by screenshot capture) | auto-detected by Selenium |
| `CHROMEDRIVER_PATH` | Path to a pre-installed chromedriver, skips `webdriver-manager`'s auto-download | unset |

## Deployment

### Option A — Docker Compose (recommended)

The bundled image installs WeasyPrint's system dependencies **and**
headless Chromium, so PDF export and screenshot capture work
immediately without any extra setup.

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_hex(32))"   # paste into .env

docker compose up -d --build
```

Open `http://<host>:5001`. Logs: `docker compose logs -f`. Stop:
`docker compose down`.

The `shm_size: 1gb` setting in `docker-compose.yml` prevents headless
Chrome from crashing due to Docker's default tiny `/dev/shm`.

Put a reverse proxy (nginx, Caddy, Traefik) in front for TLS termination.

### Option B — Bare metal with gunicorn + systemd + nginx

1. Install as above (venv + `pip install -r requirements.txt`, which
   includes `gunicorn`). Install Chrome/Chromium separately if you want
   screenshot capture.

2. Create `/etc/systemd/system/recon-tool.service`:
   ```ini
   [Unit]
   Description=Web Application Recon Tool
   After=network.target

   [Service]
   User=www-data
   WorkingDirectory=/opt/webapp-recon-tool
   Environment="RECON_TOOL_SECRET_KEY=<random-hex>"
   ExecStart=/opt/webapp-recon-tool/.venv/bin/gunicorn --bind 127.0.0.1:5001 --workers 2 --timeout 120 app:app
   Restart=on-failure

   [Install]
   WantedBy=multi-user.target
   ```
   (Note the longer `--timeout 120` — recon scans with screenshots/port
   scans take longer than a simple header check.)

3. Enable and start:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now recon-tool
   ```

4. Put nginx in front for TLS:
   ```nginx
   server {
       listen 443 ssl;
       server_name recon.internal.example.com;
       # ssl_certificate / ssl_certificate_key ...
       location / { proxy_pass http://127.0.0.1:5001; }
   }
   ```

### Production checklist

- [ ] Set a real, random `RECON_TOOL_SECRET_KEY` — required for
      sessions/flash messages to work correctly across multiple
      gunicorn workers.
- [ ] `FLASK_DEBUG` unset or `0`.
- [ ] Run behind gunicorn, never Flask's built-in dev server.
- [ ] Put the tool behind authentication (nginx basic auth, VPN-only
      access, or an auth proxy) — as shipped, anyone who can reach the
      app can trigger a scan (including port scans) that originates
      from your server's IP.
- [ ] Terminate TLS at the reverse proxy; don't expose the raw gunicorn
      port directly.
- [ ] Decide deliberately whether to expose the port-scan checkbox at
      all in shared/internet-facing deployments — it generates real
      traffic to the target.
- [ ] If internet-facing, rate-limit the `/` POST route.

## Running the test suite

```bash
python -m unittest test_recon.py -v
```

The test suite mocks all network calls, so it runs offline and quickly.
