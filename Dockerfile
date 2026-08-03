# Web Application Recon Tool — production image
# Build from this directory:  docker build -t recon-tool .
FROM python:3.12-slim

# System deps for WeasyPrint (PDF export) + headless Chromium (screenshots)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf2.0-0 \
    libffi-dev shared-mime-info \
    chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Point Selenium at the system-installed Chromium instead of downloading one
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_PATH=/usr/bin/chromedriver

RUN useradd -m appuser && chown -R appuser /app
USER appuser

EXPOSE 5001
ENV FLASK_DEBUG=0

CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "2", "--timeout", "120", "app:app"]
