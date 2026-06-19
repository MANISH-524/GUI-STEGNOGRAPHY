FROM python:3.12-slim

# OpenCV runtime libs
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgl1 libglib2.0-0 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN useradd -m stego && mkdir -p uploads && chown -R stego uploads
USER stego

ENV STEGO_HOST=0.0.0.0 STEGO_PORT=5000
EXPOSE 5000
# Behind a TLS-terminating reverse proxy in production.
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "--timeout", "300", "app:app"]
