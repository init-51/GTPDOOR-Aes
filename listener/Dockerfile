# ── GTPDoor listener image ─────────────────────────────────────
FROM python:3.11-slim

# Tools so tcpdump in gtpdoor.py works
RUN apt-get update && \
    apt-get install -y --no-install-recommends tcpdump iproute2 iputils-ping net-tools && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gtpdoor.py .

# GTP‑C port
EXPOSE 2123/udp

# Start tcpdump + listener
CMD ["bash", "-c", "tcpdump -i any udp port 2123 -w /tmp/session.pcap & python gtpdoor.py"]
