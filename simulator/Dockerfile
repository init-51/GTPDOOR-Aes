# ── GTPDoor simulator image ────────────────────────────────────
FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY simulator.py .

# We rewrite the hard‑coded IP so the client talks to the
# docker‑compose service called “listener”.
RUN sed -i 's/^TARGET_IP *=.*/TARGET_IP = "listener"/' simulator.py

CMD ["python", "simulator.py"]

